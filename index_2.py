from flask import Flask, jsonify
import boto3
from botocore.exceptions import ClientError
import time
import ipaddress
import os

app = Flask(__name__)


# ----------------- Port → Service Mapping -----------------
PORT_SERVICE_MAP = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    5432: "PostgreSQL",
    3306: "MySQL",
    6379: "Redis",
    53: "DNS",
    123: "NTP"
}

# ----------------- Config -----------------
ROLE_ARN = "arn:aws:iam::146937414118:role/Saas_Infra_Readonly"
REGION = "us-east-1"
VPC_FLOWLOG_GROUP = "/aws/vpc/flowlogs"

# ----------------- Helpers -----------------
def aws_client(service):
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName="poc-session"
    )["Credentials"]

    return boto3.client(
        service,
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

def safe_int(val):
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ----------------- Fetch Flow Logs -----------------
def fetch_flow_logs(log_group_name, start_time=None, end_time=None, limit=1000):
    logs_client = aws_client("logs")
    if start_time is None:
        start_time = int((time.time() - 3600) * 1000)
    if end_time is None:
        end_time = int(time.time() * 1000)

    response = logs_client.filter_log_events(
        logGroupName=log_group_name,
        startTime=start_time,
        endTime=end_time,
        limit=limit
    )

    flow_logs = []
    for event in response["events"]:
        parts = event["message"].split()
        if len(parts) >= 12:
            flow_logs.append({
                "eni": parts[2],
                "src": parts[3],
                "dst": parts[4],
                "srcPort": safe_int(parts[5]),
                "dstPort": safe_int(parts[6]),
                "protocol": safe_int(parts[7]),
                "action": parts[12] if len(parts) > 12 else None
            })
    return flow_logs

# ----------------- Build ENI → Resource Map -----------------
def build_eni_map():
    ec2 = aws_client("ec2")
    rds = aws_client("rds")
    eni_map = {}

    # Get all network interfaces in VPC
    enis = ec2.describe_network_interfaces()["NetworkInterfaces"]

    for eni in enis:
        ip = eni.get("PrivateIpAddress")
        desc = eni.get("Description", "")

        # EC2 instance ENI
        if "InstanceId" in eni.get("Attachment", {}):
            instance_id = eni["Attachment"]["InstanceId"]
            eni_map[ip] = {"type": "EC2", "id": instance_id, "name": instance_id}

        # Load Balancer ENI
        elif "ELB" in desc:
            eni_map[ip] = {"type": "ALB", "id": desc, "name": "LoadBalancer"}

        # NAT Gateway ENI
        elif "nat" in desc.lower():
            eni_map[ip] = {"type": "NAT", "id": desc, "name": "NATGateway"}

        # RDS ENI
        elif "rds" in desc.lower():
            eni_map[ip] = {"type": "RDS", "id": desc, "name": "RDS"}

    # Also map RDS endpoint DNS
    dbs = rds.describe_db_instances()["DBInstances"]
    for db in dbs:
        eni_map[db["Endpoint"]["Address"]] = {
            "type": "RDS",
            "id": db["DBInstanceIdentifier"],
            "name": db["DBInstanceIdentifier"]
        }

    return eni_map




# fetch infra topology 

def fetch_infra_topology():
    ec2 = aws_client("ec2")
    rds = aws_client("rds")

    nodes = []
    edges = []

    # --- VPCs ---
    for vpc in ec2.describe_vpcs()["Vpcs"]:
        vpc_id = vpc["VpcId"]
        nodes.append({"id": vpc_id, "type": "VPC", "name": vpc_id})

    # --- Subnets ---
    for subnet in ec2.describe_subnets()["Subnets"]:
        subnet_id = subnet["SubnetId"]
        vpc_id = subnet["VpcId"]
        nodes.append({"id": subnet_id, "type": "Subnet", "name": subnet_id})
        edges.append({"from": subnet_id, "to": vpc_id, "relation": "belongs_to"})

    # --- Route Tables ---
    for rt in ec2.describe_route_tables()["RouteTables"]:
        rt_id = rt["RouteTableId"]
        vpc_id = rt["VpcId"]
        nodes.append({"id": rt_id, "type": "RouteTable", "name": rt_id})
        edges.append({"from": rt_id, "to": vpc_id, "relation": "belongs_to"})

        for assoc in rt.get("Associations", []):
            if "SubnetId" in assoc:
                edges.append({"from": assoc["SubnetId"], "to": rt_id, "relation": "uses_route_table"})

    # --- NAT Gateways ---
    for nat in ec2.describe_nat_gateways()["NatGateways"]:
        nat_id = nat["NatGatewayId"]
        subnet_id = nat["SubnetId"]
        nodes.append({"id": nat_id, "type": "NAT", "name": nat_id})
        edges.append({"from": nat_id, "to": subnet_id, "relation": "deployed_in"})

    # --- Internet Gateway ---
    for igw in ec2.describe_internet_gateways()["InternetGateways"]:
        igw_id = igw["InternetGatewayId"]
        for attach in igw.get("Attachments", []):
            edges.append({"from": igw_id, "to": attach["VpcId"], "relation": "attached_to"})
        nodes.append({"id": igw_id, "type": "InternetGateway", "name": igw_id})

    # --- EC2 Instances → Subnets ---
    for r in ec2.describe_instances()["Reservations"]:
        for i in r["Instances"]:
            iid = i["InstanceId"]
            subnet_id = i.get("SubnetId")
            if subnet_id:
                edges.append({"from": iid, "to": subnet_id, "relation": "runs_in"})

    # --- RDS → Subnets ---
    for db in rds.describe_db_instances()["DBInstances"]:
        db_id = db["DBInstanceIdentifier"]
        subnet_group = db["DBSubnetGroup"]["Subnets"]
        for s in subnet_group:
            edges.append({"from": db_id, "to": s["SubnetIdentifier"], "relation": "deployed_in"})
        nodes.append({"id": db_id, "type": "RDS", "name": db_id})

    return {"nodes": nodes, "edges": edges}


# ----------------- Infer Relations -----------------

def infer_relations(flow_logs, eni_map):
  edges = []
  nodes = []
  seen_nodes = set()

  def add_node(n):
    if n["id"] not in seen_nodes:
      nodes.append(n)
      seen_nodes.add(n["id"])

  for log in flow_logs:
    src_ip = log["src"]
    dst_ip = log["dst"]

    src_node = eni_map.get(src_ip)
    dst_node = eni_map.get(dst_ip)

    if not src_node:
      src_node = {"type": "Internet", "id": "Internet", "name": "Internet"}

    if not dst_node:
      dst_node = {"type": "Internet", "id": "Internet", "name": "Internet"}

    add_node(src_node)
    add_node(dst_node)

    port = log["dstPort"]
    protocol = "TCP" if log["protocol"] == 6 else "UDP" if log[
        "protocol"] == 17 else str(log["protocol"])

    # Interpret connection type
    if src_node["type"] == "External" and dst_node["type"] == "EC2":
      relation = f"Internet → EC2:{dst_node['name']} (Port {port})"

    elif src_node["type"] == "EC2" and dst_node["type"] == "RDS":
      relation = f"EC2:{src_node['name']} → RDS:{dst_node['name']} ({PORT_SERVICE_MAP.get(port,'Custom')})"

    elif src_node["type"] == "EC2" and dst_node["type"] == "EC2":
      relation = f"EC2:{src_node['name']} → EC2:{dst_node['name']} (Port {port})"

    else:
      relation = f"{src_node['type']} → {dst_node['type']} (Port {port})"

    edges.append({
        "from": src_node["id"],
        "to": dst_node["id"],
        "protocol": protocol,
        "port": port,
        "relation": relation
    })

  return {"nodes": nodes, "edges": edges}

@app.route("/")
def home():
    return "API running"


# ----------------- Flask Endpoint -----------------
@app.route("/graph", methods=["GET"])
def graph():
    flow_logs = fetch_flow_logs(VPC_FLOWLOG_GROUP)
    if not flow_logs:
        return jsonify({"error": "No flow logs found"}), 404

    eni_map = build_eni_map()
    traffic_graph = infer_relations(flow_logs, eni_map)

    infra_graph = fetch_infra_topology()

    return jsonify({
        "traffic": traffic_graph,
        "topology": infra_graph
    })


# ----------------- Run App -----------------
if __name__ == "__main__":
    # app.run(debug=True)
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
