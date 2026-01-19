from flask import Flask, jsonify
import boto3
from botocore.exceptions import ClientError
import time
import ipaddress

app = Flask(__name__)

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

    # EC2
    reservations = ec2.describe_instances().get("Reservations", [])
    for r in reservations:
        for i in r.get("Instances", []):
            for iface in i.get("NetworkInterfaces", []):
                eni_map[iface["PrivateIpAddress"]] = {
                    "type": "EC2",
                    "id": i["InstanceId"],
                    "name": next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), i["InstanceId"])
                }

    # RDS
    dbs = rds.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        for addr in [db["Endpoint"]["Address"]]:
            eni_map[addr] = {
                "type": "RDS",
                "id": db["DBInstanceIdentifier"],
                "name": db["DBInstanceIdentifier"]
            }

    return eni_map

# ----------------- Infer Relations -----------------
def infer_relations(flow_logs, eni_map):
    edges = []
    nodes = []

    node_ids = set()

    for log in flow_logs:
        src_ip = log["src"]
        dst_ip = log["dst"]

        # Resolve IP to AWS resource if known
        src_node = eni_map.get(src_ip, {"type": "External", "id": src_ip, "name": src_ip})
        dst_node = eni_map.get(dst_ip, {"type": "External", "id": dst_ip, "name": dst_ip})

        # Add nodes
        for n in [src_node, dst_node]:
            if n["id"] not in node_ids:
                nodes.append(n)
                node_ids.add(n["id"])

        # Determine relation type
        if is_private_ip(dst_ip):
            relation = "egress" if src_node["type"] != "External" else "ingress"
        else:
            relation = "egress" if src_node["type"] != "External" else "ingress"

        protocol = "TCP" if log["protocol"] == 6 else "UDP" if log["protocol"] == 17 else str(log["protocol"])

        edges.append({
            "from": src_node["id"],
            "to": dst_node["id"],
            "port": log["dstPort"],
            "protocol": protocol,
            "relation": relation
        })

    return {"nodes": nodes, "edges": edges}

# ----------------- Flask Endpoint -----------------
@app.route("/graph", methods=["GET"])
def graph():
    flow_logs = fetch_flow_logs(VPC_FLOWLOG_GROUP)
    if not flow_logs:
        return jsonify({"error": "No flow logs found"}), 404

    eni_map = build_eni_map()
    result = infer_relations(flow_logs, eni_map)
    return jsonify(result)

# ----------------- Run App -----------------
if __name__ == "__main__":
    app.run(debug=True)
