from flask import Flask, jsonify
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)

ROLE_ARN = "arn:aws:iam::146937414118:role/Saas_Infra_Readonly"
REGION = "us-east-1"


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


@app.route("/graph", methods=["GET"])
def get_graph():
    nodes, edges = [], []

    # ---------- AWS Clients ----------
    ec2 = aws_client("ec2")
    rds = aws_client("rds")
    elb = aws_client("elbv2")
    asg = aws_client("autoscaling")
    lam = aws_client("lambda")
    iam = aws_client("iam")
    s3 = aws_client("s3")

    # ---------- VPCs ----------
    vpcs = ec2.describe_vpcs().get("Vpcs", [])
    for v in vpcs:
        nodes.append({
            "id": v["VpcId"],
            "type": "VPC",
            "label": v["VpcId"],
            "metadata": {"cidr": v["CidrBlock"]}
        })

    # ---------- Subnets & Route Tables ----------
    route_tables = ec2.describe_route_tables().get("RouteTables", [])
    subnets = ec2.describe_subnets().get("Subnets", [])
    public_subnets = set()
    subnet_to_rt = {}

    for rt in route_tables:
        rt_id = rt["RouteTableId"]
        nodes.append({
            "id": rt_id,
            "type": "RouteTable",
            "label": rt_id,
            "metadata": {}
        })
        for assoc in rt.get("Associations", []):
            if "SubnetId" in assoc:
                subnet_to_rt[assoc["SubnetId"]] = rt_id
                edges.append({
                    "from": assoc["SubnetId"],
                    "to": rt_id,
                    "relation": "uses",
                    "type": "explicit"
                })
        for r in rt.get("Routes", []):
            if r.get("GatewayId", "").startswith("igw-"):
                for assoc in rt.get("Associations", []):
                    if "SubnetId" in assoc:
                        public_subnets.add(assoc["SubnetId"])

    for s in subnets:
        subnet_type = "Public" if s["SubnetId"] in public_subnets else "Private"
        nodes.append({
            "id": s["SubnetId"],
            "type": "Subnet",
            "label": s["SubnetId"],
            "metadata": {
                "cidr": s["CidrBlock"],
                "az": s["AvailabilityZone"],
                "subnet_type": subnet_type
            }
        })
        edges.append({
            "from": s["SubnetId"],
            "to": s["VpcId"],
            "relation": "belongs_to",
            "type": "explicit"
        })

    # ---------- Internet Gateways ----------
    igws = ec2.describe_internet_gateways().get("InternetGateways", [])
    for igw in igws:
        igw_id = igw["InternetGatewayId"]
        nodes.append({
            "id": igw_id,
            "type": "InternetGateway",
            "label": igw_id,
            "metadata": {}
        })
        for a in igw.get("Attachments", []):
            edges.append({
                "from": igw_id,
                "to": a["VpcId"],
                "relation": "attached_to",
                "type": "explicit"
            })

    # ---------- NAT Gateways ----------
    ngws = ec2.describe_nat_gateways().get("NatGateways", [])
    for ngw in ngws:
        nid = ngw["NatGatewayId"]
        nodes.append({
            "id": nid,
            "type": "NATGateway",
            "label": nid,
            "metadata": {"state": ngw["State"]}
        })
        edges.append({
            "from": nid,
            "to": ngw.get("SubnetId"),
            "relation": "placed_in",
            "type": "explicit"
        })

    # ---------- Security Groups ----------
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    sg_map = {}
    for sg in sgs:
        sg_map[sg["GroupId"]] = sg
        nodes.append({
            "id": sg["GroupId"],
            "type": "SecurityGroup",
            "label": sg["GroupName"],
            "metadata": {"vpc": sg.get("VpcId")}
        })
        for rule in sg.get("IpPermissions", []):
            for pair in rule.get("UserIdGroupPairs", []):
                edges.append({
                    "from": sg["GroupId"],
                    "to": pair["GroupId"],
                    "relation": "allows",
                    "type": "explicit"
                })

    # ---------- EC2 Instances ----------
    ec2_sg_map = {}
    reservations = ec2.describe_instances().get("Reservations", [])
    for r in reservations:
        for i in r.get("Instances", []):
            iid = i["InstanceId"]
            ec2_sg_map[iid] = [sg["GroupId"] for sg in i.get("SecurityGroups", [])]

            nodes.append({
                "id": iid,
                "type": "EC2",
                "label": iid,
                "metadata": {
                    "state": i["State"]["Name"],
                    "instance_type": i["InstanceType"],
                    "ami": i["ImageId"],
                    "key_name": i.get("KeyName"),
                    "private_ip": i.get("PrivateIpAddress"),
                    "public_ip": i.get("PublicIpAddress"),
                    "tags": i.get("Tags", [])
                }
            })

            edges.extend([
                {"from": iid, "to": i.get("SubnetId"), "relation": "attached_to", "type": "explicit"},
                {"from": iid, "to": i.get("VpcId"), "relation": "belongs_to", "type": "explicit"}
            ])

            for sg in i.get("SecurityGroups", []):
                edges.append({
                    "from": iid,
                    "to": sg["GroupId"],
                    "relation": "secured_by",
                    "type": "explicit"
                })

            # IAM Role attached to EC2
            if "IamInstanceProfile" in i:
                profile_name = i["IamInstanceProfile"]["Arn"].split("/")[-1]
                try:
                    profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
                    for role in profile.get("Roles", []):
                        role_name = role["RoleName"]
                        nodes.append({
                            "id": role_name,
                            "type": "IAMRole",
                            "label": role_name,
                            "metadata": {}
                        })
                        edges.append({
                            "from": iid,
                            "to": role_name,
                            "relation": "assumes",
                            "type": "explicit"
                        })
                except ClientError:
                    pass

    # ---------- Auto Scaling Groups ----------
    groups = asg.describe_auto_scaling_groups().get("AutoScalingGroups", [])
    for g in groups:
        gid = g["AutoScalingGroupName"]
        nodes.append({
            "id": gid,
            "type": "AutoScalingGroup",
            "label": gid,
            "metadata": {}
        })
        for inst in g.get("Instances", []):
            edges.append({
                "from": gid,
                "to": inst["InstanceId"],
                "relation": "manages",
                "type": "explicit"
            })
        for tg in g.get("TargetGroupARNs", []):
            edges.append({
                "from": gid,
                "to": tg,
                "relation": "attached_to",
                "type": "explicit"
            })

    # ---------- ELB & Target Groups ----------
    lbs = elb.describe_load_balancers().get("LoadBalancers", [])
    tgs = elb.describe_target_groups().get("TargetGroups", [])
    for lb in lbs:
        lb_arn = lb["LoadBalancerArn"]
        nodes.append({
            "id": lb_arn,
            "type": "LoadBalancer",
            "label": lb["LoadBalancerName"],
            "metadata": {"scheme": lb["Scheme"]}
        })
        for az in lb.get("AvailabilityZones", []):
            edges.append({
                "from": lb_arn,
                "to": az["SubnetId"],
                "relation": "placed_in",
                "type": "explicit"
            })

    for tg in tgs:
        tg_arn = tg["TargetGroupArn"]
        nodes.append({
            "id": tg_arn,
            "type": "TargetGroup",
            "label": tg["TargetGroupName"],
            "metadata": {"protocol": tg["Protocol"]}
        })
        th = elb.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
        for t in th:
            edges.append({
                "from": tg_arn,
                "to": t["Target"]["Id"],
                "relation": "registers",
                "type": "explicit"
            })

    # ---------- RDS ----------
    dbs = rds.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        db_id = db["DBInstanceIdentifier"]
        db_sgs = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
        nodes.append({
            "id": db_id,
            "type": "RDS",
            "label": db_id,
            "metadata": {
                "engine": db["Engine"],
                "instance_class": db["DBInstanceClass"],
                "storage": db["AllocatedStorage"],
                "multi_az": db["MultiAZ"],
                "endpoint": db.get("Endpoint", {}).get("Address"),
                "port": db.get("Endpoint", {}).get("Port"),
                "backup_retention": db["BackupRetentionPeriod"],
                "tags": db.get("TagList", [])
                         
                         }
        })
        edges.append({
            "from": db_id,
            "to": db.get("DBSubnetGroup", {}).get("VpcId"),
            "relation": "belongs_to",
            "type": "explicit"
        })
        # DB → Subnets
        for sid in db.get("DBSubnetGroup", {}).get("Subnets", []):
            edges.append({
                "from": db_id,
                "to": sid["SubnetIdentifier"],
                "relation": "runs_in",
                "type": "explicit"
            })
        # EC2 → DB inferred via SG
        for ec2_id, ec2_sgs in ec2_sg_map.items():
            for db_sg in db_sgs:
                for rule in sg_map.get(db_sg, {}).get("IpPermissions", []):
                    for pair in rule.get("UserIdGroupPairs", []):
                        if pair["GroupId"] in ec2_sgs:
                            edges.append({
                                "from": ec2_id,
                                "to": db_id,
                                "relation": "can_connect_to",
                                "type": "inferred"
                            })

    # ---------- Lambda ----------
    funcs = lam.list_functions().get("Functions", [])
    for f in funcs:
        cfg = lam.get_function_configuration(FunctionName=f["FunctionName"])
        nodes.append({
            "id": f["FunctionArn"],
            "type": "Lambda",
            "label": f["FunctionName"],
            "metadata": {"runtime": f["Runtime"]}
        })
        if "Role" in cfg:
            role_name = cfg["Role"].split("/")[-1]
            nodes.append({
                "id": role_name,
                "type": "IAMRole",
                "label": role_name,
                "metadata": {}
            })
            edges.append({
                "from": f["FunctionArn"],
                "to": role_name,
                "relation": "assumes",
                "type": "explicit"
            })
        if "VpcConfig" in cfg:
            for sg_id in cfg["VpcConfig"].get("SecurityGroupIds", []):
                edges.append({
                    "from": f["FunctionArn"],
                    "to": sg_id,
                    "relation": "secured_by",
                    "type": "explicit"
                })
            for sid in cfg["VpcConfig"].get("SubnetIds", []):
                edges.append({
                    "from": f["FunctionArn"],
                    "to": sid,
                    "relation": "attached_to",
                    "type": "explicit"
                })

    # ---------- S3 Buckets ----------
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    for b in buckets:
        nodes.append({
            "id": b,
            "type": "S3",
            "label": b,
            "metadata": {}
        })
        try:
            policy = s3.get_bucket_policy(Bucket=b)["Policy"]
            nodes.append({
                "id": f"{b}_policy",
                "type": "S3Policy",
                "label": f"{b}_policy",
                "metadata": {"policy": policy}
                        
            })
            edges.append({
                "from": f"{b}_policy",
                "to": b,
                "relation": "applies_to",
                "type": "explicit"
            })
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise

    # ---------- IAM Policies ----------
    policies = iam.list_policies(Scope="Local").get("Policies", [])
    for p in policies:
        nodes.append({
            "id": p["Arn"],
            "type": "IAMPolicy",
            "label": p["PolicyName"],
            "metadata": {}
        })

    # ---------- Network ACLs ----------
    acls = ec2.describe_network_acls().get("NetworkAcls", [])
    for acl in acls:
        acl_id = acl["NetworkAclId"]
        nodes.append({
            "id": acl_id,
            "type": "NACL",
            "label": acl_id,
            "metadata": {"default": acl["IsDefault"]}
        })
        edges.append({
            "from": acl_id,
            "to": acl["VpcId"],
            "relation": "belongs_to",
            "type": "explicit"
        })
        for assoc in acl.get("Associations", []):
            edges.append({
                "from": assoc["SubnetId"],
                "to": acl_id,
                "relation": "filtered_by",
                "type": "explicit"
            })

    # ---------- VPC Endpoints ----------
    endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
    for ep in endpoints:
        ep_id = ep["VpcEndpointId"]
        nodes.append({
            "id": ep_id,
            "type": "VPCEndpoint",
            "label": ep_id,
            "metadata": {
                "service": ep["ServiceName"],
                "endpoint_type": ep["VpcEndpointType"]
            }
        })
        edges.append({
            "from": ep_id,
            "to": ep["VpcId"],
            "relation": "attached_to",
            "type": "explicit"
        })
        for rt_id in ep.get("RouteTableIds", []):
            edges.append({
                "from": ep_id,
                "to": rt_id,
                "relation": "associated_with",
                "type": "explicit"
            })
        if "s3" in ep["ServiceName"]:
            for b in buckets:
                edges.append({
                    "from": ep_id,
                    "to": b,
                    "relation": "provides_private_access",
                    "type": "explicit"
                })

    # ---------- ENIs & Elastic IPs ----------
    enis = ec2.describe_network_interfaces().get("NetworkInterfaces", [])
    for eni in enis:
        eni_id = eni["NetworkInterfaceId"]
        nodes.append({
            "id": eni_id,
            "type": "ENI",
            "label": eni_id,
            "metadata": {"status": eni["Status"]}
        })
        if eni.get("Attachment") and "InstanceId" in eni["Attachment"]:
            edges.append({
                "from": eni_id,
                "to": eni["Attachment"]["InstanceId"],
                "relation": "attached_to",
                "type": "explicit"
            })
        if eni.get("Association") and "PublicIp" in eni["Association"]:
            eip = eni["Association"]["PublicIp"]
            nodes.append({
                "id": eip,
                "type": "ElasticIP",
                "label": eip,
                "metadata": {}
            })
            edges.append({
                "from": eip,
                "to": eni_id,
                "relation": "associated_with",
                "type": "explicit"
            })

    # ---------- VPC Peering ----------
    peerings = ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
    for pc in peerings:
        pc_id = pc["VpcPeeringConnectionId"]
        nodes.append({
            "id": pc_id,
            "type": "VPCPeering",
            "label": pc_id,
            "metadata": {"status": pc["Status"]["Code"]}
        })
        edges.append({
            "from": pc["RequesterVpcInfo"]["VpcId"],
            "to": pc["AccepterVpcInfo"]["VpcId"],
            "relation": "peered_with",
            "type": "explicit"
        })

    # ---------- Transit Gateways ----------
    tgws = ec2.describe_transit_gateways().get("TransitGateways", [])
    for tgw in tgws:
        tgw_id = tgw["TransitGatewayId"]
        nodes.append({
            "id": tgw_id,
            "type": "TransitGateway",
            "label": tgw_id,
            "metadata": {"state": tgw["State"]}
        })
        tgw_attachments = ec2.describe_transit_gateway_attachments(
            Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
        ).get("TransitGatewayAttachments", [])
        for att in tgw_attachments:
            edges.append({
                "from": att["ResourceId"],
                "to": tgw_id,
                "relation": "attached_to",
                "type": "explicit"
            })

    # ---------- VPN Connections ----------
    vpns = ec2.describe_vpn_connections().get("VpnConnections", [])
    for vpn in vpns:
        vpn_id = vpn["VpnConnectionId"]
        nodes.append({
            "id": vpn_id,
            "type": "VPNConnection",
            "label": vpn_id,
            "metadata": {"state": vpn["State"]}
        })
        gw_id = vpn.get("VpnGatewayId") or vpn.get("CustomerGatewayId")
        edges.append({
            "from": gw_id,
            "to": vpn_id,
            "relation": "connects_to",
            "type": "explicit"
        })

    return jsonify({"nodes": nodes, "edges": edges})


if __name__ == "__main__":
    app.run(debug=True)
