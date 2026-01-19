from flask import Flask, jsonify
import boto3

app = Flask(__name__)


# # m0V2nkzTrwM/+r+qp9Ey5ssvrMK0wRvNZZSLM14s


ROLE_ARN = "arn:aws:iam::146937414118:role/Saas_Infra_Readonly"
REGION = "us-east-1"


def aws_client(service):
    sts = boto3.client("sts")

    response = sts.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName="poc-session"
    )

    creds = response["Credentials"]

    return boto3.client(
        service,
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


@app.route("/vpcs", methods=["GET"])
def get_vpcs():
    ec2 = aws_client("ec2")
    response = ec2.describe_vpcs()

    vpcs = [{
        "vpc_id": v["VpcId"],
        "cidr": v["CidrBlock"],
        "is_default": v["IsDefault"],
        "state": v["State"]
    } for v in response["Vpcs"]]

    return jsonify(vpcs)

@app.route("/relationships/vpc", methods=["GET"])
def vpc_relationships():
    ec2 = aws_client("ec2")
    rds = aws_client("rds")

    vpcs = ec2.describe_vpcs()["Vpcs"]
    subnets = ec2.describe_subnets()["Subnets"]

    instances = []
    for page in ec2.get_paginator("describe_instances").paginate():
        for r in page["Reservations"]:
            instances.extend(r["Instances"])

    dbs = rds.describe_db_instances()["DBInstances"]

    nodes = []
    edges = []

    for vpc in vpcs:
        nodes.append({"id": vpc["VpcId"], "type": "vpc"})

    for s in subnets:
        nodes.append({"id": s["SubnetId"], "type": "subnet"})
        edges.append({
            "from": s["VpcId"],
            "to": s["SubnetId"],
            "relation": "contains"
        })

    for i in instances:
        nodes.append({"id": i["InstanceId"], "type": "ec2"})
        edges.append({
            "from": i["SubnetId"],
            "to": i["InstanceId"],
            "relation": "hosts"
        })

    for db in dbs:
        nodes.append({"id": db["DBInstanceIdentifier"], "type": "rds"})
        edges.append({
            "from": db["DBSubnetGroup"]["VpcId"],
            "to": db["DBInstanceIdentifier"],
            "relation": "hosts"
        })

    return jsonify({"nodes": nodes, "edges": edges})



@app.route("/subnets", methods=["GET"])
def get_subnets():
    ec2 = aws_client("ec2")
    response = ec2.describe_subnets()

    subnets = []
    for s in response["Subnets"]:
        subnets.append({
            "subnet_id": s["SubnetId"],
            "vpc_id": s["VpcId"],
            "cidr": s["CidrBlock"],
            "az": s["AvailabilityZone"],
            "map_public_ip": s["MapPublicIpOnLaunch"]
        })

    return jsonify(subnets)


@app.route("/relationships/security-groups", methods=["GET"])
def sg_relationships():
    ec2 = aws_client("ec2")
    sgs = ec2.describe_security_groups()["SecurityGroups"]

    edges = []

    for sg in sgs:
        for rule in sg["IpPermissions"]:
            for ref in rule.get("UserIdGroupPairs", []):
                edges.append({
                    "from": sg["GroupId"],
                    "to": ref["GroupId"],
                    "relation": "allows-traffic"
                })

    return jsonify(edges)



@app.route("/ec2", methods=["GET"])
def get_ec2():
    ec2 = aws_client("ec2")
    instances = []

    paginator = ec2.get_paginator("describe_instances")

    for page in paginator.paginate():
        for res in page["Reservations"]:
            for i in res["Instances"]:
                instances.append({
                    "instance_id": i["InstanceId"],
                    "type": i["InstanceType"],
                    "state": i["State"]["Name"],
                    "private_ip": i.get("PrivateIpAddress"),
                    "public_ip": i.get("PublicIpAddress"),
                    "subnet_id": i["SubnetId"],
                    "vpc_id": i["VpcId"]
                })

    return jsonify(instances)



@app.route("/rds", methods=["GET"])
def get_rds():
    rds = aws_client("rds")
    response = rds.describe_db_instances()

    dbs = []
    for db in response["DBInstances"]:
        dbs.append({
            "db_id": db["DBInstanceIdentifier"],
            "engine": db["Engine"],
            "engine_version": db["EngineVersion"],
            "status": db["DBInstanceStatus"],
            "endpoint": db["Endpoint"]["Address"],
            "public": db["PubliclyAccessible"],
            "az": db["AvailabilityZone"]
        })

    return jsonify(dbs)




@app.route("/internet-gateways", methods=["GET"])
def get_igw():
    ec2 = aws_client("ec2")
    response = ec2.describe_internet_gateways()

    igws = []
    for igw in response["InternetGateways"]:
        igws.append({
            "igw_id": igw["InternetGatewayId"],
            "attached_vpcs": [a["VpcId"] for a in igw["Attachments"]]
        })

    return jsonify(igws)




@app.route("/security-groups", methods=["GET"])
def get_sgs():
    ec2 = aws_client("ec2")
    response = ec2.describe_security_groups()

    sgs = []
    for sg in response["SecurityGroups"]:
        sgs.append({
            "sg_id": sg["GroupId"],
            "name": sg["GroupName"],
            "vpc_id": sg.get("VpcId"),
            "inbound_rules": len(sg["IpPermissions"]),
            "outbound_rules": len(sg["IpPermissionsEgress"])
        })

    return jsonify(sgs)





@app.route("/iam/roles", methods=["GET"])
def get_roles():
    iam = aws_client("iam")
    response = iam.list_roles()

    roles = [{
        "role_name": r["RoleName"],
        "arn": r["Arn"],
        "created": r["CreateDate"].isoformat()
    } for r in response["Roles"]]

    return jsonify(roles)


@app.route("/cloudwatch/namespaces", methods=["GET"])
def get_cloudwatch_namespaces():
    cw = aws_client("cloudwatch")
    response = cw.list_metrics()

    namespaces = sorted(set(m["Namespace"] for m in response["Metrics"]))

    return jsonify(namespaces)



@app.route("/s3", methods=["GET"])
def get_s3():
    s3 = aws_client("s3")
    response = s3.list_buckets()

    buckets = [{
        "name": b["Name"],
        "created": b["CreationDate"].isoformat()
    } for b in response["Buckets"]]

    return jsonify(buckets)



 
def build_graph():
    ec2 = aws_client("ec2")
    rds = aws_client("rds")
    s3 = aws_client("s3")

    nodes = []
    edges = []

    # ---- VPCs ----
    vpcs = ec2.describe_vpcs()["Vpcs"]
    for v in vpcs:
        nodes.append({
            "id": v["VpcId"],
            "type": "VPC",
            "cidr": v["CidrBlock"]
        })

    # ---- Subnets ----
    subnets = ec2.describe_subnets()["Subnets"]
    for s in subnets:
        nodes.append({
            "id": s["SubnetId"],
            "type": "Subnet",
            "vpc_id": s["VpcId"]
        })
        edges.append({
            "from": s["VpcId"],
            "to": s["SubnetId"],
            "relation": "contains"
        })

    # ---- EC2 ----
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for res in page["Reservations"]:
            for i in res["Instances"]:
                iid = i["InstanceId"]
                nodes.append({
                    "id": iid,
                    "type": "EC2",
                    "subnet_id": i["SubnetId"]
                })
                edges.append({
                    "from": i["SubnetId"],
                    "to": iid,
                    "relation": "hosts"
                })

    # ---- RDS ----
    dbs = rds.describe_db_instances()["DBInstances"]
    for db in dbs:
        db_id = db["DBInstanceIdentifier"]
        nodes.append({
            "id": db_id,
            "type": "RDS",
            "engine": db["Engine"]
        })

        for sn in db["DBSubnetGroup"]["Subnets"]:
            edges.append({
                "from": sn["SubnetIdentifier"],
                "to": db_id,
                "relation": "deployed-in"
            })

    # ---- S3 ----
    buckets = s3.list_buckets()["Buckets"]
    for b in buckets:
        nodes.append({
            "id": b["Name"],
            "type": "S3"
        })

    return {
        "nodes": nodes,
        "edges": edges
    }


@app.route("/graph", methods=["GET"])
def get_graph():
    graph = build_graph()
    return jsonify(graph)







if __name__ == "__main__":
    print("Starting Flask app...")
    app.run(host="127.0.0.1", port=5000, debug=True)







# def assume_role():
#     sts = boto3.client("sts")

#     response = sts.assume_role(
#         RoleArn=ROLE_ARN,
#         RoleSessionName="poc-session"
#     )

#     creds = response["Credentials"]

#     return boto3.client(
#         "ec2",
#         region_name=REGION,
#         aws_access_key_id=creds["AccessKeyId"],
#         aws_secret_access_key=creds["SecretAccessKey"],
#         aws_session_token=creds["SessionToken"]
#     )

# @app.route("/ec2", methods=["GET"])
# def get_ec2_info():
#     ec2 = assume_role()
#     instances = []

#     paginator = ec2.get_paginator("describe_instances")

#     for page in paginator.paginate():
#         for reservation in page["Reservations"]:
#             for inst in reservation["Instances"]:
#                 instances.append({
#                     "instance_id": inst["InstanceId"],
#                     "instance_type": inst["InstanceType"],
#                     "state": inst["State"]["Name"],
#                     "az": inst["Placement"]["AvailabilityZone"]
#                 })

#     return jsonify({
#         "count": len(instances),
#         "instances": instances
#     })

# if __name__ == "__main__":
#     app.run(debug=True)
