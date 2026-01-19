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




@app.route("/graph", methods=["GET"])
def graph():
    nodes = []
    edges = []

    ec2 = aws_client("ec2")
    rds = aws_client("rds")
    iam = aws_client("iam")
    s3 = aws_client("s3")

    # ---------- VPC ----------
    vpcs = ec2.describe_vpcs()["Vpcs"]
    for v in vpcs:
        nodes.append({
            "id": v["VpcId"],
            "type": "VPC",
            "label": v["VpcId"]
        })

    # ---------- Subnets ----------
    subnets = ec2.describe_subnets()["Subnets"]
    for s in subnets:
        nodes.append({
            "id": s["SubnetId"],
            "type": "Subnet",
            "label": s["SubnetId"]
        })
        edges.append({
            "from": s["SubnetId"],
            "to": s["VpcId"],
            "relation": "belongs_to",
            "type": "explicit"
        })

    # ---------- EC2 ----------
    instances = ec2.describe_instances()["Reservations"]
    instance_sgs = {}

    for r in instances:
        for i in r["Instances"]:
            iid = i["InstanceId"]
            nodes.append({
                "id": iid,
                "type": "EC2",
                "label": iid
            })

            edges.extend([
                {
                    "from": iid,
                    "to": i["VpcId"],
                    "relation": "belongs_to",
                    "type": "explicit"
                },
                {
                    "from": iid,
                    "to": i["SubnetId"],
                    "relation": "attached_to",
                    "type": "explicit"
                }
            ])

            instance_sgs[iid] = [sg["GroupId"] for sg in i["SecurityGroups"]]

            if "IamInstanceProfile" in i:
                edges.append({
                    "from": iid,
                    "to": i["IamInstanceProfile"]["Arn"],
                    "relation": "assumes",
                    "type": "explicit"
                })

    # ---------- RDS ----------
    rds_instances = rds.describe_db_instances()["DBInstances"]
    rds_sgs = {}

    for db in rds_instances:
        dbid = db["DBInstanceIdentifier"]
        nodes.append({
            "id": dbid,
            "type": "RDS",
            "label": dbid
        })

        edges.append({
            "from": dbid,
            "to": db["DBSubnetGroup"]["VpcId"],
            "relation": "belongs_to",
            "type": "explicit"
        })

        rds_sgs[dbid] = [sg["VpcSecurityGroupId"] for sg in db["VpcSecurityGroups"]]

    # ---------- Security Groups ----------
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    sg_rules = {}

    for sg in sgs:
        nodes.append({
            "id": sg["GroupId"],
            "type": "SecurityGroup",
            "label": sg["GroupName"]
        })
        sg_rules[sg["GroupId"]] = sg["IpPermissions"]

    # ---------- EC2 → RDS (INFERRED) ----------
    for ec2_id, ec2_sg_ids in instance_sgs.items():
        for db_id, db_sg_ids in rds_sgs.items():
            if set(ec2_sg_ids) & set(db_sg_ids):
                edges.append({
                    "from": ec2_id,
                    "to": db_id,
                    "relation": "communicates_with",
                    "type": "inferred",
                    "evidence": "shared security group"
                })

    # ---------- S3 ----------
    buckets = s3.list_buckets()["Buckets"]
    for b in buckets:
        nodes.append({
            "id": b["Name"],
            "type": "S3",
            "label": b["Name"]
        })

    return jsonify({
        "nodes": nodes,
        "edges": edges
    })


if __name__ == "__main__":
    app.run(debug=True)
