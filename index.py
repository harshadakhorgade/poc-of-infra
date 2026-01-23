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
    


    
    
# /audit/q3/encryption-at-rest


@app.route("/audit/q3/encryption-at-rest")
def encryption_at_rest():
    findings = []
    evidence = []
    score = 3

    rds = aws_client("rds")
    s3 = aws_client("s3")
    kms = aws_client("kms")

    # RDS
    dbs = rds.describe_db_instances()["DBInstances"]
    for db in dbs:
        if not db.get("StorageEncrypted"):
            score = min(score, 2)
            findings.append(f"RDS {db['DBInstanceIdentifier']} not encrypted")
        else:
            evidence.append(f"RDS encrypted: {db['DBInstanceIdentifier']}")

    # S3
    for b in s3.list_buckets()["Buckets"]:
        try:
            s3.get_bucket_encryption(Bucket=b["Name"])
            evidence.append(f"S3 encrypted: {b['Name']}")
        except ClientError:
            score = min(score, 2)
            findings.append(f"S3 bucket unencrypted: {b['Name']}")

    # KMS rotation
    keys = kms.list_keys()["Keys"]
    for k in keys:
        if not kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"]:
            score = min(score, 1)
            findings.append("KMS key rotation disabled")

    return jsonify({
        "control": "Q3.1",
        "title": "Encryption at Rest",
        "score": score,
        "status": "COMPLIANT" if score == 3 else "PARTIAL",
        "findings": findings,
        "evidence": evidence,
        "timestamp": time.time()
    })


# /audit/q3/encryption-in-transit

@app.route("/audit/q3/encryption-in-transit")
def encryption_in_transit():
    elb = aws_client("elbv2")
    findings, evidence = [], []
    score = 3

    lbs = elb.describe_load_balancers()["LoadBalancers"]
    for lb in lbs:
        listeners = elb.describe_listeners(
            LoadBalancerArn=lb["LoadBalancerArn"]
        )["Listeners"]

        for l in listeners:
            if l["Protocol"] != "HTTPS":
                score = min(score, 2)
                findings.append(f"{lb['LoadBalancerName']} has non-HTTPS listener")
            else:
                evidence.append(f"{lb['LoadBalancerName']} HTTPS enabled")

    return jsonify({
        "control": "Q3.2",
        "title": "Encryption in Transit",
        "score": score,
        "status": "COMPLIANT" if score == 3 else "PARTIAL",
        "findings": findings,
        "evidence": evidence,
        "timestamp": time.time()
    })


# /audit/q3/mfa


@app.route("/audit/q3/mfa")
def mfa_status():
    iam = aws_client("iam")
    findings, evidence = [], []
    score = 3

    users = iam.list_users()["Users"]
    for u in users:
        mfa = iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
        if not mfa:
            score = min(score, 2)
            findings.append(f"MFA missing for user {u['UserName']}")
        else:
            evidence.append(f"MFA enabled: {u['UserName']}")

    root_mfa = iam.get_account_summary()["SummaryMap"]["AccountMFAEnabled"]
    if not root_mfa:
        score = 0
        findings.append("Root account MFA disabled")

    return jsonify({
        "control": "Q3.3",
        "title": "Multi-Factor Authentication",
        "score": score,
        "status": "COMPLIANT" if score == 3 else "NON_COMPLIANT",
        "findings": findings,
        "evidence": evidence,
        "timestamp": time.time()
    })


#  /audit/q3/access-control

@app.route("/audit/q3/access-control")
def access_control():
    iam = aws_client("iam")
    findings, evidence = [], []
    score = 3

    roles = iam.list_roles()["Roles"]
    for r in roles:
        evidence.append(f"Role present: {r['RoleName']}")

    users = iam.list_users()["Users"]
    for u in users:
        policies = iam.list_attached_user_policies(UserName=u["UserName"])
        for p in policies["AttachedPolicies"]:
            if "AdministratorAccess" in p["PolicyName"]:
                score = min(score, 2)
                findings.append(f"Admin policy attached to user {u['UserName']}")

    return jsonify({
        "control": "Q3.4",
        "title": "Access Control & Least Privilege",
        "score": score,
        "status": "PARTIAL" if findings else "COMPLIANT",
        "findings": findings,
        "evidence": evidence,
        "timestamp": time.time()
    })


# /audit/q3/audit-logging

@app.route("/audit/q3/audit-logging")
def audit_logging():
    ct = aws_client("cloudtrail")
    findings, evidence = [], []
    score = 3

    trails = ct.describe_trails()["trailList"]
    if not trails:
        score = 0
        findings.append("CloudTrail not enabled")
    else:
        for t in trails:
            evidence.append(f"Trail: {t['Name']}")
            if not t["IsMultiRegionTrail"]:
                score = min(score, 2)
                findings.append("Trail not multi-region")

    return jsonify({
        "control": "Q3.5",
        "title": "Audit Logging & Monitoring",
        "score": score,
        "status": "COMPLIANT" if score == 3 else "PARTIAL",
        "findings": findings,
        "evidence": evidence,
        "timestamp": time.time()
    })


# /audit/q3/network-segmentation

@app.route("/audit/q3/network-segmentation")
def network_segmentation():
    ec2 = aws_client("ec2")
    findings, evidence = [], []
    score = 3

    subnets = ec2.describe_subnets()["Subnets"]
    for s in subnets:
        if s["MapPublicIpOnLaunch"]:
            score = min(score, 2)
            findings.append(f"Public subnet: {s['SubnetId']}")
        else:
            evidence.append(f"Private subnet: {s['SubnetId']}")

    return jsonify({
        "control": "Q3.11",
        "title": "Network Segmentation & Zero Trust",
        "score": score,
        "status": "PARTIAL" if findings else "COMPLIANT",
        "findings": findings,
        "evidence": evidence,
        "timestamp": time.time()
    })


#  /audit/q3/network-segmentation

@app.route("/audit/q3/summary")
def q3_summary():
    # Call internal functions or re-fetch
    return jsonify({
        "section": "Section 3 – Security Safeguards",
        "max_score": 75,
        "calculated_score": 61,
        "risk_level": "MEDIUM"
    })



# ----------------- Run App -----------------
if __name__ == "__main__":
    # app.run(debug=True)
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
