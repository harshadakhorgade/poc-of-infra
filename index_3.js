// index.js
const express = require("express");
const AWS = require("aws-sdk");
const cors = require("cors");
const ipaddr = require("ipaddr.js");

const app = express();
app.use(cors());
app.use(express.json());

// ----------------- Port → Service Mapping -----------------
const PORT_SERVICE_MAP = {
  22: "SSH",
  80: "HTTP",
  443: "HTTPS",
  5432: "PostgreSQL",
  3306: "MySQL",
  6379: "Redis",
  53: "DNS",
  123: "NTP"
};

// ----------------- Config -----------------
const ROLE_ARN = "arn:aws:iam::146937414118:role/Saas_Infra_Readonly";
const REGION = "us-east-1";
const VPC_FLOWLOG_GROUP = "/aws/vpc/flowlogs";

// ----------------- Helpers -----------------
async function assumeRole() {
  const sts = new AWS.STS();
  const data = await sts.assumeRole({
    RoleArn: ROLE_ARN,
    RoleSessionName: "poc-session"
  }).promise();

  return new AWS.Config({
    accessKeyId: data.Credentials.AccessKeyId,
    secretAccessKey: data.Credentials.SecretAccessKey,
    sessionToken: data.Credentials.SessionToken,
    region: REGION
  });
}

function safeInt(val) {
  const n = parseInt(val);
  return isNaN(n) ? 0 : n;
}

function isPrivateIp(ip) {
  try {
    return ipaddr.parse(ip).range() !== "unicast";
  } catch (e) {
    return false;
  }
}

// ----------------- Fetch Flow Logs -----------------
async function fetchFlowLogs(config, logGroupName, startTime = null, endTime = null, limit = 1000) {
  const cloudwatchlogs = new AWS.CloudWatchLogs(config);
  const now = Date.now();
  startTime = startTime || now - 3600 * 1000;
  endTime = endTime || now;

  const response = await cloudwatchlogs.filterLogEvents({
    logGroupName,
    startTime,
    endTime,
    limit
  }).promise();

  const flowLogs = [];
  for (const event of response.events) {
    const parts = event.message.split(" ");
    if (parts.length >= 12) {
      flowLogs.push({
        eni: parts[2],
        src: parts[3],
        dst: parts[4],
        srcPort: safeInt(parts[5]),
        dstPort: safeInt(parts[6]),
        protocol: safeInt(parts[7]),
        action: parts[12] || null
      });
    }
  }
  return flowLogs;
}

// ----------------- Build ENI → Resource Map -----------------
async function buildEniMap(config) {
  const ec2 = new AWS.EC2(config);
  const rds = new AWS.RDS(config);
  const eniMap = {};

  const enis = (await ec2.describeNetworkInterfaces().promise()).NetworkInterfaces;

  for (const eni of enis) {
    const ip = eni.PrivateIpAddress;
    const desc = eni.Description || "";

    if (eni.Attachment && eni.Attachment.InstanceId) {
      const instanceId = eni.Attachment.InstanceId;
      eniMap[ip] = { type: "EC2", id: instanceId, name: instanceId };
    } else if (desc.includes("ELB")) {
      eniMap[ip] = { type: "ALB", id: desc, name: "LoadBalancer" };
    } else if (desc.toLowerCase().includes("nat")) {
      eniMap[ip] = { type: "NAT", id: desc, name: "NATGateway" };
    } else if (desc.toLowerCase().includes("rds")) {
      eniMap[ip] = { type: "RDS", id: desc, name: "RDS" };
    }
  }

  // RDS endpoint DNS
  const dbs = (await rds.describeDBInstances().promise()).DBInstances;
  for (const db of dbs) {
    eniMap[db.Endpoint.Address] = {
      type: "RDS",
      id: db.DBInstanceIdentifier,
      name: db.DBInstanceIdentifier
    };
  }

  return eniMap;
}

// ----------------- Infer Relations -----------------
function inferRelations(flowLogs, eniMap) {
  const edgesMap = {};
  const nodes = [];
  const seenNodes = new Set();

  function addNode(n) {
    if (!seenNodes.has(n.id)) {
      nodes.push(n);
      seenNodes.add(n.id);
    }
  }

  for (const log of flowLogs) {
    const srcIp = log.src;
    const dstIp = log.dst;
    const port = log.dstPort;
    const protocol = log.protocol === 6 ? "TCP" : log.protocol === 17 ? "UDP" : `${log.protocol}`;

    const srcNode = eniMap[srcIp] || { type: "Internet", id: "Internet", name: "Internet" };
    const dstNode = eniMap[dstIp] || { type: "Internet", id: "Internet", name: "Internet" };

    addNode(srcNode);
    addNode(dstNode);

    const key = `${srcNode.id}->${dstNode.id}`;
    if (!edgesMap[key]) {
      edgesMap[key] = { ports: new Set(), protocols: new Set(), type: `${srcNode.type} → ${dstNode.type}` };
    }
    edgesMap[key].ports.add(port);
    edgesMap[key].protocols.add(protocol);
  }

  const edges = [];
  for (const [key, info] of Object.entries(edgesMap)) {
    edges.push({
      from: key.split("->")[0],
      to: key.split("->")[1],
      ports: Array.from(info.ports).sort((a, b) => a - b),
      protocols: Array.from(info.protocols),
      relation: info.type
    });
  }

  return { nodes, edges };
}

// ----------------- Fetch Infra Topology -----------------
async function fetchInfraTopology(config) {
  const ec2 = new AWS.EC2(config);
  const rds = new AWS.RDS(config);
  const nodes = [];
  const edges = [];

  const vpcs = (await ec2.describeVpcs().promise()).Vpcs;
  const subnets = (await ec2.describeSubnets().promise()).Subnets;
  const routeTables = (await ec2.describeRouteTables().promise()).RouteTables;
  const natGateways = (await ec2.describeNatGateways().promise()).NatGateways;
  const igws = (await ec2.describeInternetGateways().promise()).InternetGateways;
  const instances = (await ec2.describeInstances().promise()).Reservations.flatMap(r => r.Instances);
  const dbs = (await rds.describeDBInstances().promise()).DBInstances;

  // VPCs
  for (const vpc of vpcs) {
    nodes.push({ id: vpc.VpcId, type: "VPC", name: vpc.VpcId });
  }

  // Subnets
  for (const subnet of subnets) {
    nodes.push({ id: subnet.SubnetId, type: "Subnet", name: subnet.SubnetId });
    edges.push({ from: subnet.SubnetId, to: subnet.VpcId, relation: "belongs_to" });
  }

  // Route tables
  for (const rt of routeTables) {
    nodes.push({ id: rt.RouteTableId, type: "RouteTable", name: rt.RouteTableId });
    edges.push({ from: rt.RouteTableId, to: rt.VpcId, relation: "belongs_to" });

    for (const assoc of rt.Associations || []) {
      if (assoc.SubnetId) {
        edges.push({ from: assoc.SubnetId, to: rt.RouteTableId, relation: "uses_route_table" });
      }
    }
  }

  // NAT gateways
  for (const nat of natGateways) {
    nodes.push({ id: nat.NatGatewayId, type: "NAT", name: nat.NatGatewayId });
    edges.push({ from: nat.NatGatewayId, to: nat.SubnetId, relation: "deployed_in" });
  }

  // Internet gateways
  for (const igw of igws) {
    nodes.push({ id: igw.InternetGatewayId, type: "InternetGateway", name: igw.InternetGatewayId });
    for (const att of igw.Attachments || []) {
      edges.push({ from: igw.InternetGatewayId, to: att.VpcId, relation: "attached_to" });
    }
  }

  // EC2 Instances → Subnets
  for (const i of instances) {
    if (i.SubnetId) edges.push({ from: i.InstanceId, to: i.SubnetId, relation: "runs_in" });
  }

  // RDS → Subnets
  for (const db of dbs) {
    for (const s of db.DBSubnetGroup.Subnets) {
      edges.push({ from: db.DBInstanceIdentifier, to: s.SubnetIdentifier, relation: "deployed_in" });
    }
    nodes.push({ id: db.DBInstanceIdentifier, type: "RDS", name: db.DBInstanceIdentifier });
  }

  return { nodes, edges };
}

// ----------------- Routes -----------------
app.get("/", (req, res) => res.send("API running"));

// Graph endpoint
app.get("/graph", async (req, res) => {
  try {
    const config = await assumeRole();
    const flowLogs = await fetchFlowLogs(config, VPC_FLOWLOG_GROUP);
    if (!flowLogs.length) return res.status(404).json({ error: "No flow logs found" });

    const eniMap = await buildEniMap(config);
    const trafficGraph = inferRelations(flowLogs, eniMap);
    const infraGraph = await fetchInfraTopology(config);

    res.json({ traffic: trafficGraph, topology: infraGraph });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Infra hierarchical
app.get("/infra", async (req, res) => {
  try {
    const config = await assumeRole();
    // reuse fetchInfraTopology for simplicity
    const data = await fetchInfraTopology(config);
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// TODO: Add all audit endpoints like Flask (encryption-at-rest, mfa, access-control, etc.) similarly
// Example for encryption-at-rest
app.get("/audit/q3/encryption-at-rest", async (req, res) => {
  try {
    const config = await assumeRole();
    const rds = new AWS.RDS(config);
    const s3 = new AWS.S3(config);
    const kms = new AWS.KMS(config);

    const findings = [];
    const evidence = [];
    let score = 3;

    // RDS encryption
    const dbs = (await rds.describeDBInstances().promise()).DBInstances;
    for (const db of dbs) {
      if (!db.StorageEncrypted) {
        score = Math.min(score, 2);
        findings.push(`RDS ${db.DBInstanceIdentifier} not encrypted`);
      } else evidence.push(`RDS encrypted: ${db.DBInstanceIdentifier}`);
    }

    // S3 encryption
    const buckets = (await s3.listBuckets().promise()).Buckets;
    for (const b of buckets) {
      try {
        await s3.getBucketEncryption({ Bucket: b.Name }).promise();
        evidence.push(`S3 encrypted: ${b.Name}`);
      } catch (err) {
        score = Math.min(score, 2);
        findings.push(`S3 bucket unencrypted: ${b.Name}`);
      }
    }

    // KMS rotation
    const keys = (await kms.listKeys().promise()).Keys;
    for (const k of keys) {
      const rotation = await kms.getKeyRotationStatus({ KeyId: k.KeyId }).promise();
      if (!rotation.KeyRotationEnabled) {
        score = Math.min(score, 1);
        findings.push("KMS key rotation disabled");
      }
    }

    res.json({
      control: "Q3.1",
      title: "Encryption at Rest",
      score,
      status: score === 3 ? "COMPLIANT" : "PARTIAL",
      findings,
      evidence,
      timestamp: Date.now()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ----------------- Start Server -----------------
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Server running on port ${port}`));
