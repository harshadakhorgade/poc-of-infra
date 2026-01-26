const express = require("express");
const cors = require("cors");
const AWS = require("aws-sdk");
const ipaddr = require("ipaddr.js");

const app = express();
app.use(cors());
app.use(express.json());

/* ----------------- Port → Service Mapping ----------------- */
const PORT_SERVICE_MAP = {
  22: "SSH",
  80: "HTTP",
  443: "HTTPS",
  5432: "PostgreSQL",
  3306: "MySQL",
  6379: "Redis",
  53: "DNS",
  123: "NTP",
};

/* ----------------- Config ----------------- */
const ROLE_ARN = "arn:aws:iam::146937414118:role/Saas_Infra_Readonly";
const REGION = "us-east-1";
const VPC_FLOWLOG_GROUP = "/aws/vpc/flowlogs";

/* ----------------- Assume Role ----------------- */
async function awsClient(service) {
  const sts = new AWS.STS({ region: REGION });

  const creds = await sts
    .assumeRole({
      RoleArn: ROLE_ARN,
      RoleSessionName: "poc-session",
    })
    .promise();

  return new AWS[service]({
    region: REGION,
    accessKeyId: creds.Credentials.AccessKeyId,
    secretAccessKey: creds.Credentials.SecretAccessKey,
    sessionToken: creds.Credentials.SessionToken,
  });
}

/* ----------------- Helpers ----------------- */
const safeInt = (val) => parseInt(val) || 0;

function isPrivateIp(ip) {
  try {
    return ipaddr.parse(ip).range() !== "unicast";
  } catch {
    return false;
  }
}

/* ----------------- Fetch Flow Logs ----------------- */
async function fetchFlowLogs() {
  const logs = await awsClient("CloudWatchLogs");
  const endTime = Date.now();
  const startTime = endTime - 3600 * 1000;

  const res = await logs
    .filterLogEvents({
      logGroupName: VPC_FLOWLOG_GROUP,
      startTime,
      endTime,
      limit: 1000,
    })
    .promise();

  return res.events
    .map((e) => {
      const p = e.message.split(" ");
      if (p.length < 12) return null;
      return {
        eni: p[2],
        src: p[3],
        dst: p[4],
        srcPort: safeInt(p[5]),
        dstPort: safeInt(p[6]),
        protocol: safeInt(p[7]),
        action: p[12] || null,
      };
    })
    .filter(Boolean);
}

/* ----------------- ENI Map ----------------- */
async function buildEniMap() {
  const ec2 = await awsClient("EC2");
  const rds = await awsClient("RDS");
  const eniMap = {};

  const enis = (await ec2.describeNetworkInterfaces().promise()).NetworkInterfaces;

  for (const eni of enis) {
    const ip = eni.PrivateIpAddress;
    const desc = eni.Description || "";

    if (eni.Attachment?.InstanceId) {
      eniMap[ip] = { type: "EC2", id: eni.Attachment.InstanceId, name: eni.Attachment.InstanceId };
    } else if (desc.includes("ELB")) {
      eniMap[ip] = { type: "ALB", id: desc, name: "LoadBalancer" };
    } else if (desc.toLowerCase().includes("nat")) {
      eniMap[ip] = { type: "NAT", id: desc, name: "NATGateway" };
    } else if (desc.toLowerCase().includes("rds")) {
      eniMap[ip] = { type: "RDS", id: desc, name: "RDS" };
    }
  }

  const dbs = (await rds.describeDBInstances().promise()).DBInstances;
  dbs.forEach((db) => {
    eniMap[db.Endpoint.Address] = {
      type: "RDS",
      id: db.DBInstanceIdentifier,
      name: db.DBInstanceIdentifier,
    };
  });

  return eniMap;
}

/* ----------------- Infer Relations ----------------- */
function inferRelations(flowLogs, eniMap) {
  const edgesMap = {};
  const nodes = new Map();

  const addNode = (n) => nodes.set(n.id, n);

  for (const log of flowLogs) {
    const protocol = log.protocol === 6 ? "TCP" : log.protocol === 17 ? "UDP" : String(log.protocol);

    const srcNode = eniMap[log.src] || { type: "Internet", id: "Internet", name: "Internet" };
    const dstNode = eniMap[log.dst] || { type: "Internet", id: "Internet", name: "Internet" };

    addNode(srcNode);
    addNode(dstNode);

    const key = `${srcNode.id}->${dstNode.id}`;
    if (!edgesMap[key]) {
      edgesMap[key] = { from: srcNode.id, to: dstNode.id, ports: new Set(), protocols: new Set(), relation: `${srcNode.type} → ${dstNode.type}` };
    }
    edgesMap[key].ports.add(log.dstPort);
    edgesMap[key].protocols.add(protocol);
  }

  return {
    nodes: Array.from(nodes.values()),
    edges: Object.values(edgesMap).map((e) => ({
      ...e,
      ports: Array.from(e.ports).sort(),
      protocols: Array.from(e.protocols),
    })),
  };
}

/* ----------------- Infra Topology ----------------- */
async function fetchInfraTopology() {
  const ec2 = await awsClient("EC2");
  const rds = await awsClient("RDS");

  const nodes = [];
  const edges = [];

  const vpcs = (await ec2.describeVpcs().promise()).Vpcs;
  vpcs.forEach((v) => nodes.push({ id: v.VpcId, type: "VPC", name: v.VpcId }));

  const subnets = (await ec2.describeSubnets().promise()).Subnets;
  subnets.forEach((s) => {
    nodes.push({ id: s.SubnetId, type: "Subnet", name: s.SubnetId });
    edges.push({ from: s.SubnetId, to: s.VpcId, relation: "belongs_to" });
  });

  return { nodes, edges };
}

/* ----------------- Routes ----------------- */

app.get("/", (req, res) => res.send("API running"));

app.get("/graph", async (req, res) => {
  try {
    const flowLogs = await fetchFlowLogs();
    if (!flowLogs.length) return res.status(404).json({ error: "No flow logs found" });

    const eniMap = await buildEniMap();
    const traffic = inferRelations(flowLogs, eniMap);
    const topology = await fetchInfraTopology();

    res.json({ traffic, topology });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Graph generation failed" });
  }
});

/* ----------------- Server ----------------- */
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Server running on port ${port}`));
