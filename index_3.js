const express = require("express");
const cors = require("cors");
const AWS = require("aws-sdk");

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

/* ----------------- Helpers ----------------- */
async function awsClient(service) {
  const sts = new AWS.STS({ region: REGION });

  const assumed = await sts
    .assumeRole({
      RoleArn: ROLE_ARN,
      RoleSessionName: "poc-session",
    })
    .promise();

  const creds = assumed.Credentials;

  return new AWS[service]({
    region: REGION,
    accessKeyId: creds.AccessKeyId,
    secretAccessKey: creds.SecretAccessKey,
    sessionToken: creds.SessionToken,
  });
}

function safeInt(val) {
  const n = parseInt(val);
  return isNaN(n) ? 0 : n;
}

function isPrivateIp(ip) {
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.16.") ||
    ip.startsWith("172.17.") ||
    ip.startsWith("172.18.") ||
    ip.startsWith("172.19.") ||
    ip.startsWith("172.2")
  );
}

/* ----------------- Fetch Flow Logs ----------------- */
async function fetchFlowLogs(logGroupName, startTime, endTime, limit = 1000) {
  const logs = await awsClient("CloudWatchLogs");

  startTime = startTime || Date.now() - 3600 * 1000;
  endTime = endTime || Date.now();

  const response = await logs
    .filterLogEvents({
      logGroupName: logGroupName,
      startTime,
      endTime,
      limit,
    })
    .promise();

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
        action: parts[12] || null,
      });
    }
  }

  return flowLogs;
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

    if (eni.Attachment && eni.Attachment.InstanceId) {
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
  for (const db of dbs) {
    eniMap[db.Endpoint.Address] = {
      type: "RDS",
      id: db.DBInstanceIdentifier,
      name: db.DBInstanceIdentifier,
    };
  }

  return eniMap;
}

/* ----------------- Infra Topology Graph ----------------- */
async function fetchInfraTopology() {
  const ec2 = await awsClient("EC2");
  const rds = await awsClient("RDS");

  const nodes = [];
  const edges = [];

  const vpcs = (await ec2.describeVpcs().promise()).Vpcs;
  vpcs.forEach(vpc => nodes.push({ id: vpc.VpcId, type: "VPC", name: vpc.VpcId }));

  const subnets = (await ec2.describeSubnets().promise()).Subnets;
  subnets.forEach(s => {
    nodes.push({ id: s.SubnetId, type: "Subnet", name: s.SubnetId });
    edges.push({ from: s.SubnetId, to: s.VpcId, relation: "belongs_to" });
  });

  return { nodes, edges };
}

/* ----------------- Infer Traffic Relations ----------------- */
function inferRelations(flowLogs, eniMap) {
  const edgesMap = {};
  const nodes = [];
  const seen = new Set();

  function addNode(n) {
    if (!seen.has(n.id)) {
      nodes.push(n);
      seen.add(n.id);
    }
  }

  for (const log of flowLogs) {
    const srcNode = eniMap[log.src] || { type: "Internet", id: "Internet", name: "Internet" };
    const dstNode = eniMap[log.dst] || { type: "Internet", id: "Internet", name: "Internet" };

    addNode(srcNode);
    addNode(dstNode);

    const key = `${srcNode.id}-${dstNode.id}`;
    if (!edgesMap[key]) {
      edgesMap[key] = { ports: new Set(), protocols: new Set(), type: `${srcNode.type} → ${dstNode.type}` };
    }

    edgesMap[key].ports.add(log.dstPort);
    edgesMap[key].protocols.add(log.protocol === 6 ? "TCP" : log.protocol === 17 ? "UDP" : String(log.protocol));
  }

  const edges = Object.entries(edgesMap).map(([key, val]) => {
    const [from, to] = key.split("-");
    return { from, to, ports: [...val.ports].sort(), protocols: [...val.protocols], relation: val.type };
  });

  return { nodes, edges };
}

/* ----------------- Hierarchical Infra (FULL) ----------------- */
async function buildHierarchicalInfra() {
  const ec2 = await awsClient("EC2");
  const rds = await awsClient("RDS");

  const output = { vpcs: [] };

  const subnets = (await ec2.describeSubnets().promise()).Subnets;
  const routeTables = (await ec2.describeRouteTables().promise()).RouteTables;
  const reservations = (await ec2.describeInstances().promise()).Reservations;
  const igws = (await ec2.describeInternetGateways().promise()).InternetGateways;
  const dbs = (await rds.describeDBInstances().promise()).DBInstances;

  const subnetRoutes = {};
  for (const rt of routeTables) {
    for (const assoc of rt.Associations || []) {
      if (assoc.SubnetId) subnetRoutes[assoc.SubnetId] = rt;
    }
  }

  const vpcs = (await ec2.describeVpcs().promise()).Vpcs;

  for (const vpc of vpcs) {
    const vpcObj = { id: vpc.VpcId, internetGateway: null, subnets: { public: [], private: [] } };

    for (const igw of igws) {
      for (const att of igw.Attachments || []) {
        if (att.VpcId === vpc.VpcId) vpcObj.internetGateway = { id: igw.InternetGatewayId };
      }
    }

    for (const subnet of subnets.filter(s => s.VpcId === vpc.VpcId)) {
      const subnetId = subnet.SubnetId;
      const rt = subnetRoutes[subnetId];

      let isPublic = false;
      let routes = [];

      if (rt) {
        for (const r of rt.Routes || []) {
          if (r.DestinationCidrBlock === "0.0.0.0/0" && r.GatewayId) isPublic = true;
          routes.push({
            destination: r.DestinationCidrBlock || null,
            target: r.GatewayId || r.NatGatewayId || "local",
          });
        }
      }

      const subnetObj = {
        id: subnetId,
        availabilityZone: subnet.AvailabilityZone,
        routeTable: rt ? { id: rt.RouteTableId, routes } : null,
        resources: { ec2Instances: [], loadBalancers: [], s3Buckets: [], rdsInstances: [], lambdaFunctions: [] },
      };

      for (const res of reservations) {
        for (const inst of res.Instances) {
          if (inst.SubnetId === subnetId) {
            subnetObj.resources.ec2Instances.push({
              id: inst.InstanceId,
              type: "EC2",
              publiclyAccessible: !!inst.PublicIpAddress,
            });
          }
        }
      }

      for (const db of dbs) {
        for (const s of db.DBSubnetGroup.Subnets) {
          if (s.SubnetIdentifier === subnetId) {
            subnetObj.resources.rdsInstances.push({
              id: db.DBInstanceIdentifier,
              engine: db.Engine,
              publiclyAccessible: db.PubliclyAccessible,
            });
          }
        }
      }

      isPublic ? vpcObj.subnets.public.push(subnetObj) : vpcObj.subnets.private.push(subnetObj);
    }

    output.vpcs.push(vpcObj);
  }

  return output;
}

/* ----------------- ROUTES ----------------- */

app.get("/", (req, res) => res.send("API running"));

app.get("/graph", async (req, res) => {
  const flowLogs = await fetchFlowLogs(VPC_FLOWLOG_GROUP);
  if (!flowLogs.length) return res.status(404).json({ error: "No flow logs found" });

  const eniMap = await buildEniMap();
  res.json({
    traffic: inferRelations(flowLogs, eniMap),
    topology: await fetchInfraTopology(),
  });
});

app.get("/infra", async (req, res) => res.json(await buildHierarchicalInfra()));

/* ----------------- START SERVER ----------------- */
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Server running on port ${port}`));
