import express from "express";
import cors from "cors";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { S3Client, ListBucketsCommand, GetBucketLocationCommand, GetBucketAclCommand, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";
import { IAMClient, GetAccountPasswordPolicyCommand, ListUsersCommand, ListAccessKeysCommand, GetAccountSummaryCommand } from "@aws-sdk/client-iam";
import { EC2Client, DescribeSecurityGroupsCommand, DescribeVpcsCommand, DescribeFlowLogsCommand, DescribeVolumesCommand } from "@aws-sdk/client-ec2";
import { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } from "@aws-sdk/client-cloudtrail";
import { GuardDutyClient, ListDetectorsCommand, GetDetectorCommand } from "@aws-sdk/client-guardduty";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";


// ── Gemini API helper ──────────────────────────────────────────────────────
// Model: gemini-2.5-flash-lite — best free tier (15 RPM, 1000 RPD, no cost)
// Get your free key: https://aistudio.google.com/apikey
const GEMINI_MODEL = "gemini-2.0-flash-lite"; // stable GA model

async function callGemini(prompt, systemInstruction = null) {
  if (!process.env.GEMINI_API_KEY) {
    throw new Error("GEMINI_API_KEY environment variable is not set on the server.");
  }
  const body = {
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    generationConfig: { maxOutputTokens: 800, temperature: 0.3 },
  };
  if (systemInstruction) {
    body.systemInstruction = { parts: [{ text: systemInstruction }] };
  }

  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${process.env.GEMINI_API_KEY}`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
  );

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || "";
}

const app = express();

// ── CORS ───────────────────────────────────────────────────────────────────
const corsOptions = {
  origin: [
    "https://nishverse.com",       // custom domain
    "https://www.nishverse.com",   // www variant
    "https://nish3094.github.io",  // GitHub Pages fallback
    "http://localhost:3000",       // local dev
    "http://127.0.0.1:5500",       // VS Code Live Server
  ],
  methods: ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

// Preflight BEFORE express.json()
app.options("*", cors(corsOptions));
app.use(cors(corsOptions));
app.use(express.json());
// ── Health check ───────────────────────────────────────────────────────────
app.get("/", (_req, res) => res.json({ status: "lets go!!! Nishverse backend running" }));

// ── Helper: build AWS client with assumed-role credentials ─────────────────
function makeClient(Client, creds, region = "us-east-1") {
  return new Client({
    region,
    credentials: {
      accessKeyId:     creds.AccessKeyId,
      secretAccessKey: creds.SecretAccessKey,
      sessionToken:    creds.SessionToken,
    },
  });
}

// ── Helper: safe AWS call — returns null on permission denied ──────────────
async function safe(fn) {
  try { return await fn(); }
  catch (e) {
    if (e.name === "AccessDenied" || e.name === "AccessDeniedException") return null;
    throw e;
  }
}

// ── Main scan endpoint ─────────────────────────────────────────────────────
app.post("/scan", async (req, res) => {
  const { roleArn, externalId } = req.body;

  if (!roleArn || !roleArn.includes("arn:aws:iam::")) {
    return res.status(400).json({ success: false, error: "Invalid roleArn" });
  }

  let creds;
  try {
    const sts = new STSClient({ region: "us-east-1" });
    const assumed = await sts.send(new AssumeRoleCommand({
      RoleArn:         roleArn,
      RoleSessionName: "nishverse-audit-session",
      ExternalId:      externalId || "nishverse-audit",
      DurationSeconds: 900,
    }));
    creds = assumed.Credentials;
  } catch (err) {
    console.error("AssumeRole failed:", err.message);
    return res.status(403).json({ success: false, error: `Cannot assume role: ${err.message}` });
  }

  const findings = [];

  // ── 1. S3: Public access block + ACL ──────────────────────────────────
  try {
    const s3 = makeClient(S3Client, creds);
    const { Buckets = [] } = await s3.send(new ListBucketsCommand({}));
    console.log(`S3: found ${Buckets.length} bucket(s):`, Buckets.map(b => b.Name));

    for (const bucket of Buckets) {
      let isPublic = false;
      let reason = "";

      // Get bucket region and use a region-specific client
      let s3Regional = s3;
      try {
        const { LocationConstraint } = await s3.send(
          new GetBucketLocationCommand({ Bucket: bucket.Name })
        );
        const bucketRegion = LocationConstraint || "us-east-1"; // null means us-east-1
        s3Regional = makeClient(S3Client, creds, bucketRegion);
      } catch (e) {
        console.error(`S3 region lookup failed for ${bucket.Name}:`, e.message);
      }

      // Check public access block — AWS throws (not returns null) when no config exists
      try {
        const block = await s3Regional.send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name }));
        const cfg = block?.PublicAccessBlockConfiguration;
        if (!cfg || !cfg.BlockPublicAcls || !cfg.BlockPublicPolicy ||
            !cfg.IgnorePublicAcls || !cfg.RestrictPublicBuckets) {
          isPublic = true;
          reason = "public access block is not fully enabled";
        }
      } catch (e) {
        if (e.name === "NoSuchPublicAccessBlockConfiguration") {
          // No block config at all — bucket is potentially public
          isPublic = true;
          reason = "no public access block configuration exists";
        } else if (e.name !== "AccessDenied" && e.name !== "AccessDeniedException") {
          throw e;
        }
      }

      // Also check ACL for public grants (even if block config looks ok)
      if (!isPublic) {
        try {
          const acl = await s3Regional.send(new GetBucketAclCommand({ Bucket: bucket.Name }));
          const publicUris = [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
          ];
          const hasPublicAcl = (acl.Grants || []).some(
            g => g.Grantee?.URI && publicUris.includes(g.Grantee.URI)
          );
          if (hasPublicAcl) {
            isPublic = true;
            reason = "bucket ACL grants public access";
          }
        } catch (e) {
          if (e.name !== "AccessDenied" && e.name !== "AccessDeniedException") throw e;
        }
      }

      console.log(`S3 bucket ${bucket.Name}: isPublic=${isPublic}, reason="${reason}"`);
      if (isPublic) {
        findings.push({
          id:          `s3_public_${bucket.Name}`,
          service:     "S3",
          severity:    "CRITICAL",
          title:       "S3 bucket publicly accessible",
          cis:         "CIS 2.1.5",
          soc2:        "CC6.1",
          resource:    `aws_s3_bucket.${bucket.Name}`,
          description: `Bucket "${bucket.Name}" is public: ${reason}.`,
        });
      }
    }
  } catch (e) { console.error("S3 check error:", e.name, e.message); }

  // ── 2. IAM: Root MFA ──────────────────────────────────────────────────
  try {
    const iam = makeClient(IAMClient, creds);
    const summary = await safe(() => iam.send(new GetAccountSummaryCommand({})));
    if (summary && summary.SummaryMap?.AccountMFAEnabled === 0) {
      findings.push({
        id:          "root_mfa",
        service:     "IAM",
        severity:    "CRITICAL",
        title:       "Root account MFA not enabled",
        cis:         "CIS 1.5",
        soc2:        "CC6.1",
        resource:    "aws_iam_account (root)",
        description: "The AWS root account has no MFA device registered, leaving it vulnerable to credential theft.",
      });
    }
  } catch (e) { console.error("IAM root MFA check error:", e.message); }

  // ── 3. IAM: Password policy ───────────────────────────────────────────
  try {
    const iam = makeClient(IAMClient, creds);
    let passwordPolicy = null;
    try {
      const result = await iam.send(new GetAccountPasswordPolicyCommand({}));
      passwordPolicy = result.PasswordPolicy;
    } catch (e) {
      if (e.name === "NoSuchEntityException" || e.name === "NoSuchEntity") {
        // No password policy set at all — definitely a finding
        passwordPolicy = null;
      } else if (e.name !== "AccessDenied" && e.name !== "AccessDeniedException") {
        throw e;
      }
    }
    if (!passwordPolicy || (passwordPolicy.MinimumPasswordLength || 0) < 14) {
      findings.push({
        id:          "pwd_policy",
        service:     "IAM",
        severity:    "LOW",
        title:       "Weak IAM password policy",
        cis:         "CIS 1.8",
        soc2:        "CC6.1",
        resource:    "aws_iam_account_password_policy",
        description: !passwordPolicy
          ? "No IAM password policy is configured. AWS accounts with no password policy have no minimum security requirements."
          : "Password policy allows passwords shorter than 14 characters or has no complexity requirements.",
      });
    }
  } catch (e) { console.error("Password policy check error:", e.name, e.message); }

  // ── 4. IAM: Access key rotation ───────────────────────────────────────
  try {
    const iam = makeClient(IAMClient, creds);
    const { Users = [] } = await iam.send(new ListUsersCommand({}));
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    let staleKeyFound = false;

    for (const user of Users.slice(0, 20)) { // cap at 20 to avoid timeout
      const keys = await safe(() =>
        iam.send(new ListAccessKeysCommand({ UserName: user.UserName }))
      );
      const stale = (keys?.AccessKeyMetadata || []).some(
        k => k.Status === "Active" && new Date(k.CreateDate) < ninetyDaysAgo
      );
      if (stale) { staleKeyFound = true; break; }
    }

    if (staleKeyFound) {
      findings.push({
        id:          "key_rotate",
        service:     "IAM",
        severity:    "MEDIUM",
        title:       "IAM access keys older than 90 days",
        cis:         "CIS 1.14",
        soc2:        "CC6.1",
        resource:    "aws_iam_access_key.*",
        description: "One or more IAM users have active access keys that have not been rotated in over 90 days.",
      });
    }
  } catch (e) { console.error("Key rotation check error:", e.message); }

  // ── 5. EC2: Security groups open to 0.0.0.0/0 ────────────────────────
  try {
    const ec2 = makeClient(EC2Client, creds);
    const { SecurityGroups = [] } = await ec2.send(new DescribeSecurityGroupsCommand({}));
    const openSgs = SecurityGroups.filter(sg =>
      sg.IpPermissions?.some(rule =>
        rule.IpRanges?.some(r => r.CidrIp === "0.0.0.0/0") &&
        [22, 3389, 0].includes(rule.FromPort)
      )
    );

    if (openSgs.length > 0) {
      findings.push({
        id:          "sg_open",
        service:     "EC2",
        severity:    "HIGH",
        title:       "Security group allows 0.0.0.0/0 ingress",
        cis:         "CIS 5.2",
        soc2:        "CC6.6",
        resource:    `aws_security_group.${openSgs[0].GroupName}`,
        description: `${openSgs.length} security group(s) allow unrestricted inbound access on sensitive ports from the public internet.`,
      });
    }
  } catch (e) { console.error("SG check error:", e.message); }

  // ── 6. EC2: EBS default encryption ───────────────────────────────────
  try {
    const ec2 = makeClient(EC2Client, creds);
    const { Volumes = [] } = await ec2.send(new DescribeVolumesCommand({}));
    const unencrypted = Volumes.filter(v => !v.Encrypted);
    if (unencrypted.length > 0) {
      findings.push({
        id:          "ebs_encrypt",
        service:     "EC2",
        severity:    "HIGH",
        title:       "EBS volumes not encrypted",
        cis:         "CIS 2.2.1",
        soc2:        "CC6.7",
        resource:    "aws_ebs_volume.*",
        description: `${unencrypted.length} EBS volume(s) are not encrypted at rest. Data could be exposed if underlying storage is compromised.`,
      });
    }
  } catch (e) { console.error("EBS check error:", e.message); }

  // ── 7. VPC: Flow logs ─────────────────────────────────────────────────
  try {
    const ec2 = makeClient(EC2Client, creds);
    const { Vpcs = [] } = await ec2.send(new DescribeVpcsCommand({}));
    const { FlowLogs = [] } = await ec2.send(new DescribeFlowLogsCommand({}));
    const coveredVpcs = new Set(FlowLogs.map(fl => fl.ResourceId));
    const uncovered = Vpcs.filter(v => !coveredVpcs.has(v.VpcId));

    if (uncovered.length > 0) {
      findings.push({
        id:          "vpc_flow",
        service:     "VPC",
        severity:    "MEDIUM",
        title:       "VPC flow logs disabled",
        cis:         "CIS 3.9",
        soc2:        "CC7.2",
        resource:    `aws_vpc.${uncovered[0].VpcId}`,
        description: `${uncovered.length} VPC(s) have no flow logs enabled. Network traffic cannot be audited for threats or data exfiltration.`,
      });
    }
  } catch (e) { console.error("VPC flow log check error:", e.message); }

  // ── 8. CloudTrail: Multi-region trail ────────────────────────────────
  try {
    const ct = makeClient(CloudTrailClient, creds);
    const { trailList = [] } = await ct.send(new DescribeTrailsCommand({ includeShadowTrails: false }));
    const hasMultiRegion = trailList.some(t => t.IsMultiRegionTrail && t.HomeRegion === "us-east-1");

    if (!hasMultiRegion) {
      findings.push({
        id:          "cloudtrail",
        service:     "CloudTrail",
        severity:    "HIGH",
        title:       "CloudTrail not enabled as multi-region trail",
        cis:         "CIS 3.1",
        soc2:        "CC7.2",
        resource:    "aws_cloudtrail.main",
        description: "No multi-region CloudTrail trail found. API calls in some regions may go unlogged and unaudited.",
      });
    }
  } catch (e) { console.error("CloudTrail check error:", e.message); }

  // ── 9. GuardDuty: Enabled ────────────────────────────────────────────
  try {
    const gd = makeClient(GuardDutyClient, creds);
    const { DetectorIds = [] } = await gd.send(new ListDetectorsCommand({}));
    let guardDutyOff = DetectorIds.length === 0;

    if (!guardDutyOff && DetectorIds.length > 0) {
      const detector = await safe(() =>
        gd.send(new GetDetectorCommand({ DetectorId: DetectorIds[0] }))
      );
      if (detector?.Status !== "ENABLED") guardDutyOff = true;
    }

    if (guardDutyOff) {
      findings.push({
        id:          "guardduty",
        service:     "GuardDuty",
        severity:    "MEDIUM",
        title:       "GuardDuty not enabled",
        cis:         "CIS 3.8",
        soc2:        "CC7.1",
        resource:    "aws_guardduty_detector",
        description: "AWS GuardDuty threat detection is not active. Malicious activity and compromised resources will go undetected.",
      });
    }
  } catch (e) { console.error("GuardDuty check error:", e.message); }

  // ── 10. RDS: Publicly accessible ─────────────────────────────────────
  try {
    const rds = makeClient(RDSClient, creds);
    const { DBInstances = [] } = await rds.send(new DescribeDBInstancesCommand({}));
    const publicDbs = DBInstances.filter(db => db.PubliclyAccessible);

    if (publicDbs.length > 0) {
      findings.push({
        id:          "rds_public",
        service:     "RDS",
        severity:    "HIGH",
        title:       "RDS instance publicly accessible",
        cis:         "CIS 2.3.2",
        soc2:        "CC6.6",
        resource:    `aws_db_instance.${publicDbs[0].DBInstanceIdentifier}`,
        description: `${publicDbs.length} RDS instance(s) have publicly_accessible = true, exposing the database endpoint to the internet.`,
      });
    }
  } catch (e) { console.error("RDS check error:", e.message); }

  // ── Sort by severity and respond ──────────────────────────────────────
  const SEVORD = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  findings.sort((a, b) => (SEVORD[a.severity] ?? 9) - (SEVORD[b.severity] ?? 9));

  return res.json({
    success: true,
    scannedAt: new Date().toISOString(),
    roleArn,
    findings,
    summary: {
      total:    findings.length,
      critical: findings.filter(f => f.severity === "CRITICAL").length,
      high:     findings.filter(f => f.severity === "HIGH").length,
      medium:   findings.filter(f => f.severity === "MEDIUM").length,
      low:      findings.filter(f => f.severity === "LOW").length,
    },
  });
});


// ── AI: Explain risk for a finding ────────────────────────────────────────
app.post("/explain", async (req, res) => {
  const { finding } = req.body;
  if (!finding) return res.status(400).json({ error: "Missing finding" });

  try {
    const prompt = `Explain the real-world risk of this AWS security finding in 3-4 sentences for a DevOps engineer. Then give ONE concrete attack scenario an adversary could exploit.

Finding: "${finding.title}"
Service: ${finding.service}
Resource: ${finding.resource}
Description: ${finding.description}
CIS Control: ${finding.cis}

Be direct and technical. No bullet points.`;

    const explanation = await callGemini(prompt);
    res.json({ explanation: explanation || "No explanation generated." });
  } catch(err) {
    console.error("Explain error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── AI: Generate Terraform fix for a finding ──────────────────────────────
app.post("/terraform", async (req, res) => {
  const { finding } = req.body;
  if (!finding) return res.status(400).json({ error: "Missing finding" });

  try {
    const prompt = `Generate a complete, production-ready Terraform HCL snippet to remediate this AWS security finding.

Finding: "${finding.title}"
Resource: ${finding.resource}
Description: ${finding.description}
CIS Control: ${finding.cis}

Rules:
- Output ONLY valid HCL inside a single fenced \`\`\`hcl code block
- Use realistic resource names matching the finding resource field
- Add inline comments explaining WHY each attribute is set
- Include supporting resources (KMS keys, IAM roles, log groups) if needed
- No prose outside the code block`;

    const terraform = await callGemini(prompt);
    res.json({ terraform: terraform || "# Could not generate fix" });
  } catch(err) {
    console.error("Terraform error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── AI: Chat about the environment ────────────────────────────────────────
app.post("/chat", async (req, res) => {
  const { messages, findings } = req.body;
  if (!messages || !findings) return res.status(400).json({ error: "Missing messages or findings" });

  const systemInstruction = `You are a senior AWS cloud security engineer embedded in a Security Posture dashboard called Nishverse.
The user's environment has these active findings:

${findings.map(f => `[${f.severity}] ${f.title} (${f.service}) — ${f.description} | CIS: ${f.cis} | Resource: ${f.resource}`).join("\n")}

Rules:
- Be concise, direct, and technical but readable
- Answer only about this AWS environment and its security posture
- When asked for remediation plans, prioritize CRITICAL first, then HIGH
- Use markdown sparingly — short bold phrases only`;

  try {
    // Gemini uses a flat conversation format — combine history into a single prompt
    const lastUserMsg = messages.filter(m => m.role === "user").pop()?.content || "";
    const history = messages.slice(0, -1).map(m => `${m.role === "user" ? "User" : "Assistant"}: ${m.content}`).join("\n");
    const fullPrompt = history ? `${history}\n\nUser: ${lastUserMsg}` : lastUserMsg;

    const reply = await callGemini(fullPrompt, systemInstruction);
    res.json({ reply, content: [{ text: reply }] });
  } catch(err) {
    console.error("Chat error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Nishverse backend running on port ${PORT}`));