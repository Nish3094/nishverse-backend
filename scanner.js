// ── AWS Scanner ────────────────────────────────────────────────────────────
// Collects raw state from AWS services using assumed-role credentials.
// Returns structured resource data — NO hardcoded findings or CIS references.
// The scan engine in server.js compares this data against RAG-retrieved CIS
// controls to generate findings dynamically.

import { S3Client, ListBucketsCommand, GetBucketLocationCommand, GetBucketAclCommand, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3";
import { IAMClient, GetAccountPasswordPolicyCommand, ListUsersCommand, ListAccessKeysCommand, GetAccountSummaryCommand } from "@aws-sdk/client-iam";
import { EC2Client, DescribeSecurityGroupsCommand, DescribeVpcsCommand, DescribeFlowLogsCommand, DescribeVolumesCommand } from "@aws-sdk/client-ec2";
import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { GuardDutyClient, ListDetectorsCommand, GetDetectorCommand } from "@aws-sdk/client-guardduty";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";

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

async function safe(fn) {
  try { return await fn(); }
  catch (e) {
    if (["AccessDenied", "AccessDeniedException", "UnauthorizedOperation"].includes(e.name)) return null;
    throw e;
  }
}

// ── S3 ─────────────────────────────────────────────────────────────────────
async function scanS3(creds) {
  const results = [];
  try {
    const s3 = makeClient(S3Client, creds);
    const { Buckets = [] } = await s3.send(new ListBucketsCommand({}));

    for (const bucket of Buckets) {
      const resource = { name: bucket.Name, service: "S3", type: "aws_s3_bucket" };

      // Get region-specific client
      let s3r = s3;
      try {
        const { LocationConstraint } = await s3.send(new GetBucketLocationCommand({ Bucket: bucket.Name }));
        s3r = makeClient(S3Client, creds, LocationConstraint || "us-east-1");
      } catch (_) {}

      // Public access block
      try {
        const block = await s3r.send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name }));
        const cfg = block?.PublicAccessBlockConfiguration;
        resource.blockPublicAcls       = cfg?.BlockPublicAcls       ?? false;
        resource.blockPublicPolicy     = cfg?.BlockPublicPolicy     ?? false;
        resource.ignorePublicAcls      = cfg?.IgnorePublicAcls      ?? false;
        resource.restrictPublicBuckets = cfg?.RestrictPublicBuckets ?? false;
        resource.publicAccessFullyBlocked = cfg?.BlockPublicAcls && cfg?.BlockPublicPolicy && cfg?.IgnorePublicAcls && cfg?.RestrictPublicBuckets;
      } catch (e) {
        if (e.name === "NoSuchPublicAccessBlockConfiguration") {
          resource.publicAccessFullyBlocked = false;
          resource.blockPublicAcls = resource.blockPublicPolicy = resource.ignorePublicAcls = resource.restrictPublicBuckets = false;
          resource.noPublicAccessBlockConfig = true;
        }
      }

      // ACL public grants
      try {
        const acl = await s3r.send(new GetBucketAclCommand({ Bucket: bucket.Name }));
        const publicUris = ["http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"];
        resource.hasPublicAcl = (acl.Grants || []).some(g => g.Grantee?.URI && publicUris.includes(g.Grantee.URI));
      } catch (_) { resource.hasPublicAcl = false; }

      resource.isPublic = !resource.publicAccessFullyBlocked || resource.hasPublicAcl;
      results.push(resource);
    }
  } catch (e) { console.error("[Scanner] S3 error:", e.message); }
  return results;
}

// ── IAM ─────────────────────────────────────────────────────────────────────
async function scanIAM(creds) {
  const results = [];
  const iam = makeClient(IAMClient, creds);

  // Root MFA
  try {
    const summary = await safe(() => iam.send(new GetAccountSummaryCommand({})));
    results.push({
      service: "IAM", type: "aws_iam_account_root",
      mfaEnabled: summary?.SummaryMap?.AccountMFAEnabled === 1,
      accountAccessKeysPresent: summary?.SummaryMap?.AccountAccessKeysPresent > 0,
    });
  } catch (e) { console.error("[Scanner] IAM root error:", e.message); }

  // Password policy
  try {
    let policy = null;
    try { const r = await iam.send(new GetAccountPasswordPolicyCommand({})); policy = r.PasswordPolicy; }
    catch (e) { if (e.name !== "NoSuchEntityException") throw e; }
    results.push({
      service: "IAM", type: "aws_iam_account_password_policy",
      hasPolicy:         !!policy,
      minLength:         policy?.MinimumPasswordLength || 0,
      requireUppercase:  policy?.RequireUppercaseCharacters ?? false,
      requireLowercase:  policy?.RequireLowercaseCharacters ?? false,
      requireNumbers:    policy?.RequireNumbers ?? false,
      requireSymbols:    policy?.RequireSymbols ?? false,
      preventReuse:      policy?.PasswordReusePrevention || 0,
      meetsMinLength:    (policy?.MinimumPasswordLength || 0) >= 14,
    });
  } catch (e) { console.error("[Scanner] IAM password policy error:", e.message); }

  // Access key rotation
  try {
    const { Users = [] } = await iam.send(new ListUsersCommand({}));
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    const staleKeys = [];
    for (const user of Users.slice(0, 20)) {
      const keys = await safe(() => iam.send(new ListAccessKeysCommand({ UserName: user.UserName })));
      const stale = (keys?.AccessKeyMetadata || []).filter(k => k.Status === "Active" && new Date(k.CreateDate) < ninetyDaysAgo);
      stale.forEach(k => staleKeys.push({ user: user.UserName, keyId: k.AccessKeyId, age: Math.floor((Date.now() - new Date(k.CreateDate)) / 86400000) + " days" }));
    }
    results.push({ service: "IAM", type: "aws_iam_access_keys", staleKeys, hasStaleKeys: staleKeys.length > 0 });
  } catch (e) { console.error("[Scanner] IAM key rotation error:", e.message); }

  return results;
}

// ── EC2 ─────────────────────────────────────────────────────────────────────
async function scanEC2(creds) {
  const results = [];
  try {
    const ec2 = makeClient(EC2Client, creds);

    // Security groups open to world on admin ports
    const { SecurityGroups = [] } = await ec2.send(new DescribeSecurityGroupsCommand({}));
    const adminPorts = [22, 3389];
    const openGroups = SecurityGroups.filter(sg =>
      (sg.IpPermissions || []).some(p =>
        adminPorts.includes(p.FromPort) &&
        (p.IpRanges || []).some(r => r.CidrIp === "0.0.0.0/0" || r.CidrIpv6 === "::/0")
      )
    );
    results.push({
      service: "EC2", type: "aws_security_group",
      totalGroups: SecurityGroups.length,
      openAdminPortGroups: openGroups.map(sg => ({ id: sg.GroupId, name: sg.GroupName, vpcId: sg.VpcId })),
      hasOpenAdminPorts: openGroups.length > 0,
    });

    // Unencrypted EBS volumes
    const { Volumes = [] } = await ec2.send(new DescribeVolumesCommand({}));
    const unencrypted = Volumes.filter(v => !v.Encrypted);
    results.push({
      service: "EC2", type: "aws_ebs_volume",
      totalVolumes: Volumes.length,
      unencryptedVolumes: unencrypted.map(v => ({ id: v.VolumeId, size: v.Size, state: v.State })),
      hasUnencryptedVolumes: unencrypted.length > 0,
    });
  } catch (e) { console.error("[Scanner] EC2 error:", e.message); }
  return results;
}

// ── VPC ─────────────────────────────────────────────────────────────────────
async function scanVPC(creds) {
  const results = [];
  try {
    const ec2 = makeClient(EC2Client, creds);
    const { Vpcs = [] } = await ec2.send(new DescribeVpcsCommand({}));
    const { FlowLogs = [] } = await ec2.send(new DescribeFlowLogsCommand({}));
    const coveredVpcs = new Set(FlowLogs.map(fl => fl.ResourceId));
    const vpcsMissingLogs = Vpcs.filter(v => !coveredVpcs.has(v.VpcId));
    results.push({
      service: "VPC", type: "aws_vpc",
      totalVpcs: Vpcs.length,
      vpcsMissingFlowLogs: vpcsMissingLogs.map(v => ({ id: v.VpcId, isDefault: v.IsDefault })),
      allVpcsHaveFlowLogs: vpcsMissingLogs.length === 0,
    });
  } catch (e) { console.error("[Scanner] VPC error:", e.message); }
  return results;
}

// ── CloudTrail ───────────────────────────────────────────────────────────────
async function scanCloudTrail(creds) {
  const results = [];
  try {
    const ct = makeClient(CloudTrailClient, creds);
    const { trailList = [] } = await ct.send(new DescribeTrailsCommand({ includeShadowTrails: false }));
    const multiRegion = trailList.filter(t => t.IsMultiRegionTrail);
    const logValidation = trailList.filter(t => t.LogFileValidationEnabled);
    results.push({
      service: "CloudTrail", type: "aws_cloudtrail",
      totalTrails: trailList.length,
      hasMultiRegionTrail:     multiRegion.length > 0,
      hasLogFileValidation:    logValidation.length > 0,
      trails: trailList.map(t => ({ name: t.Name, multiRegion: t.IsMultiRegionTrail, logValidation: t.LogFileValidationEnabled, s3Bucket: t.S3BucketName })),
    });
  } catch (e) { console.error("[Scanner] CloudTrail error:", e.message); }
  return results;
}

// ── GuardDuty ────────────────────────────────────────────────────────────────
async function scanGuardDuty(creds) {
  const results = [];
  try {
    const gd = makeClient(GuardDutyClient, creds);
    const { DetectorIds = [] } = await gd.send(new ListDetectorsCommand({}));
    let enabled = false;
    if (DetectorIds.length > 0) {
      const detector = await safe(() => gd.send(new GetDetectorCommand({ DetectorId: DetectorIds[0] })));
      enabled = detector?.Status === "ENABLED";
    }
    results.push({ service: "GuardDuty", type: "aws_guardduty_detector", enabled, detectorCount: DetectorIds.length });
  } catch (e) { console.error("[Scanner] GuardDuty error:", e.message); }
  return results;
}

// ── RDS ──────────────────────────────────────────────────────────────────────
async function scanRDS(creds) {
  const results = [];
  try {
    const rds = makeClient(RDSClient, creds);
    const { DBInstances = [] } = await rds.send(new DescribeDBInstancesCommand({}));
    results.push({
      service: "RDS", type: "aws_db_instance",
      totalInstances: DBInstances.length,
      publicInstances:    DBInstances.filter(db => db.PubliclyAccessible).map(db => ({ id: db.DBInstanceIdentifier, engine: db.Engine })),
      unencryptedInstances: DBInstances.filter(db => !db.StorageEncrypted).map(db => ({ id: db.DBInstanceIdentifier, engine: db.Engine })),
      hasPublicInstances:    DBInstances.some(db => db.PubliclyAccessible),
      hasUnencryptedStorage: DBInstances.some(db => !db.StorageEncrypted),
    });
  } catch (e) { console.error("[Scanner] RDS error:", e.message); }
  return results;
}

// ── Main: run all scanners ────────────────────────────────────────────────────
export async function collectAWSState(creds) {
  console.log("[Scanner] Collecting raw AWS state across all services...");
  const [s3, iam, ec2, vpc, cloudtrail, guardduty, rds] = await Promise.all([
    scanS3(creds),
    scanIAM(creds),
    scanEC2(creds),
    scanVPC(creds),
    scanCloudTrail(creds),
    scanGuardDuty(creds),
    scanRDS(creds),
  ]);

  const allResources = [...s3, ...iam, ...ec2, ...vpc, ...cloudtrail, ...guardduty, ...rds];
  console.log(`[Scanner] Collected ${allResources.length} resource snapshots`);
  return allResources;
}