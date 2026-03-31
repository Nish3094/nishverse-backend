// ── CIS AWS Foundations Benchmark v3.0 Knowledge Base ─────────────────────
// Source: CIS AWS Foundations Benchmark v3.0, CIS IAM Controls, CIS S3 Controls
// Each entry = one chunk that gets embedded and stored in Pinecone

export const CIS_CONTROLS = [

  // ── IDENTITY & ACCESS MANAGEMENT ──────────────────────────────────────────

  {
    id: "cis-1.1",
    control: "CIS 1.1",
    title: "Maintain current contact details",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.1: Ensure contact email and telephone details for AWS accounts are current and map to more than one individual in your organization. AWS will use these details to contact the account owner if there are security issues. Rationale: Ensure contact email and telephone details for AWS accounts are current and map to more than one individual in your organization. Remediation: Log into the AWS Management Console, navigate to your account settings, and update primary and alternate contacts with valid organizational contacts.`,
  },
  {
    id: "cis-1.4",
    control: "CIS 1.4",
    title: "Ensure no root account access key exists",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.4: Ensure no root account access key exists. The root account is the most privileged AWS account. AWS Access Keys provide programmatic access to a given account. Rationale: Removing access keys associated with the root account limits vectors by which the account can be compromised. Additionally, removing root access keys encourages the creation and use of role-based accounts that are least privileged. Audit: Run the command "aws iam get-account-summary" and check if the value of AccountAccessKeysPresent is 0. Remediation: Log in to the AWS Management console as root. Click on the account name in the top right corner. Click on Security Credentials. Delete all access keys associated with the root account.`,
  },
  {
    id: "cis-1.5",
    control: "CIS 1.5",
    title: "Ensure MFA is enabled for the root account",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.5: Ensure MFA is enabled for the root account. The root account is the most privileged user in an AWS account. MFA adds an extra layer of protection on top of a username and password. Rationale: Enabling MFA provides increased security for console access as it requires the authenticating principal to possess a device that emits a time-sensitive key and have knowledge of a credential. Attack scenario: An adversary who obtains the root account password can log in and have unrestricted access to the entire AWS account, delete all resources, exfiltrate data, and incur unlimited charges — without MFA, there is no second barrier. Remediation: Using IAM console navigate to Dashboard and expand Activate MFA on your root account. Enable a virtual MFA device or hardware MFA. CIS Benchmark Level: Level 1. SOC2 mapping: CC6.1 - Logical and Physical Access Controls.`,
  },
  {
    id: "cis-1.6",
    control: "CIS 1.6",
    title: "Ensure hardware MFA is enabled for the root account",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.6: Ensure hardware MFA is enabled for the root account. A hardware MFA has a smaller attack surface than a virtual MFA. Rationale: A hardware MFA has a smaller attack surface than a virtual MFA. For example, a hardware MFA does not suffer from attacks against the mobile device used for a virtual MFA. Remediation: Log into the root account, navigate to IAM > Dashboard > Activate MFA, and register a hardware MFA device such as a YubiKey or Gemalto token.`,
  },
  {
    id: "cis-1.8",
    control: "CIS 1.8",
    title: "Ensure IAM password policy requires minimum length of 14 or greater",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.8: Ensure IAM password policy requires minimum length of 14 or greater. Password policies are used to enforce password complexity requirements. IAM password policies can be used to ensure passwords are at least a given length. Rationale: Setting a password complexity policy increases account resiliency against brute force login attempts. Attack scenario: Weak passwords can be brute-forced or guessed. An attacker with IAM console access and a weak password can enumerate roles, escalate privileges, and pivot to sensitive resources. Remediation: From the AWS Management Console navigate to IAM > Account Settings and set minimum password length to 14 or greater. Also enable require uppercase, lowercase, numbers, and non-alphanumeric characters. CIS Benchmark Level: Level 1.`,
  },
  {
    id: "cis-1.9",
    control: "CIS 1.9",
    title: "Ensure IAM password policy prevents password reuse",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.9: Ensure IAM password policy prevents password reuse of last 24 passwords. Rationale: Preventing password reuse increases account resiliency against brute force login attempts. Remediation: Navigate to IAM > Account Settings and set number of passwords to remember to 24.`,
  },
  {
    id: "cis-1.10",
    control: "CIS 1.10",
    title: "Ensure MFA is enabled for all IAM users with console access",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.10: Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password. Rationale: Multi-factor authentication (MFA) adds an extra layer of protection on top of a username and password. Enabling MFA for all IAM users with console access provides increased security. Attack scenario: An attacker who obtains or phishes a user's password can immediately log in and access all resources that user has permission to. MFA prevents this by requiring a physical or virtual token. Remediation: Using IAM console, for each IAM user with console access navigate to Security Credentials tab and enable MFA. CIS Level: Level 1.`,
  },
  {
    id: "cis-1.14",
    control: "CIS 1.14",
    title: "Ensure access keys are rotated every 90 days or less",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.14: Ensure access keys are rotated every 90 days or less. Access keys consist of an access key ID and secret access key, which are used to sign programmatic requests to AWS. Rationale: Rotating access keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Attack scenario: A leaked or stolen access key that is never rotated provides permanent programmatic access to all resources the IAM user can access. An attacker can use it to exfiltrate data, launch instances, or move laterally indefinitely. Remediation: Using the IAM console, navigate to each user, select Security Credentials tab, and rotate any active access key older than 90 days. Automate rotation using AWS Secrets Manager or a CI/CD pipeline. CIS Level: Level 1.`,
  },
  {
    id: "cis-1.16",
    control: "CIS 1.16",
    title: "Ensure IAM policies are attached only to groups or roles",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.16: Ensure IAM policies are attached only to groups or roles. By default, IAM users, groups, and roles have no access to AWS resources. IAM policies are the means by which privileges are granted. Rationale: Assigning privileges at the group or role level reduces the complexity of access management as the number of users grows. Attaching policies directly to users makes it harder to audit and manage least-privilege access. Remediation: Remove all direct policy attachments from IAM users. Create groups that reflect job functions and attach policies to those groups. Add users to appropriate groups.`,
  },
  {
    id: "cis-1.17",
    control: "CIS 1.17",
    title: "Ensure a support role has been created to manage incidents with AWS Support",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.17: Ensure a support role has been created to manage incidents with AWS Support. AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. Rationale: By implementing least privilege for access control, an IAM Role will require an appropriate IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support. Remediation: Create an IAM role with the AWSSupportAccess managed policy attached and assign it to appropriate personnel.`,
  },
  {
    id: "cis-1.20",
    control: "CIS 1.20",
    title: "Ensure that AWS Security Hub is enabled",
    service: "IAM",
    section: "Identity and Access Management",
    text: `CIS Control 1.20: Ensure that AWS Security Hub is enabled for the AWS account. Security Hub collects security data from across AWS accounts, services, and supported third-party partner products and helps you analyze your security trends and identify the highest priority security issues. Rationale: AWS Security Hub provides a comprehensive view of the security state of your AWS environment and resources. It also provides you with the readiness status of your environment relative to security industry standards and best practices. Remediation: Enable AWS Security Hub from the console or via CLI: aws securityhub enable-security-hub.`,
  },

  // ── S3 ─────────────────────────────────────────────────────────────────────

  {
    id: "cis-2.1.1",
    control: "CIS 2.1.1",
    title: "Ensure S3 Bucket Policy is set to deny HTTP requests",
    service: "S3",
    section: "Storage - S3",
    text: `CIS Control 2.1.1: Ensure S3 Bucket Policy is set to deny HTTP requests. At the Amazon S3 bucket level, you can configure permissions through a bucket policy making the objects accessible only through HTTPS. Rationale: By default, Amazon S3 allows both HTTP and HTTPS requests. To achieve only allowing access to Amazon S3 objects through HTTPS, a bucket policy needs to explicitly deny access to HTTP to protect data in transit. Attack scenario: An attacker on a shared network can perform a man-in-the-middle attack to intercept unencrypted S3 traffic, stealing sensitive data or credentials in transit. Remediation: Add a bucket policy with condition "aws:SecureTransport": "false" set to Deny to enforce HTTPS only. Terraform: use aws_s3_bucket_policy with a policy that denies s3:* when aws:SecureTransport is false. CIS Level: Level 2.`,
  },
  {
    id: "cis-2.1.2",
    control: "CIS 2.1.2",
    title: "Ensure MFA Delete is enabled on S3 buckets",
    service: "S3",
    section: "Storage - S3",
    text: `CIS Control 2.1.2: Ensure MFA Delete is enabled on S3 buckets. Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication. Rationale: Adding MFA delete to an S3 bucket requires additional authentication when you change the versioning state of the bucket or you delete an object version, adding another layer of security. Attack scenario: An attacker who gains access to long-lived AWS credentials can permanently delete versioned S3 objects without MFA delete. This can destroy critical data backups irreversibly. Remediation: Enable versioning and MFA delete using the root account: aws s3api put-bucket-versioning with MfaDelete=Enabled. CIS Level: Level 2.`,
  },
  {
    id: "cis-2.1.4",
    control: "CIS 2.1.4",
    title: "Ensure that S3 Buckets are configured with Block public access",
    service: "S3",
    section: "Storage - S3",
    text: `CIS Control 2.1.4: Ensure that S3 Buckets are configured with Block public access (bucket settings). Amazon S3 Block Public Access provides settings for access points, buckets, and accounts to help manage public access to Amazon S3 resources. Rationale: Amazon S3 block public access prevents the accidental or malicious public exposure of S3 bucket contents. Attack scenario: A misconfigured S3 bucket with public access can expose sensitive data (PII, credentials, backups, source code) to the entire internet. Attackers regularly scan for public S3 buckets as they are a common source of data breaches. Remediation: Enable all four Block Public Access settings at the bucket level: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets. Terraform: use aws_s3_bucket_public_access_block resource with all four settings set to true. CIS Level: Level 1. SOC2 mapping: CC6.1.`,
  },
  {
    id: "cis-2.1.5",
    control: "CIS 2.1.5",
    title: "Ensure S3 bucket access logging is enabled",
    service: "S3",
    section: "Storage - S3",
    text: `CIS Control 2.1.5: Ensure that S3 bucket access logging is enabled on the CloudTrail S3 bucket. S3 Bucket Access Logging generates a log that contains access records for each request made to your S3 bucket. Rationale: By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which may affect objects within any target buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows. Remediation: Enable server access logging on the bucket via the S3 console or aws s3api put-bucket-logging CLI command. Terraform: use aws_s3_bucket_logging resource.`,
  },
  {
    id: "cis-2.1.6",
    control: "CIS 2.1.6",
    title: "Ensure S3 buckets are encrypted at rest",
    service: "S3",
    section: "Storage - S3",
    text: `CIS Control 2.1.6: Ensure that S3 Buckets have server-side encryption enabled. Amazon S3 default encryption provides a way to set the default encryption behavior for an S3 bucket. Rationale: Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken. Remediation: Enable default encryption on S3 buckets using SSE-S3 or SSE-KMS. Terraform: use aws_s3_bucket_server_side_encryption_configuration with AES256 or aws:kms algorithm. CIS Level: Level 2.`,
  },

  // ── LOGGING ────────────────────────────────────────────────────────────────

  {
    id: "cis-3.1",
    control: "CIS 3.1",
    title: "Ensure CloudTrail is enabled in all regions",
    service: "CloudTrail",
    section: "Logging",
    text: `CIS Control 3.1: Ensure CloudTrail is enabled in all regions. AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you. Rationale: The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing. Additionally, ensuring that a multi-region trail exists will ensure that unexpected activity occurring in otherwise unused regions is detected. Attack scenario: Without a multi-region CloudTrail, an attacker can operate in non-monitored regions — launching instances, creating IAM users, or exfiltrating data in a region with no logging, making the attack invisible in standard audit reviews. Remediation: Create a multi-region CloudTrail trail that applies to all regions: aws cloudtrail create-trail --name multi-region-trail --s3-bucket-name <bucket> --is-multi-region-trail. Terraform: use aws_cloudtrail with is_multi_region_trail = true. CIS Level: Level 1. SOC2: CC7.2.`,
  },
  {
    id: "cis-3.2",
    control: "CIS 3.2",
    title: "Ensure CloudTrail log file validation is enabled",
    service: "CloudTrail",
    section: "Logging",
    text: `CIS Control 3.2: Ensure CloudTrail log file validation is enabled. CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. Rationale: Enabling log file validation will provide additional integrity checking of CloudTrail logs. An adversary with sufficient access could tamper with CloudTrail log files. Validation ensures logs have not been altered or deleted. Remediation: Enable log file validation: aws cloudtrail update-trail --name <trail_name> --enable-log-file-validation. Terraform: use aws_cloudtrail with enable_log_file_validation = true. CIS Level: Level 2.`,
  },
  {
    id: "cis-3.3",
    control: "CIS 3.3",
    title: "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
    service: "CloudTrail",
    section: "Logging",
    text: `CIS Control 3.3: Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible. CloudTrail logs a record of every API call made in your AWS account. These logs file are stored in an S3 bucket. Rationale: Allowing public access to CloudTrail log content may aid an adversary in identifying weaknesses in the affected account's use or configuration. Remediation: Apply S3 Block Public Access settings to the CloudTrail S3 bucket and verify no bucket policy grants public access.`,
  },
  {
    id: "cis-3.7",
    control: "CIS 3.7",
    title: "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
    service: "CloudTrail",
    section: "Logging",
    text: `CIS Control 3.7: Ensure CloudTrail logs are encrypted at rest using KMS CMKs. By default, the log files delivered by CloudTrail to your bucket are encrypted by Amazon server-side encryption with Amazon S3-managed encryption keys (SSE-S3). Rationale: Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data as a given user must have S3 read permission and must be granted decrypt permission by the CMK policy. Remediation: Create a KMS CMK and configure CloudTrail to use it for encryption: aws cloudtrail update-trail --name <trail_name> --kms-key-id <kms_key_id>. CIS Level: Level 2.`,
  },
  {
    id: "cis-3.8",
    control: "CIS 3.8",
    title: "Ensure AWS Config is enabled in all regions",
    service: "Config",
    section: "Logging",
    text: `CIS Control 3.8: Ensure AWS Config is enabled in all regions. AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. Rationale: The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing. Ensuring Config is enabled in all regions catches resource changes in otherwise unused regions. Remediation: Enable AWS Config in all regions using the console or CLI. Terraform: use aws_config_configuration_recorder and aws_config_delivery_channel. CIS Level: Level 2.`,
  },
  {
    id: "cis-3.9",
    control: "CIS 3.9",
    title: "Ensure VPC flow logging is enabled in all VPCs",
    service: "VPC",
    section: "Logging",
    text: `CIS Control 3.9: Ensure VPC flow logging is enabled in all VPCs. VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. Rationale: VPC flow logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows. Attack scenario: Without VPC flow logs, an attacker performing lateral movement, data exfiltration, or C2 communication leaves no network-level audit trail. Security teams cannot reconstruct the timeline of a breach. Remediation: Enable flow logs for all VPCs: aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs. Terraform: use aws_flow_log resource with traffic_type = "ALL". CIS Level: Level 2. SOC2: CC7.2.`,
  },

  // ── MONITORING ─────────────────────────────────────────────────────────────

  {
    id: "cis-4.1",
    control: "CIS 4.1",
    title: "Ensure unauthorized API calls are monitored",
    service: "CloudWatch",
    section: "Monitoring",
    text: `CIS Control 4.1: Ensure a log metric filter and alarm exist for unauthorized API calls. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Rationale: Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity. Remediation: Create a CloudWatch metric filter on CloudTrail logs that matches errorCode "AccessDenied" and "UnauthorizedOperation", then create a CloudWatch alarm on that metric. CIS Level: Level 1.`,
  },
  {
    id: "cis-4.3",
    control: "CIS 4.3",
    title: "Ensure usage of root account is monitored",
    service: "CloudWatch",
    section: "Monitoring",
    text: `CIS Control 4.3: Ensure a log metric filter and alarm exist for usage of root account. Real-time monitoring of API calls can be achieved by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Rationale: Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it. Attack scenario: Any use of the root account is highly suspicious in a mature AWS environment. An alarm on root usage immediately flags potential credential compromise. Remediation: Create a CloudWatch Logs metric filter for principal = root and create an SNS alarm. CIS Level: Level 1.`,
  },

  // ── NETWORKING ─────────────────────────────────────────────────────────────

  {
    id: "cis-5.1",
    control: "CIS 5.1",
    title: "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
    service: "VPC",
    section: "Networking",
    text: `CIS Control 5.1: Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports. The Network Access Control List (NACL) function as a stateless packet filter to control ingress and egress traffic for subnets within a VPC. Rationale: Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise. Remediation: Update NACL inbound rules to restrict ports 22 (SSH) and 3389 (RDP) to known corporate IP ranges only. CIS Level: Level 1.`,
  },
  {
    id: "cis-5.2",
    control: "CIS 5.2",
    title: "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
    service: "EC2",
    section: "Networking",
    text: `CIS Control 5.2: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports. Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. Rationale: Public access to remote server administration ports, such as SSH port 22 and RDP port 3389, increases resource attack surface. Attack scenario: Security groups open to 0.0.0.0/0 on port 22 or 3389 allow any internet user to attempt brute force or exploit authentication vulnerabilities on your EC2 instances. This is one of the most common initial access vectors in AWS breaches. Remediation: Update security group inbound rules to restrict SSH (22) and RDP (3389) to specific trusted IP CIDR ranges. Terraform: use aws_security_group with ingress rules that specify your corporate IP range instead of 0.0.0.0/0. CIS Level: Level 1. SOC2: CC6.6.`,
  },
  {
    id: "cis-5.3",
    control: "CIS 5.3",
    title: "Ensure the default security group of every VPC restricts all traffic",
    service: "EC2",
    section: "Networking",
    text: `CIS Control 5.3: Ensure the default security group of every VPC restricts all traffic. A VPC comes with a default security group whose initial settings deny all inbound traffic, allow all outbound traffic. Rationale: Configuring all VPC default security groups to restrict all traffic will encourage least privilege security group development and mindful placement of AWS resources into security groups which will in-turn reduce the exposure of those resources. Remediation: For each VPC, set the default security group to deny all inbound and outbound traffic. Use custom security groups for actual resource access requirements. CIS Level: Level 2.`,
  },

  // ── EC2 / EBS ──────────────────────────────────────────────────────────────

  {
    id: "cis-2.2.1",
    control: "CIS 2.2.1",
    title: "Ensure EBS volume encryption is enabled",
    service: "EC2",
    section: "Storage - EBS",
    text: `CIS Control 2.2.1: Ensure EBS volume encryption is enabled in all regions. Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. Rationale: Enabling encryption on EBS volumes protects data at rest inside the volume, data moving between the volume and the instance, snapshots created from the volume, and volumes created from those snapshots. Attack scenario: If an EBS snapshot is accidentally shared publicly or an AWS employee with physical access obtains underlying storage, unencrypted volumes expose all data in plaintext. Remediation: Enable EBS encryption by default in each region: aws ec2 enable-ebs-encryption-by-default --region <region>. For existing volumes, create an encrypted snapshot and restore. Terraform: use aws_ebs_encryption_by_default resource set to true. CIS Level: Level 2. SOC2: CC6.1.`,
  },

  // ── RDS ────────────────────────────────────────────────────────────────────

  {
    id: "cis-2.3.1",
    control: "CIS 2.3.1",
    title: "Ensure that encryption-at-rest is enabled for RDS instances",
    service: "RDS",
    section: "Storage - RDS",
    text: `CIS Control 2.3.1: Ensure that encryption-at-rest is enabled for RDS Instances. Amazon RDS encrypted DB instances use the industry standard AES-256 encryption algorithm to encrypt your data on the server that hosts your Amazon RDS DB instance. Rationale: Databases likely hold the most sensitive data in your infrastructure. Encrypting at rest ensures that even if the underlying storage is compromised, the data remains unreadable. Remediation: RDS encryption must be enabled at creation. Create a new encrypted instance and migrate data, or restore from an encrypted snapshot. Terraform: set storage_encrypted = true in aws_db_instance. CIS Level: Level 1.`,
  },
  {
    id: "cis-2.3.2",
    control: "CIS 2.3.2",
    title: "Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances",
    service: "RDS",
    section: "Storage - RDS",
    text: `CIS Control 2.3.2: Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances. Ensure that RDS database instances have the Auto Minor Version Upgrade flag enabled in order to automatically receive minor engine upgrades during the specified maintenance window. Rationale: AWS RDS will occasionally deprecate minor engine versions and provide new ones for an upgrade. When the last version number within the release is replaced, the version changed is considered minor. Minor upgrades often contain security patches. Remediation: Enable auto minor version upgrade: aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade. Terraform: set auto_minor_version_upgrade = true in aws_db_instance.`,
  },
  {
    id: "cis-2.3.3",
    control: "CIS 2.3.3",
    title: "Ensure that public access is not given to RDS instance",
    service: "RDS",
    section: "Storage - RDS",
    text: `CIS Control 2.3.3: Ensure that public access is not given to RDS Instance. Ensure and verify that RDS database instance is not publicly accessible to minimize security risk. Rationale: Ensure that RDS instances are not publicly accessible by checking the "Publicly Accessible" setting. A database instance that is publicly accessible allows connections from any IP address. Attack scenario: A publicly accessible RDS instance is exposed to internet-based brute force attacks, credential stuffing, and known CVE exploits against the database engine. Attackers regularly scan for open database ports (3306, 5432, 1433). Remediation: Modify RDS instance to disable public accessibility: aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible. Place RDS instances in private subnets. Terraform: set publicly_accessible = false in aws_db_instance. CIS Level: Level 1. SOC2: CC6.6.`,
  },

  // ── GUARDDUTY ──────────────────────────────────────────────────────────────

  {
    id: "cis-guardduty",
    control: "CIS 3.8 / AWS Best Practice",
    title: "Ensure GuardDuty is enabled",
    service: "GuardDuty",
    section: "Detection",
    text: `AWS Best Practice / CIS 3.8: Ensure Amazon GuardDuty is enabled. Amazon GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior to protect your AWS accounts and workloads. Rationale: GuardDuty analyzes billions of events across your AWS accounts from CloudTrail event logs, VPC Flow Logs, and DNS logs. Without it, there is no automated threat detection layer. Attack scenario: Without GuardDuty, reconnaissance activities like port scans, credential misuse, cryptocurrency mining, and data exfiltration go undetected. GuardDuty uses machine learning to identify anomalous patterns that rule-based tools miss. Remediation: Enable GuardDuty in all regions: aws guardduty create-detector --enable. Terraform: use aws_guardduty_detector with enable = true. Set up SNS notifications for findings. CIS Level: Level 2. SOC2: CC7.1.`,
  },
];

export default CIS_CONTROLS;
