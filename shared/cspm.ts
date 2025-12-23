import { z } from "zod";

export type CloudProvider = "aws" | "azure" | "gcp";
export type CSPMSeverity = "critical" | "high" | "medium" | "low" | "info";
export type CSPMCategory = 
  | "identity_access"
  | "network_security"
  | "data_protection"
  | "logging_monitoring"
  | "compute_security"
  | "storage_security"
  | "container_security"
  | "serverless_security"
  | "compliance";

export interface CloudCredentials {
  provider: CloudProvider;
  accessKeyId?: string;
  secretAccessKey?: string;
  region?: string;
  subscriptionId?: string;
  tenantId?: string;
  projectId?: string;
}

export interface CloudAsset {
  id: string;
  provider: CloudProvider;
  resourceType: string;
  resourceId: string;
  resourceName: string;
  region: string;
  tags?: Record<string, string>;
  configuration: Record<string, unknown>;
  discoveredAt: string;
}

export interface CSPMMisconfiguration {
  id: string;
  provider: CloudProvider;
  resourceType: string;
  resourceId: string;
  resourceName: string;
  region: string;
  title: string;
  description: string;
  severity: CSPMSeverity;
  category: CSPMCategory;
  complianceFrameworks: string[];
  remediation: string;
  remediationCode?: string;
  affectedConfiguration: string;
  expectedConfiguration: string;
  cweId?: string;
  benchmarkId?: string;
  confidenceScore: number;
}

export interface AWSMisconfigurationTemplate {
  checkId: string;
  title: string;
  description: string;
  severity: CSPMSeverity;
  category: CSPMCategory;
  resourceType: string;
  complianceFrameworks: string[];
  remediation: string;
  remediationCode?: string;
  cweId?: string;
  benchmarkId: string;
}

export const AWS_MISCONFIGURATIONS: AWSMisconfigurationTemplate[] = [
  {
    checkId: "AWS-IAM-001",
    title: "Root Account MFA Not Enabled",
    description: "The AWS root account does not have Multi-Factor Authentication (MFA) enabled, leaving it vulnerable to credential compromise.",
    severity: "critical",
    category: "identity_access",
    resourceType: "iam:root",
    complianceFrameworks: ["CIS AWS 1.5", "SOC2", "PCI-DSS", "NIST 800-53"],
    remediation: "Enable MFA on the root account using a hardware token or virtual MFA device.",
    remediationCode: `# Enable MFA for root account via AWS Console:
# 1. Sign in as root user
# 2. Navigate to Security Credentials
# 3. Click "Activate MFA" and follow the setup wizard`,
    cweId: "CWE-308",
    benchmarkId: "CIS-1.5",
  },
  {
    checkId: "AWS-IAM-002",
    title: "IAM User Without MFA",
    description: "IAM user account does not have MFA enabled, increasing the risk of unauthorized access.",
    severity: "high",
    category: "identity_access",
    resourceType: "iam:user",
    complianceFrameworks: ["CIS AWS 1.10", "SOC2", "NIST 800-53"],
    remediation: "Enable MFA for all IAM users, especially those with console access.",
    remediationCode: `aws iam enable-mfa-device \\
  --user-name <username> \\
  --serial-number <mfa-device-arn> \\
  --authentication-code1 <code1> \\
  --authentication-code2 <code2>`,
    cweId: "CWE-308",
    benchmarkId: "CIS-1.10",
  },
  {
    checkId: "AWS-IAM-003",
    title: "Overly Permissive IAM Policy",
    description: "IAM policy grants excessive permissions including 'Action': '*' or 'Resource': '*' which violates least privilege principle.",
    severity: "critical",
    category: "identity_access",
    resourceType: "iam:policy",
    complianceFrameworks: ["CIS AWS 1.16", "SOC2", "PCI-DSS", "HIPAA"],
    remediation: "Review and restrict IAM policies to specific actions and resources required for the role.",
    remediationCode: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::specific-bucket/*"
  }]
}`,
    cweId: "CWE-269",
    benchmarkId: "CIS-1.16",
  },
  {
    checkId: "AWS-S3-001",
    title: "S3 Bucket Public Access Enabled",
    description: "S3 bucket allows public access, potentially exposing sensitive data to the internet.",
    severity: "critical",
    category: "storage_security",
    resourceType: "s3:bucket",
    complianceFrameworks: ["CIS AWS 2.1.5", "SOC2", "PCI-DSS", "GDPR"],
    remediation: "Block public access using bucket policies and account-level public access settings.",
    remediationCode: `aws s3api put-public-access-block \\
  --bucket <bucket-name> \\
  --public-access-block-configuration \\
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"`,
    cweId: "CWE-732",
    benchmarkId: "CIS-2.1.5",
  },
  {
    checkId: "AWS-S3-002",
    title: "S3 Bucket Encryption Not Enabled",
    description: "S3 bucket does not have server-side encryption enabled, leaving data at rest unprotected.",
    severity: "high",
    category: "data_protection",
    resourceType: "s3:bucket",
    complianceFrameworks: ["CIS AWS 2.1.1", "SOC2", "PCI-DSS", "HIPAA"],
    remediation: "Enable default encryption using AWS KMS or AES-256.",
    remediationCode: `aws s3api put-bucket-encryption \\
  --bucket <bucket-name> \\
  --server-side-encryption-configuration \\
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"alias/aws/s3"}}]}'`,
    cweId: "CWE-311",
    benchmarkId: "CIS-2.1.1",
  },
  {
    checkId: "AWS-EC2-001",
    title: "Security Group Allows Unrestricted SSH Access",
    description: "Security group allows SSH (port 22) access from 0.0.0.0/0, exposing instances to brute-force attacks.",
    severity: "high",
    category: "network_security",
    resourceType: "ec2:security-group",
    complianceFrameworks: ["CIS AWS 5.2", "SOC2", "PCI-DSS"],
    remediation: "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager.",
    remediationCode: `aws ec2 revoke-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 22 \\
  --cidr 0.0.0.0/0`,
    cweId: "CWE-284",
    benchmarkId: "CIS-5.2",
  },
  {
    checkId: "AWS-EC2-002",
    title: "Security Group Allows Unrestricted RDP Access",
    description: "Security group allows RDP (port 3389) access from 0.0.0.0/0, exposing Windows instances to attacks.",
    severity: "high",
    category: "network_security",
    resourceType: "ec2:security-group",
    complianceFrameworks: ["CIS AWS 5.3", "SOC2", "PCI-DSS"],
    remediation: "Restrict RDP access to specific IP ranges or use VPN/bastion hosts.",
    remediationCode: `aws ec2 revoke-security-group-ingress \\
  --group-id <sg-id> \\
  --protocol tcp \\
  --port 3389 \\
  --cidr 0.0.0.0/0`,
    cweId: "CWE-284",
    benchmarkId: "CIS-5.3",
  },
  {
    checkId: "AWS-RDS-001",
    title: "RDS Instance Publicly Accessible",
    description: "RDS database instance is publicly accessible, exposing it to potential attacks from the internet.",
    severity: "critical",
    category: "data_protection",
    resourceType: "rds:instance",
    complianceFrameworks: ["CIS AWS 2.3.1", "SOC2", "PCI-DSS", "HIPAA"],
    remediation: "Disable public accessibility and use VPC security groups to control access.",
    remediationCode: `aws rds modify-db-instance \\
  --db-instance-identifier <instance-id> \\
  --no-publicly-accessible`,
    cweId: "CWE-284",
    benchmarkId: "CIS-2.3.1",
  },
  {
    checkId: "AWS-RDS-002",
    title: "RDS Encryption Not Enabled",
    description: "RDS database instance does not have encryption at rest enabled.",
    severity: "high",
    category: "data_protection",
    resourceType: "rds:instance",
    complianceFrameworks: ["CIS AWS 2.3.2", "SOC2", "PCI-DSS", "HIPAA"],
    remediation: "Enable encryption for new RDS instances. Existing instances require snapshot restore with encryption.",
    cweId: "CWE-311",
    benchmarkId: "CIS-2.3.2",
  },
  {
    checkId: "AWS-CT-001",
    title: "CloudTrail Not Enabled",
    description: "AWS CloudTrail is not enabled in all regions, limiting visibility into API activity.",
    severity: "high",
    category: "logging_monitoring",
    resourceType: "cloudtrail:trail",
    complianceFrameworks: ["CIS AWS 3.1", "SOC2", "PCI-DSS", "NIST 800-53"],
    remediation: "Enable CloudTrail with multi-region logging and log file validation.",
    remediationCode: `aws cloudtrail create-trail \\
  --name my-trail \\
  --s3-bucket-name my-bucket \\
  --is-multi-region-trail \\
  --enable-log-file-validation`,
    cweId: "CWE-778",
    benchmarkId: "CIS-3.1",
  },
  {
    checkId: "AWS-LAMBDA-001",
    title: "Lambda Function with Overly Permissive Execution Role",
    description: "Lambda function has an execution role with excessive permissions that could be exploited.",
    severity: "high",
    category: "serverless_security",
    resourceType: "lambda:function",
    complianceFrameworks: ["AWS Well-Architected", "SOC2"],
    remediation: "Apply least privilege principle to Lambda execution roles.",
    cweId: "CWE-269",
    benchmarkId: "WAF-SEC-3",
  },
  {
    checkId: "AWS-EKS-001",
    title: "EKS Cluster Endpoint Publicly Accessible",
    description: "EKS cluster API server endpoint is accessible from the public internet.",
    severity: "high",
    category: "container_security",
    resourceType: "eks:cluster",
    complianceFrameworks: ["CIS EKS 5.4.1", "SOC2"],
    remediation: "Restrict cluster endpoint access to private VPC or specific CIDR ranges.",
    remediationCode: `aws eks update-cluster-config \\
  --name <cluster-name> \\
  --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true`,
    cweId: "CWE-284",
    benchmarkId: "CIS-EKS-5.4.1",
  },
];

export interface AzureMisconfigurationTemplate {
  checkId: string;
  title: string;
  description: string;
  severity: CSPMSeverity;
  category: CSPMCategory;
  resourceType: string;
  complianceFrameworks: string[];
  remediation: string;
  remediationCode?: string;
  cweId?: string;
  benchmarkId: string;
}

export const AZURE_MISCONFIGURATIONS: AzureMisconfigurationTemplate[] = [
  {
    checkId: "AZURE-IAM-001",
    title: "Azure AD MFA Not Enforced",
    description: "Multi-Factor Authentication is not enforced for all Azure AD users.",
    severity: "critical",
    category: "identity_access",
    resourceType: "aad:user",
    complianceFrameworks: ["CIS Azure 1.1.1", "SOC2", "NIST 800-53"],
    remediation: "Enable Azure AD Conditional Access policies to require MFA.",
    benchmarkId: "CIS-Azure-1.1.1",
    cweId: "CWE-308",
  },
  {
    checkId: "AZURE-STORAGE-001",
    title: "Storage Account Allows Blob Public Access",
    description: "Azure Storage account is configured to allow anonymous public read access to blobs.",
    severity: "critical",
    category: "storage_security",
    resourceType: "storage:account",
    complianceFrameworks: ["CIS Azure 3.5", "SOC2", "GDPR"],
    remediation: "Disable blob public access at the storage account level.",
    remediationCode: `az storage account update \\
  --name <storage-account> \\
  --resource-group <resource-group> \\
  --allow-blob-public-access false`,
    cweId: "CWE-732",
    benchmarkId: "CIS-Azure-3.5",
  },
  {
    checkId: "AZURE-NSG-001",
    title: "NSG Allows Unrestricted SSH Access",
    description: "Network Security Group allows SSH access from any source IP address.",
    severity: "high",
    category: "network_security",
    resourceType: "network:nsg",
    complianceFrameworks: ["CIS Azure 6.1", "SOC2", "PCI-DSS"],
    remediation: "Restrict SSH access to specific IP ranges using NSG rules.",
    cweId: "CWE-284",
    benchmarkId: "CIS-Azure-6.1",
  },
  {
    checkId: "AZURE-SQL-001",
    title: "Azure SQL Server Firewall Allows All Azure IPs",
    description: "SQL Server firewall rule allows connections from all Azure services (0.0.0.0).",
    severity: "medium",
    category: "data_protection",
    resourceType: "sql:server",
    complianceFrameworks: ["CIS Azure 4.1.2", "SOC2"],
    remediation: "Remove the 'Allow Azure Services' rule and use specific virtual network rules.",
    remediationCode: `az sql server firewall-rule delete \\
  --resource-group <rg> \\
  --server <server> \\
  --name AllowAllWindowsAzureIps`,
    cweId: "CWE-284",
    benchmarkId: "CIS-Azure-4.1.2",
  },
  {
    checkId: "AZURE-KV-001",
    title: "Key Vault Soft Delete Not Enabled",
    description: "Azure Key Vault does not have soft delete enabled, risking permanent key loss.",
    severity: "medium",
    category: "data_protection",
    resourceType: "keyvault:vault",
    complianceFrameworks: ["CIS Azure 8.4", "SOC2"],
    remediation: "Enable soft delete for Key Vault to protect against accidental deletion.",
    cweId: "CWE-404",
    benchmarkId: "CIS-Azure-8.4",
  },
  {
    checkId: "AZURE-AKS-001",
    title: "AKS Cluster Without Azure AD Integration",
    description: "AKS cluster is not integrated with Azure AD for RBAC authentication.",
    severity: "high",
    category: "container_security",
    resourceType: "aks:cluster",
    complianceFrameworks: ["CIS AKS 5.1.1", "SOC2"],
    remediation: "Enable Azure AD integration for AKS cluster authentication.",
    cweId: "CWE-287",
    benchmarkId: "CIS-AKS-5.1.1",
  },
];

export interface GCPMisconfigurationTemplate {
  checkId: string;
  title: string;
  description: string;
  severity: CSPMSeverity;
  category: CSPMCategory;
  resourceType: string;
  complianceFrameworks: string[];
  remediation: string;
  remediationCode?: string;
  cweId?: string;
  benchmarkId: string;
}

export const GCP_MISCONFIGURATIONS: GCPMisconfigurationTemplate[] = [
  {
    checkId: "GCP-IAM-001",
    title: "Service Account with Owner Role",
    description: "Service account has been granted the Owner role, violating least privilege.",
    severity: "critical",
    category: "identity_access",
    resourceType: "iam:service-account",
    complianceFrameworks: ["CIS GCP 1.5", "SOC2", "NIST 800-53"],
    remediation: "Replace Owner role with specific roles needed for the service account's function.",
    remediationCode: `gcloud projects remove-iam-policy-binding <project-id> \\
  --member="serviceAccount:<sa-email>" \\
  --role="roles/owner"`,
    cweId: "CWE-269",
    benchmarkId: "CIS-GCP-1.5",
  },
  {
    checkId: "GCP-GCS-001",
    title: "Cloud Storage Bucket Publicly Accessible",
    description: "Cloud Storage bucket grants access to 'allUsers' or 'allAuthenticatedUsers'.",
    severity: "critical",
    category: "storage_security",
    resourceType: "storage:bucket",
    complianceFrameworks: ["CIS GCP 5.1", "SOC2", "GDPR"],
    remediation: "Remove public access and use IAM policies for controlled access.",
    remediationCode: `gsutil iam ch -d allUsers gs://<bucket-name>
gsutil iam ch -d allAuthenticatedUsers gs://<bucket-name>`,
    cweId: "CWE-732",
    benchmarkId: "CIS-GCP-5.1",
  },
  {
    checkId: "GCP-FW-001",
    title: "Firewall Rule Allows SSH from 0.0.0.0/0",
    description: "VPC firewall rule allows SSH access from any IP address on the internet.",
    severity: "high",
    category: "network_security",
    resourceType: "compute:firewall",
    complianceFrameworks: ["CIS GCP 3.6", "SOC2", "PCI-DSS"],
    remediation: "Restrict SSH access to specific source IP ranges or use IAP for SSH.",
    remediationCode: `gcloud compute firewall-rules update <rule-name> \\
  --source-ranges=<trusted-ip-range>`,
    cweId: "CWE-284",
    benchmarkId: "CIS-GCP-3.6",
  },
  {
    checkId: "GCP-SQL-001",
    title: "Cloud SQL Instance Allows Public IP",
    description: "Cloud SQL instance has a public IP address, making it accessible from the internet.",
    severity: "high",
    category: "data_protection",
    resourceType: "sql:instance",
    complianceFrameworks: ["CIS GCP 6.5", "SOC2", "HIPAA"],
    remediation: "Use private IP only and configure Cloud SQL Auth Proxy for connections.",
    remediationCode: `gcloud sql instances patch <instance-name> \\
  --no-assign-ip`,
    cweId: "CWE-284",
    benchmarkId: "CIS-GCP-6.5",
  },
  {
    checkId: "GCP-LOG-001",
    title: "Audit Logs Not Enabled for All Services",
    description: "Cloud Audit Logs are not enabled for all services, limiting visibility.",
    severity: "high",
    category: "logging_monitoring",
    resourceType: "logging:config",
    complianceFrameworks: ["CIS GCP 2.1", "SOC2", "PCI-DSS"],
    remediation: "Enable Data Access audit logs for all services.",
    cweId: "CWE-778",
    benchmarkId: "CIS-GCP-2.1",
  },
  {
    checkId: "GCP-GKE-001",
    title: "GKE Cluster Without Network Policy",
    description: "GKE cluster does not have network policies enabled for pod-to-pod traffic control.",
    severity: "medium",
    category: "container_security",
    resourceType: "gke:cluster",
    complianceFrameworks: ["CIS GKE 6.6.2", "SOC2"],
    remediation: "Enable network policy enforcement on the GKE cluster.",
    remediationCode: `gcloud container clusters update <cluster-name> \\
  --enable-network-policy`,
    cweId: "CWE-284",
    benchmarkId: "CIS-GKE-6.6.2",
  },
];

export interface CSPMScanRequest {
  projectId: string;
  provider: CloudProvider;
  regions?: string[];
  categories?: CSPMCategory[];
  includeRemediation?: boolean;
}

export const insertCSPMScanSchema = z.object({
  projectId: z.string().min(1, "Project ID is required"),
  provider: z.enum(["aws", "azure", "gcp"]),
  regions: z.array(z.string()).optional(),
  categories: z.array(z.enum([
    "identity_access",
    "network_security",
    "data_protection",
    "logging_monitoring",
    "compute_security",
    "storage_security",
    "container_security",
    "serverless_security",
    "compliance",
  ])).optional(),
  includeRemediation: z.boolean().optional().default(true),
});

export interface CSPMScanResult {
  id: string;
  projectId: string;
  provider: CloudProvider;
  status: "running" | "completed" | "failed";
  startedAt: string;
  completedAt?: string;
  assetsScanned: number;
  misconfigurations: CSPMMisconfiguration[];
  summary: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    complianceScore: number;
    categoryCounts: Record<CSPMCategory, number>;
  };
  creditsDeducted: number;
  error?: string;
}

export const CSPM_COSTS = {
  BASIC: { baseCost: 200, perAssetCost: 2 },
  STANDARD: { baseCost: 500, perAssetCost: 5 },
  ELITE: { baseCost: 1000, perAssetCost: 10 },
};
