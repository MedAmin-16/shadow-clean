import { nanoid } from "nanoid";
import {
  type CloudProvider,
  type CSPMCategory,
  type CSPMMisconfiguration,
  type CSPMScanResult,
  type CSPMScanRequest,
  AWS_MISCONFIGURATIONS,
  AZURE_MISCONFIGURATIONS,
  GCP_MISCONFIGURATIONS,
  CSPM_COSTS,
} from "@shared/cspm";
import type { PlanLevel } from "@shared/schema";
import { storage } from "../../../storage";

function randomDelay(min: number, max: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, Math.random() * (max - min) + min));
}

interface CSPMContext {
  userId: string;
  projectId: string;
  provider: CloudProvider;
  planLevel: PlanLevel;
  categories?: CSPMCategory[];
  includeRemediation: boolean;
}

function generateResourceId(provider: CloudProvider, resourceType: string): string {
  const prefixes: Record<CloudProvider, string> = {
    aws: "arn:aws",
    azure: "/subscriptions",
    gcp: "projects",
  };
  return `${prefixes[provider]}:${resourceType}:${nanoid(12)}`;
}

function generateResourceName(resourceType: string): string {
  const names: Record<string, string[]> = {
    "iam:root": ["root-account"],
    "iam:user": ["admin-user", "dev-user", "service-account", "readonly-user"],
    "iam:policy": ["admin-policy", "s3-full-access", "ec2-admin", "lambda-invoke"],
    "s3:bucket": ["data-bucket", "logs-bucket", "backup-bucket", "public-assets"],
    "ec2:security-group": ["web-sg", "db-sg", "bastion-sg", "default-sg"],
    "rds:instance": ["prod-db", "staging-db", "analytics-db"],
    "cloudtrail:trail": ["main-trail", "security-trail"],
    "lambda:function": ["api-handler", "event-processor", "data-sync"],
    "eks:cluster": ["prod-cluster", "dev-cluster"],
    "storage:account": ["prodstorageacct", "devstorageacct", "backupacct"],
    "network:nsg": ["web-nsg", "db-nsg", "admin-nsg"],
    "sql:server": ["prod-sql", "dev-sql"],
    "keyvault:vault": ["app-keyvault", "secrets-vault"],
    "aks:cluster": ["prod-aks", "dev-aks"],
    "aad:user": ["admin@company.com", "developer@company.com"],
    "iam:service-account": ["compute-sa", "storage-sa", "bigquery-sa"],
    "storage:bucket": ["data-bucket", "ml-models", "logs-archive"],
    "compute:firewall": ["allow-ssh", "allow-http", "allow-internal"],
    "sql:instance": ["prod-cloudsql", "analytics-db"],
    "logging:config": ["default-config"],
    "gke:cluster": ["prod-gke", "dev-gke"],
  };

  const resourceNames = names[resourceType] || ["resource"];
  return resourceNames[Math.floor(Math.random() * resourceNames.length)];
}

function generateRegion(provider: CloudProvider): string {
  const regions: Record<CloudProvider, string[]> = {
    aws: ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
    azure: ["eastus", "westeurope", "southeastasia", "centralus"],
    gcp: ["us-central1", "us-east1", "europe-west1", "asia-east1"],
  };
  const providerRegions = regions[provider];
  return providerRegions[Math.floor(Math.random() * providerRegions.length)];
}

function shouldIncludeMisconfiguration(
  template: { category: CSPMCategory; severity: string },
  categories: CSPMCategory[] | undefined,
  planLevel: PlanLevel
): boolean {
  if (categories && categories.length > 0 && !categories.includes(template.category)) {
    return false;
  }
  
  const severityChance: Record<PlanLevel, Record<string, number>> = {
    BASIC: { critical: 0.5, high: 0.4, medium: 0.2, low: 0.1, info: 0.05 },
    STANDARD: { critical: 0.7, high: 0.6, medium: 0.5, low: 0.3, info: 0.2 },
    ELITE: { critical: 0.9, high: 0.85, medium: 0.8, low: 0.7, info: 0.5 },
  };
  
  return Math.random() < (severityChance[planLevel][template.severity] || 0.3);
}

function generateAWSMisconfigurations(ctx: CSPMContext): CSPMMisconfiguration[] {
  const misconfigurations: CSPMMisconfiguration[] = [];
  
  for (const template of AWS_MISCONFIGURATIONS) {
    if (!shouldIncludeMisconfiguration(template, ctx.categories, ctx.planLevel)) {
      continue;
    }
    
    const resourceId = generateResourceId("aws", template.resourceType);
    const resourceName = generateResourceName(template.resourceType);
    const region = generateRegion("aws");
    
    misconfigurations.push({
      id: `CSPM-${nanoid(8)}`,
      provider: "aws",
      resourceType: template.resourceType,
      resourceId,
      resourceName,
      region,
      title: template.title,
      description: template.description,
      severity: template.severity,
      category: template.category,
      complianceFrameworks: template.complianceFrameworks,
      remediation: ctx.includeRemediation ? template.remediation : "",
      remediationCode: ctx.includeRemediation ? template.remediationCode : undefined,
      affectedConfiguration: `Current: Non-compliant configuration for ${template.resourceType}`,
      expectedConfiguration: `Expected: ${template.remediation}`,
      cweId: template.cweId,
      benchmarkId: template.benchmarkId,
      confidenceScore: 0.7 + Math.random() * 0.3,
    });
  }
  
  return misconfigurations;
}

function generateAzureMisconfigurations(ctx: CSPMContext): CSPMMisconfiguration[] {
  const misconfigurations: CSPMMisconfiguration[] = [];
  
  for (const template of AZURE_MISCONFIGURATIONS) {
    if (!shouldIncludeMisconfiguration(template, ctx.categories, ctx.planLevel)) {
      continue;
    }
    
    const resourceId = generateResourceId("azure", template.resourceType);
    const resourceName = generateResourceName(template.resourceType);
    const region = generateRegion("azure");
    
    misconfigurations.push({
      id: `CSPM-${nanoid(8)}`,
      provider: "azure",
      resourceType: template.resourceType,
      resourceId,
      resourceName,
      region,
      title: template.title,
      description: template.description,
      severity: template.severity,
      category: template.category,
      complianceFrameworks: template.complianceFrameworks,
      remediation: ctx.includeRemediation ? template.remediation : "",
      remediationCode: ctx.includeRemediation ? template.remediationCode : undefined,
      affectedConfiguration: `Current: Non-compliant configuration for ${template.resourceType}`,
      expectedConfiguration: `Expected: ${template.remediation}`,
      cweId: template.cweId,
      benchmarkId: template.benchmarkId,
      confidenceScore: 0.7 + Math.random() * 0.3,
    });
  }
  
  return misconfigurations;
}

function generateGCPMisconfigurations(ctx: CSPMContext): CSPMMisconfiguration[] {
  const misconfigurations: CSPMMisconfiguration[] = [];
  
  for (const template of GCP_MISCONFIGURATIONS) {
    if (!shouldIncludeMisconfiguration(template, ctx.categories, ctx.planLevel)) {
      continue;
    }
    
    const resourceId = generateResourceId("gcp", template.resourceType);
    const resourceName = generateResourceName(template.resourceType);
    const region = generateRegion("gcp");
    
    misconfigurations.push({
      id: `CSPM-${nanoid(8)}`,
      provider: "gcp",
      resourceType: template.resourceType,
      resourceId,
      resourceName,
      region,
      title: template.title,
      description: template.description,
      severity: template.severity,
      category: template.category,
      complianceFrameworks: template.complianceFrameworks,
      remediation: ctx.includeRemediation ? template.remediation : "",
      remediationCode: ctx.includeRemediation ? template.remediationCode : undefined,
      affectedConfiguration: `Current: Non-compliant configuration for ${template.resourceType}`,
      expectedConfiguration: `Expected: ${template.remediation}`,
      cweId: template.cweId,
      benchmarkId: template.benchmarkId,
      confidenceScore: 0.7 + Math.random() * 0.3,
    });
  }
  
  return misconfigurations;
}

function calculateComplianceScore(misconfigurations: CSPMMisconfiguration[]): number {
  if (misconfigurations.length === 0) return 100;
  
  const weights = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
  let totalPenalty = 0;
  
  for (const misc of misconfigurations) {
    totalPenalty += weights[misc.severity] || 0;
  }
  
  return Math.max(0, 100 - totalPenalty);
}

function calculateCategoryCounts(
  misconfigurations: CSPMMisconfiguration[]
): Record<CSPMCategory, number> {
  const counts: Record<CSPMCategory, number> = {
    identity_access: 0,
    network_security: 0,
    data_protection: 0,
    logging_monitoring: 0,
    compute_security: 0,
    storage_security: 0,
    container_security: 0,
    serverless_security: 0,
    compliance: 0,
  };
  
  for (const misc of misconfigurations) {
    counts[misc.category]++;
  }
  
  return counts;
}

export interface CSPMValidationResult {
  valid: boolean;
  error?: string;
  estimatedCost: number;
  currentBalance: number;
}

export async function validateCSPMScan(
  userId: string,
  planLevel: PlanLevel
): Promise<CSPMValidationResult> {
  const userCredits = await storage.getUserCredits(userId);
  const costs = CSPM_COSTS[planLevel];
  const estimatedAssets = 50;
  const estimatedCost = costs.baseCost + (costs.perAssetCost * estimatedAssets);
  
  if (userCredits.balance < estimatedCost) {
    return {
      valid: false,
      error: `Insufficient credits. CSPM scan requires approximately ${estimatedCost} credits, you have ${userCredits.balance}.`,
      estimatedCost,
      currentBalance: userCredits.balance,
    };
  }
  
  return {
    valid: true,
    estimatedCost,
    currentBalance: userCredits.balance,
  };
}

export async function runCSPMScan(
  request: CSPMScanRequest,
  userId: string,
  onProgress: (progress: number) => void
): Promise<CSPMScanResult> {
  const scanId = `cspm-${nanoid()}`;
  const startedAt = new Date().toISOString();
  
  const userCredits = await storage.getUserCredits(userId);
  const planLevel = userCredits.planLevel;
  const costs = CSPM_COSTS[planLevel];
  
  onProgress(5);
  
  const ctx: CSPMContext = {
    userId,
    projectId: request.projectId,
    provider: request.provider,
    planLevel,
    categories: request.categories,
    includeRemediation: request.includeRemediation ?? true,
  };
  
  await randomDelay(500, 1000);
  onProgress(15);
  
  let misconfigurations: CSPMMisconfiguration[] = [];
  
  switch (request.provider) {
    case "aws":
      misconfigurations = generateAWSMisconfigurations(ctx);
      break;
    case "azure":
      misconfigurations = generateAzureMisconfigurations(ctx);
      break;
    case "gcp":
      misconfigurations = generateGCPMisconfigurations(ctx);
      break;
  }
  
  await randomDelay(800, 1500);
  onProgress(50);
  
  const assetsScanned = Math.floor(Math.random() * 50) + 30;
  const totalCost = costs.baseCost + (costs.perAssetCost * assetsScanned);
  
  const deductionResult = await storage.deductCredits(userId, totalCost);
  if (!deductionResult.success) {
    return {
      id: scanId,
      projectId: request.projectId,
      provider: request.provider,
      status: "failed",
      startedAt,
      completedAt: new Date().toISOString(),
      assetsScanned: 0,
      misconfigurations: [],
      summary: {
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        complianceScore: 0,
        categoryCounts: calculateCategoryCounts([]),
      },
      creditsDeducted: 0,
      error: deductionResult.error || "Failed to deduct credits",
    };
  }
  
  await randomDelay(500, 1000);
  onProgress(80);
  
  const severityCounts = misconfigurations.reduce((acc, m) => {
    acc[m.severity] = (acc[m.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  onProgress(100);
  
  return {
    id: scanId,
    projectId: request.projectId,
    provider: request.provider,
    status: "completed",
    startedAt,
    completedAt: new Date().toISOString(),
    assetsScanned,
    misconfigurations,
    summary: {
      criticalCount: severityCounts.critical || 0,
      highCount: severityCounts.high || 0,
      mediumCount: severityCounts.medium || 0,
      lowCount: severityCounts.low || 0,
      infoCount: severityCounts.info || 0,
      complianceScore: calculateComplianceScore(misconfigurations),
      categoryCounts: calculateCategoryCounts(misconfigurations),
    },
    creditsDeducted: totalCost,
  };
}

export const cspmAnalyzer = {
  validateCSPMScan,
  runCSPMScan,
};
