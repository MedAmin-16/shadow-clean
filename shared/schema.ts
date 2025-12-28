import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, jsonb, serial, decimal, boolean, foreignKey, index, uniqueIndex } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// =====================================================
// TABLE 1: USERS - Core authentication and user profile
// =====================================================

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email", { length: 255 }).notNull().unique(),
  username: varchar("username", { length: 100 }).notNull().unique(),
  password_hash: varchar("password_hash", { length: 255 }).notNull(),
  full_name: varchar("full_name", { length: 255 }),
  avatar_url: text("avatar_url"),
  plan: varchar("plan", { length: 50 }).default("STANDARD"),
  status: varchar("status", { length: 50 }).default("active"),
  email_verified: boolean("email_verified").default(false),
  two_factor_enabled: boolean("two_factor_enabled").default(false),
  created_at: timestamp("created_at").notNull().defaultNow(),
  updated_at: timestamp("updated_at").notNull().defaultNow(),
  last_login: timestamp("last_login"),
}, (table) => ({
  emailIdx: index("users_email_idx").on(table.email),
}));

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password_hash: true,
  email: true,
}).extend({
  // Make full_name optional
  full_name: z.string().optional(),
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

// =====================================================
// TABLE 2: USER_CREDITS - Credit balance management
// =====================================================

export const userCreditsTable = pgTable("user_credits", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull().unique(),
  balance: integer("balance").notNull().default(1000),
  planLevel: varchar("plan_level", { length: 20 }).notNull().default("STANDARD"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("user_credits_user_id_idx").on(table.userId),
}));

export type DbUserCredits = typeof userCreditsTable.$inferSelect;

// =====================================================
// TABLE 3: USER_INTEGRATIONS - Third-party integrations
// =====================================================

export const userIntegrationsTable = pgTable("user_integrations", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  integrationType: varchar("integration_type", { length: 50 }).notNull(),
  integrationName: varchar("integration_name", { length: 100 }).notNull(),
  apiKey: text("api_key"),
  webhookUrl: text("webhook_url"),
  isActive: boolean("is_active").default(true),
  config: jsonb("config"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("user_integrations_user_id_idx").on(table.userId),
}));

export type UserIntegration = typeof userIntegrationsTable.$inferSelect;

// =====================================================
// TABLE 4: SCANS - Main scanning engine results
// =====================================================

export const scansTable = pgTable("scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  target: text("target").notNull(),
  userId: varchar("user_id").notNull(),
  status: varchar("status", { length: 20 }).notNull().default("pending"),
  currentAgent: varchar("current_agent", { length: 50 }),
  progress: integer("progress").notNull().default(0),
  startedAt: timestamp("started_at").notNull().defaultNow(),
  completedAt: timestamp("completed_at"),
  error: text("error"),
  scanType: varchar("scan_type", { length: 50 }).default("standard"),
  agentResults: jsonb("agent_results"),
}, (table) => ({
  userIdIdx: index("scans_user_id_idx").on(table.userId),
  statusIdx: index("scans_status_idx").on(table.status),
}));

export type DbScan = typeof scansTable.$inferSelect;

// =====================================================
// TABLE 5: SCAN_SANDBOXES - Isolated sandbox environments
// =====================================================

export const scanSandboxesTable = pgTable("scan_sandboxes", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").notNull(),
  userId: varchar("user_id").notNull(),
  sandboxType: varchar("sandbox_type", { length: 50 }).notNull(),
  sandboxUrl: text("sandbox_url"),
  isActive: boolean("is_active").default(true),
  isolationLevel: varchar("isolation_level", { length: 20 }).default("full"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  destroyedAt: timestamp("destroyed_at"),
}, (table) => ({
  scanIdIdx: index("scan_sandboxes_scan_id_idx").on(table.scanId),
  userIdIdx: index("scan_sandboxes_user_id_idx").on(table.userId),
}));

export type ScanSandbox = typeof scanSandboxesTable.$inferSelect;

// =====================================================
// TABLE 6: MONITORING_SCHEDULES - Continuous monitoring
// =====================================================

export const monitoringSchedulesTable = pgTable("monitoring_schedules", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  target: text("target").notNull(),
  frequency: varchar("frequency", { length: 20 }).notNull(),
  nextScanAt: timestamp("next_scan_at"),
  lastScanAt: timestamp("last_scan_at"),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("monitoring_schedules_user_id_idx").on(table.userId),
  isActiveIdx: index("monitoring_schedules_is_active_idx").on(table.isActive),
}));

export type MonitoringSchedule = typeof monitoringSchedulesTable.$inferSelect;

// =====================================================
// TABLE 7: SHADOWLOGIC_SCANS - ShadowLogic business logic scanning
// =====================================================

export const shadowlogicScansTable = pgTable("shadowlogic_scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").notNull(),
  userId: varchar("user_id").notNull(),
  target: text("target").notNull(),
  analysisType: varchar("analysis_type", { length: 50 }).notNull(),
  status: varchar("status", { length: 20 }).default("pending"),
  findingCount: integer("finding_count").default(0),
  startedAt: timestamp("started_at").notNull().defaultNow(),
  completedAt: timestamp("completed_at"),
  metadata: jsonb("metadata"),
}, (table) => ({
  scanIdIdx: index("shadowlogic_scans_scan_id_idx").on(table.scanId),
  userIdIdx: index("shadowlogic_scans_user_id_idx").on(table.userId),
}));

export type ShadowLogicScan = typeof shadowlogicScansTable.$inferSelect;

// =====================================================
// TABLE 8: SHADOWLOGIC_VULNERABILITIES - Business logic flaws with proper FK
// =====================================================

export const shadowlogicVulnerabilitiesTable = pgTable("shadowlogic_vulnerabilities", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").notNull(),
  userId: varchar("user_id").notNull(),
  shadowlogicScanId: varchar("shadowlogic_scan_id"),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description").notNull(),
  severity: varchar("severity", { length: 20 }).notNull(),
  confidence: integer("confidence").default(0),
  businessImpact: text("business_impact"),
  proof: text("proof"),
  remediation: text("remediation"),
  detectedAt: timestamp("detected_at").notNull().defaultNow(),
}, (table) => ({
  scanIdIdx: index("shadowlogic_vulnerabilities_scan_id_idx").on(table.scanId),
  userIdIdx: index("shadowlogic_vulnerabilities_user_id_idx").on(table.userId),
}));

export type ShadowLogicVulnerability = typeof shadowlogicVulnerabilitiesTable.$inferSelect;

// =====================================================
// TABLE 9: SHADOWLOGIC_DISCOVERIES - Findings and discoveries
// =====================================================

export const shadowlogicDiscoveriesTable = pgTable("shadowlogic_discoveries", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  shadowlogicScanId: varchar("shadowlogic_scan_id").notNull(),
  vulnerabilityId: varchar("vulnerability_id"),
  discoveryType: varchar("discovery_type", { length: 50 }).notNull(),
  details: jsonb("details").notNull(),
  evidence: text("evidence"),
  confidence: integer("confidence").default(0),
  discoveredAt: timestamp("discovered_at").notNull().defaultNow(),
}, (table) => ({
  scanIdIdx: index("shadowlogic_discoveries_shadowlogic_scan_id_idx").on(table.shadowlogicScanId),
}));

export type ShadowLogicDiscovery = typeof shadowlogicDiscoveriesTable.$inferSelect;

// =====================================================
// TABLE 10: PHISHING_CAMPAIGNS - Phishing simulation engine
// =====================================================

export const phishingCampaignsTable = pgTable("phishing_campaigns", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  campaignName: varchar("campaign_name", { length: 255 }).notNull(),
  description: text("description"),
  templateId: varchar("template_id", { length: 100 }),
  status: varchar("status", { length: 20 }).default("draft"),
  targetEmails: jsonb("target_emails"),
  launchedAt: timestamp("launched_at"),
  completedAt: timestamp("completed_at"),
  clickRate: decimal("click_rate", { precision: 5, scale: 2 }),
  reportingUrl: text("reporting_url"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("phishing_campaigns_user_id_idx").on(table.userId),
}));

export type PhishingCampaign = typeof phishingCampaignsTable.$inferSelect;

// =====================================================
// TABLE 11: CLOUD_SCAN_CONFIGS - Cloud infrastructure scanning
// =====================================================

export const cloudScanConfigsTable = pgTable("cloud_scan_configs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  configName: varchar("config_name", { length: 255 }).notNull(),
  cloudProvider: varchar("cloud_provider", { length: 50 }).notNull(),
  accountId: varchar("account_id", { length: 100 }),
  credentials: text("credentials"),
  regions: jsonb("regions"),
  isActive: boolean("is_active").default(true),
  lastScanAt: timestamp("last_scan_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("cloud_scan_configs_user_id_idx").on(table.userId),
}));

export type CloudScanConfig = typeof cloudScanConfigsTable.$inferSelect;

// =====================================================
// TABLE 12: THREAT_INTEL - Threat intelligence database
// =====================================================

export const threatIntelTable = pgTable("threat_intel", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  threatType: varchar("threat_type", { length: 50 }).notNull(),
  threatName: varchar("threat_name", { length: 255 }).notNull(),
  severity: varchar("severity", { length: 20 }).notNull(),
  cveId: varchar("cve_id", { length: 50 }),
  description: text("description"),
  indicators: jsonb("indicators"),
  affectedSystems: jsonb("affected_systems"),
  remediationSteps: jsonb("remediation_steps"),
  source: varchar("source", { length: 100 }),
  discoveredAt: timestamp("discovered_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => ({
  cveIdIdx: index("threat_intel_cve_id_idx").on(table.cveId),
  threatTypeIdx: index("threat_intel_threat_type_idx").on(table.threatType),
}));

export type ThreatIntel = typeof threatIntelTable.$inferSelect;

// =====================================================
// TABLE 13: COMPLIANCE_REPORTS - Compliance and regulatory reporting
// =====================================================

export const complianceReportsTable = pgTable("compliance_reports", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  scanId: varchar("scan_id"),
  reportType: varchar("report_type", { length: 50 }).notNull(),
  complianceStandard: varchar("compliance_standard", { length: 100 }).notNull(),
  status: varchar("status", { length: 20 }).default("pending"),
  score: decimal("score", { precision: 5, scale: 2 }),
  findings: jsonb("findings"),
  recommendations: jsonb("recommendations"),
  fileUrl: text("file_url"),
  generatedAt: timestamp("generated_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("compliance_reports_user_id_idx").on(table.userId),
  standardIdx: index("compliance_reports_standard_idx").on(table.complianceStandard),
}));

export type ComplianceReport = typeof complianceReportsTable.$inferSelect;

// =====================================================
// TABLE 14: CREDIT_TRANSACTIONS - Audit trail for credits
// =====================================================

export const creditTransactionsTable = pgTable("credit_transactions", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  transactionType: varchar("transaction_type", { length: 50 }).notNull(),
  amount: integer("amount").notNull(),
  balanceBefore: integer("balance_before").notNull(),
  balanceAfter: integer("balance_after").notNull(),
  description: text("description"),
  metadata: jsonb("metadata"),
  agentType: varchar("agent_type", { length: 20 }),
  scanId: varchar("scan_id"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("credit_transactions_user_id_idx").on(table.userId),
}));

export const insertCreditTransactionSchema = createInsertSchema(creditTransactionsTable);
export type InsertCreditTransaction = z.infer<typeof insertCreditTransactionSchema>;
export type CreditTransaction = typeof creditTransactionsTable.$inferSelect;

// =====================================================
// ADDITIONAL TABLES FOR 20 TABLE REQUIREMENT
// TABLE 15: SCAN_REPORTS - Individual scan report storage
// =====================================================

export const scanReportsTable = pgTable("scan_reports", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").notNull(),
  userId: varchar("user_id").notNull(),
  reportType: varchar("report_type", { length: 50 }).notNull(),
  summary: text("summary"),
  vulnerabilityCount: integer("vulnerability_count").default(0),
  securityScore: integer("security_score"),
  exportUrl: text("export_url"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => ({
  scanIdIdx: index("scan_reports_scan_id_idx").on(table.scanId),
  userIdIdx: index("scan_reports_user_id_idx").on(table.userId),
}));

export type ScanReport = typeof scanReportsTable.$inferSelect;

// =====================================================
// TABLE 16: VULNERABILITIES - Centralized vulnerability storage
// =====================================================

export const vulnerabilitiesTable = pgTable("vulnerabilities", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").notNull(),
  userId: varchar("user_id").notNull(),
  title: varchar("title", { length: 255 }).notNull(),
  severity: varchar("severity", { length: 20 }).notNull(),
  category: varchar("category", { length: 100 }),
  cveId: varchar("cve_id", { length: 50 }),
  description: text("description"),
  proof: text("proof"),
  remediation: text("remediation"),
  affectedComponent: varchar("affected_component", { length: 255 }),
  discoveredAt: timestamp("discovered_at").notNull().defaultNow(),
  isArchived: boolean("is_archived").default(false), // Evidence Vault flag
  evidenceMetadata: jsonb("evidence_metadata"),
}, (table) => ({
  scanIdIdx: index("vulnerabilities_scan_id_idx").on(table.scanId),
  userIdIdx: index("vulnerabilities_user_id_idx").on(table.userId),
  cveIdIdx: index("vulnerabilities_cve_id_idx").on(table.cveId),
}));

export type Vulnerability = typeof vulnerabilitiesTable.$inferSelect;

// =====================================================
// TABLE 17: ASSETS - Asset inventory management
// =====================================================

export const assetsTable = pgTable("assets", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  assetName: varchar("asset_name", { length: 255 }).notNull(),
  assetType: varchar("asset_type", { length: 50 }).notNull(),
  ipAddress: varchar("ip_address", { length: 45 }),
  hostname: varchar("hostname", { length: 255 }),
  status: varchar("status", { length: 20 }).default("active"),
  lastScannedAt: timestamp("last_scanned_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("assets_user_id_idx").on(table.userId),
}));

export type Asset = typeof assetsTable.$inferSelect;

// =====================================================
// TABLE 18: REMEDIATION_TRACKING - Track vulnerability fixes
// =====================================================

export const remediationTrackingTable = pgTable("remediation_tracking", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  vulnerabilityId: varchar("vulnerability_id").notNull(),
  userId: varchar("user_id").notNull(),
  status: varchar("status", { length: 20 }).default("pending"),
  assignedTo: varchar("assigned_to", { length: 255 }),
  dueDate: timestamp("due_date"),
  completedAt: timestamp("completed_at"),
  verificationScanId: varchar("verification_scan_id"),
  notes: text("notes"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("remediation_tracking_user_id_idx").on(table.userId),
  statusIdx: index("remediation_tracking_status_idx").on(table.status),
}));

export type RemediationTracking = typeof remediationTrackingTable.$inferSelect;

// =====================================================
// TABLE 19: AUDIT_LOGS - System audit trail
// =====================================================

export const auditLogsTable = pgTable("audit_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id"),
  action: varchar("action", { length: 100 }).notNull(),
  resourceType: varchar("resource_type", { length: 50 }),
  resourceId: varchar("resource_id", { length: 255 }),
  details: jsonb("details"),
  ipAddress: varchar("ip_address", { length: 45 }),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("audit_logs_user_id_idx").on(table.userId),
  actionIdx: index("audit_logs_action_idx").on(table.action),
}));

export type AuditLog = typeof auditLogsTable.$inferSelect;

// =====================================================
// TABLE 20: ADMIN_SESSIONS - Admin authentication tracking
// =====================================================

export const adminSessionsTable = pgTable("admin_sessions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email", { length: 255 }).notNull(),
  sessionToken: varchar("session_token", { length: 255 }).notNull().unique(),
  ipAddress: varchar("ip_address", { length: 45 }),
  userAgent: text("user_agent"),
  isActive: boolean("is_active").default(true),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  lastActivityAt: timestamp("last_activity_at").notNull().defaultNow(),
}, (table) => ({
  emailIdx: index("admin_sessions_email_idx").on(table.email),
  tokenIdx: index("admin_sessions_token_idx").on(table.sessionToken),
}));

export type AdminSession = typeof adminSessionsTable.$inferSelect;

// =====================================================
// TYPE DEFINITIONS AND EXPORTS
// =====================================================

export type PlanLevel = "PRO" | "ELITE";

export interface PlanConfig {
  planLevel: PlanLevel;
  llmModel: string;
  creditCostPerTarget: number;
  osintAccess: "limited" | "standard" | "full";
  osintQueryCost: number;
}

export const PLAN_CONFIGS: Record<PlanLevel, PlanConfig> = {
  PRO: {
    planLevel: "PRO",
    llmModel: "gpt-4o",
    creditCostPerTarget: 500,
    osintAccess: "full",
    osintQueryCost: 2,
  },
  ELITE: {
    planLevel: "ELITE",
    llmModel: "gpt-4o",
    creditCostPerTarget: 1000,
    osintAccess: "full",
    osintQueryCost: 5,
  },
};

// Feature identifiers for plan-based access control
export type FeatureId = 
  | "basic_scans"
  | "cloud_security"
  | "visual_attack_path"
  | "weekly_monitoring"
  | "daily_monitoring"
  | "exploiter_agent"
  | "prophet_agent"
  | "ai_threat_intel"
  | "database_sandbox"
  | "ai_remediation"
  | "compliance_reports"
  | "phishing_simulation"
  | "rl_exploiter"
  | "autonomous_defense"
  | "shadow_logic"
  | "waf_automation";

export type GatedAgentId = "recon" | "scanner" | "exploiter" | "reporter" | "prophet" | "rl_exploiter" | "autonomous_defense" | "shadow_logic";

export interface PlanFeatureConfig {
  planLevel: PlanLevel;
  displayName: string;
  allowedAgents: GatedAgentId[];
  allowedFeatures: FeatureId[];
  monitoringFrequency: "none" | "weekly" | "daily";
  maxScansPerMonth: number;
  prioritySupport: boolean;
}

export const PLAN_FEATURE_CONFIGS: Record<PlanLevel, PlanFeatureConfig> = {
  PRO: {
    planLevel: "PRO",
    displayName: "Pro Plan (ULTIMATE - Merged with ELITE)",
    allowedAgents: ["recon", "scanner", "exploiter", "reporter", "rl_exploiter", "prophet", "autonomous_defense", "shadow_logic"],
    allowedFeatures: [
      "basic_scans",
      "cloud_security",
      "visual_attack_path",
      "weekly_monitoring",
      "daily_monitoring",
      "exploiter_agent",
      "prophet_agent",
      "ai_threat_intel",
      "database_sandbox",
      "ai_remediation",
      "compliance_reports",
      "phishing_simulation",
      "rl_exploiter",
      "autonomous_defense",
      "shadow_logic",
      "waf_automation",
    ],
    monitoringFrequency: "daily",
    maxScansPerMonth: -1,
    prioritySupport: true,
  },
  ELITE: {
    planLevel: "ELITE",
    displayName: "Elite Plan",
    allowedAgents: ["recon", "scanner", "exploiter", "reporter", "prophet", "rl_exploiter", "autonomous_defense", "shadow_logic"],
    allowedFeatures: [
      "basic_scans",
      "cloud_security",
      "visual_attack_path",
      "weekly_monitoring",
      "daily_monitoring",
      "exploiter_agent",
      "prophet_agent",
      "ai_threat_intel",
      "database_sandbox",
      "ai_remediation",
      "compliance_reports",
      "phishing_simulation",
      "rl_exploiter",
      "autonomous_defense",
      "shadow_logic",
      "waf_automation",
    ],
    monitoringFrequency: "daily",
    maxScansPerMonth: -1,
    prioritySupport: true,
  },
};

export function hasFeatureAccess(planLevel: PlanLevel, feature: FeatureId): boolean {
  return PLAN_FEATURE_CONFIGS[planLevel].allowedFeatures.includes(feature);
}

export function hasAgentAccess(planLevel: PlanLevel, agent: GatedAgentId): boolean {
  return PLAN_FEATURE_CONFIGS[planLevel].allowedAgents.includes(agent);
}

export function getRequiredPlanForFeature(feature: FeatureId): PlanLevel {
  const planOrder: PlanLevel[] = ["PRO", "ELITE"];
  for (const plan of planOrder) {
    if (PLAN_FEATURE_CONFIGS[plan].allowedFeatures.includes(feature)) {
      return plan;
    }
  }
  return "ELITE";
}

export function getRequiredPlanForAgent(agent: GatedAgentId): PlanLevel {
  const planOrder: PlanLevel[] = ["PRO", "ELITE"];
  for (const plan of planOrder) {
    if (PLAN_FEATURE_CONFIGS[plan].allowedAgents.includes(agent)) {
      return plan;
    }
  }
  return "ELITE";
}

export function getPlanHierarchy(planLevel: PlanLevel): number {
  const hierarchy: Record<PlanLevel, number> = {
    PRO: 1,
    ELITE: 2,
  };
  return hierarchy[planLevel];
}

export interface ScopeCostEstimate {
  targets: string[];
  targetCount: number;
  costPerTarget: number;
  totalCost: number;
  planLevel: PlanLevel;
  llmModel: string;
}

export function calculateScopeCost(targets: string[], planLevel: PlanLevel): ScopeCostEstimate {
  const planConfig = PLAN_CONFIGS[planLevel];
  const targetCount = targets.length;
  const totalCost = targetCount * planConfig.creditCostPerTarget;
  
  return {
    targets,
    targetCount,
    costPerTarget: planConfig.creditCostPerTarget,
    totalCost,
    planLevel,
    llmModel: planConfig.llmModel,
  };
}

export interface UserCredits {
  userId: string;
  balance: number;
  planLevel: PlanLevel;
  lastUpdated: string;
}

export type AgentType = "recon" | "scanner" | "exploiter" | "reporter" | "rl_exploiter" | "prophet" | "autonomous_defense";
export type AgentStatus = "pending" | "running" | "complete" | "failed";
export type ScanStatus = "pending" | "running" | "complete" | "failed";

export interface AgentResult {
  agentType: AgentType | string;
  status: AgentStatus;
  startedAt?: string;
  completedAt?: string;
  error?: string;
  data: unknown;
}

export interface ReconFindings {
  ip?: string;
  hostname?: string;
  ports?: number[];
  services?: { port: number; service: string; version?: string }[];
  technologies?: string[];
  subdomains?: string[];
  credit_deduction_recon: number;
  strategic_decision_log: string;
  llm_model_used: string;
  plan_level: PlanLevel;
  osint_queries_made: number;
  remaining_credits: number;
}

export interface ScannerFindings {
  vulnerabilities: {
    id: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    description: string;
    port?: number;
    service?: string;
    cve?: string;
  }[];
  openPorts: number[];
  sslIssues?: string[];
}

export interface ExploiterFindings {
  exploitAttempts: {
    vulnerability: string;
    success: boolean;
    technique: string;
    evidence?: string;
  }[];
  accessGained: boolean;
  riskLevel: "critical" | "high" | "medium" | "low";
}

export type ReportAudience = "executive" | "cfo" | "cto" | "development" | "compliance";

export interface FinancialRiskAssessment {
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  severity: "critical" | "high" | "medium" | "low";
  estimatedLossMin: number;
  estimatedLossMax: number;
  estimatedLossRange: string;
  downtimeProbability: number;
  assetValue: number;
  annualizedRiskExposure: number;
  riskCategory: "data_breach" | "service_disruption" | "regulatory_fine" | "reputation_damage" | "ransomware";
  businessImpactDescription: string;
}

export interface IndustryBenchmark {
  industryName: string;
  averageSecurityScore: number;
  companyPercentile: number;
  medianVulnerabilityCount: number;
  topPerformerScore: number;
  averageTimeToRemediate: string;
  complianceStandards: string[];
  commonWeaknesses: string[];
  bestPractices: string[];
}

export interface ExploitationEvidence {
  vulnerabilityId: string;
  exploitTechnique: string;
  success: boolean;
  screenshotPath?: string;
  logSnippet?: string;
  timestamp: string;
  accessLevel?: string;
  dataAccessed?: string;
}

export interface RemediationSnippet {
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  language: string;
  codeSnippet: string;
  configSnippet?: string;
  implementation: string;
  estimatedEffort: string;
  priority: number;
}

export interface Level7PoCEvidence {
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  exploitSuccessful: boolean;
  toolUsed: string;
  exploitCommand?: string;
  exploitPayload?: string;
  exploitMethodology: string[];
  evasionTechniques: string[];
  sandboxVerified: boolean;
  sandboxAnalysisType?: string;
  riskLevel?: string;
  evidence?: string;
  timeToExploit: number;
  creditsUsed: number;
  rlOptimized: boolean;
  rlReasoning?: string;
}

export interface ReporterCostConfig {
  baseCost: number;
  financialAnalysisCost: number;
  benchmarkingCost: number;
  pdfGenerationCost: number;
  llmModel: string;
}

export const REPORTER_COSTS: Record<PlanLevel, ReporterCostConfig> = {
  ELITE: {
    baseCost: 500,
    financialAnalysisCost: 300,
    benchmarkingCost: 200,
    pdfGenerationCost: 100,
    llmModel: "gpt-5.1",
  },
  PRO: {
    baseCost: 100,
    financialAnalysisCost: 0,
    benchmarkingCost: 0,
    pdfGenerationCost: 50,
    llmModel: "gpt-4o",
  },
};

export interface EnhancedReporterOutput {
  summary: string;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityScore: number;
  recommendations: string[];
  executiveSummary: string;
  planLevel: PlanLevel;
  llmModelUsed: string;
  creditDeductionReporter: number;
  remainingCredits: number;
  generatedAt: string;
  financialRiskAssessments?: FinancialRiskAssessment[];
  totalEstimatedRiskMin?: number;
  totalEstimatedRiskMax?: number;
  annualizedRiskExposure?: number;
  audienceSpecificSummaries?: { audience: ReportAudience; summary: string };
  boardLevelExecutiveSummary?: string;
  industryBenchmark?: IndustryBenchmark;
  exploitationEvidence?: ExploitationEvidence[];
  remediationSnippets?: RemediationSnippet[];
  level7PoCEvidence?: Level7PoCEvidence[];
  verificationScanRequired?: boolean;
  nextRecommendedScanDate?: string;
  executivePdfPath?: string;
  technicalPdfPath?: string;
  formattedRiskRange?: string;
}

export interface ReporterOutput {
  summary: string;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityScore: number;
  recommendations: string[];
  executiveSummary: string;
}

export interface Scan {
  id: string;
  target: string;
  userId: string;
  status: ScanStatus;
  currentAgent: AgentType | null;
  progress: number;
  startedAt: string;
  completedAt?: string;
  error?: string;
  agentResults: {
    recon?: AgentResult & { data: ReconFindings };
    scanner?: AgentResult & { data: ScannerFindings };
    exploiter?: AgentResult & { data: ExploiterFindings };
    reporter?: AgentResult & { data: ReporterOutput | EnhancedReporterOutput };
    rl_exploiter?: AgentResult & { data: unknown };
    prophet?: AgentResult & { data: unknown };
    autonomous_defense?: AgentResult & { data: unknown };
    [key: string]: (AgentResult & { data: unknown }) | undefined;
  };
}

export const insertScanSchema = z.object({
  target: z.string().min(1, "Target is required").max(500),
  userId: z.string().min(1, "User ID is required"),
});

export type InsertScan = z.infer<typeof insertScanSchema>;

export interface Project {
  id: string;
  name: string;
  assetCount: number;
  lastScanDate: string;
  securityScore: number;
  createdAt: string;
}

export const insertProjectSchema = z.object({
  name: z.string().min(1, "Project name is required").max(100),
});

export type InsertProject = z.infer<typeof insertProjectSchema>;

export interface Activity {
  id: string;
  type: "scan_started" | "scan_completed" | "scan_failed" | "vulnerability_found" | "project_created" | "user_login";
  message: string;
  timestamp: string;
  projectId?: string;
  scanId?: string;
}

export interface Report {
  id: string;
  projectName: string;
  scanId: string;
  date: string;
  score: number;
  vulnerabilities: number;
  details?: {
    securityScore: number;
    tls?: {
      valid: boolean;
      protocol: string;
      expiresIn: string;
    };
    headers?: {
      contentSecurityPolicy: boolean;
      xFrameOptions: boolean;
      xContentTypeOptions: boolean;
      strictTransportSecurity: boolean;
    };
    vulnerabilities: {
      id: string;
      title: string;
      severity: "critical" | "high" | "medium" | "low" | "info";
      description: string;
    }[];
    recommendations: string[];
  };
}

export interface UserSettings {
  userId: string;
  notifications: {
    email: boolean;
    criticalAlerts: boolean;
    weeklyReports: boolean;
    scanComplete: boolean;
  };
  profile: {
    name: string;
    email: string;
  };
  company: {
    name: string;
    website: string;
  };
}

export const updateSettingsSchema = z.object({
  notifications: z.object({
    email: z.boolean(),
    criticalAlerts: z.boolean(),
    weeklyReports: z.boolean(),
    scanComplete: z.boolean(),
  }).optional(),
  profile: z.object({
    name: z.string(),
    email: z.string().email(),
  }).optional(),
  company: z.object({
    name: z.string(),
    website: z.string().url(),
  }).optional(),
});

export interface ScannerCostConfig {
  baseCost: number;
  rePlanningFee: number;
  selfRegulationThreshold: number;
  authenticatedScanEnabled: boolean;
}
