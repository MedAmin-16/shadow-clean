import { pgTable, varchar, text, timestamp, jsonb, serial, integer, boolean } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import { z } from "zod";

// =====================================================
// THREAT INTELLIGENCE (Shodan/NVD Integration)
// =====================================================

export const threatIntelTable = pgTable("threat_intel", {
  id: serial("id").primaryKey(),
  cveId: varchar("cve_id", { length: 50 }),
  source: varchar("source", { length: 50 }).notNull(), // shodan, nvd, custom
  type: varchar("type", { length: 50 }).notNull(), // vulnerability, exploit, threat_actor
  severity: varchar("severity", { length: 20 }),
  title: text("title").notNull(),
  description: text("description"),
  affectedProducts: jsonb("affected_products"),
  exploitAvailable: boolean("exploit_available").default(false),
  references: jsonb("references"),
  publishedAt: timestamp("published_at"),
  lastModified: timestamp("last_modified"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export type DbThreatIntel = typeof threatIntelTable.$inferSelect;

export interface ThreatIntelQuery {
  cve?: string;
  keyword?: string;
  severity?: "critical" | "high" | "medium" | "low";
  source?: "shodan" | "nvd" | "all";
  limit?: number;
}

export interface ThreatIntelResult {
  id: string;
  cveId?: string;
  source: string;
  type: string;
  severity?: string;
  title: string;
  description?: string;
  affectedProducts?: string[];
  exploitAvailable: boolean;
  references?: string[];
  publishedAt?: string;
}

// =====================================================
// DATABASE SANDBOX (Postgres Schema Isolation)
// =====================================================

export const scanSandboxTable = pgTable("scan_sandboxes", {
  id: serial("id").primaryKey(),
  scanId: varchar("scan_id").notNull(),
  userId: varchar("user_id").notNull(),
  schemaName: varchar("schema_name", { length: 100 }).notNull(),
  status: varchar("status", { length: 20 }).notNull().default("active"), // active, archived, deleted
  tablesCreated: integer("tables_created").default(0),
  dataInserted: boolean("data_inserted").default(false),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  cleanedAt: timestamp("cleaned_at"),
});

export type DbScanSandbox = typeof scanSandboxTable.$inferSelect;

export interface SandboxConfig {
  scanId: string;
  userId: string;
  ttlHours?: number;
  allowedTables?: string[];
}

// =====================================================
// AI-POWERED REMEDIATION
// =====================================================

export const remediationSuggestionsTable = pgTable("remediation_suggestions", {
  id: serial("id").primaryKey(),
  scanId: varchar("scan_id").notNull(),
  vulnerabilityId: varchar("vulnerability_id").notNull(),
  userId: varchar("user_id").notNull(),
  severity: varchar("severity", { length: 20 }).notNull(),
  vulnerabilityTitle: text("vulnerability_title").notNull(),
  aiSuggestion: text("ai_suggestion").notNull(),
  codeSnippet: text("code_snippet"),
  configFix: text("config_fix"),
  estimatedEffort: varchar("estimated_effort", { length: 50 }),
  priority: integer("priority").default(1),
  status: varchar("status", { length: 20 }).default("pending"), // pending, applied, dismissed
  llmModel: varchar("llm_model", { length: 50 }),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  appliedAt: timestamp("applied_at"),
});

export type DbRemediationSuggestion = typeof remediationSuggestionsTable.$inferSelect;

export interface RemediationRequest {
  scanId: string;
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  vulnerabilityDescription: string;
  severity: string;
  affectedCode?: string;
  technology?: string;
}

export interface AIRemediationResult {
  vulnerabilityId: string;
  suggestion: string;
  codeSnippet?: string;
  configFix?: string;
  estimatedEffort: string;
  priority: number;
  steps: string[];
}

// =====================================================
// GLOBAL COMPLIANCE REPORTS (ISO/GDPR)
// =====================================================

export const complianceReportsTable = pgTable("compliance_reports", {
  id: serial("id").primaryKey(),
  scanId: varchar("scan_id").notNull(),
  userId: varchar("user_id").notNull(),
  framework: varchar("framework", { length: 50 }).notNull(), // iso27001, gdpr, pci_dss, hipaa, soc2
  overallScore: integer("overall_score"),
  compliantControls: integer("compliant_controls").default(0),
  nonCompliantControls: integer("non_compliant_controls").default(0),
  partialControls: integer("partial_controls").default(0),
  findings: jsonb("findings"),
  recommendations: jsonb("recommendations"),
  reportData: jsonb("report_data"),
  pdfPath: text("pdf_path"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export type DbComplianceReport = typeof complianceReportsTable.$inferSelect;

export type ComplianceFramework = "iso27001" | "gdpr" | "pci_dss" | "hipaa" | "soc2";

export interface ComplianceControl {
  controlId: string;
  category: string;
  title: string;
  description: string;
  status: "compliant" | "non_compliant" | "partial" | "not_applicable";
  findings?: string[];
  recommendations?: string[];
  evidence?: string[];
}

export interface ComplianceReportRequest {
  scanId: string;
  frameworks: ComplianceFramework[];
  includeRemediation?: boolean;
}

export interface ComplianceReportResult {
  framework: ComplianceFramework;
  overallScore: number;
  controls: ComplianceControl[];
  summary: {
    compliant: number;
    nonCompliant: number;
    partial: number;
    notApplicable: number;
  };
  recommendations: string[];
  generatedAt: string;
}

// =====================================================
// VISUAL ATTACK PATH (Graph Visualization)
// =====================================================

export const attackPathsTable = pgTable("attack_paths", {
  id: serial("id").primaryKey(),
  scanId: varchar("scan_id").notNull(),
  userId: varchar("user_id").notNull(),
  graphData: jsonb("graph_data").notNull(),
  nodeCount: integer("node_count").default(0),
  edgeCount: integer("edge_count").default(0),
  criticalPaths: integer("critical_paths").default(0),
  maxDepth: integer("max_depth").default(0),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export type DbAttackPath = typeof attackPathsTable.$inferSelect;

export interface AttackGraphNode {
  id: string;
  type: "asset" | "vulnerability" | "attack_technique" | "impact";
  label: string;
  severity?: "critical" | "high" | "medium" | "low";
  metadata?: Record<string, unknown>;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  type: "exploits" | "leads_to" | "enables" | "compromises";
  probability?: number;
  label?: string;
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  criticalPaths: string[][];
  summary: {
    totalNodes: number;
    totalEdges: number;
    criticalPathCount: number;
    maxAttackDepth: number;
    highestRiskPath: string[];
  };
}

// =====================================================
// CONTINUOUS MONITORING (Scheduling)
// =====================================================

export const monitoringSchedulesTable = pgTable("monitoring_schedules", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  projectId: varchar("project_id"),
  target: text("target").notNull(),
  frequency: varchar("frequency", { length: 20 }).notNull(), // daily, weekly, monthly
  enabled: boolean("enabled").default(true),
  lastRunAt: timestamp("last_run_at"),
  nextRunAt: timestamp("next_run_at"),
  config: jsonb("config"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export type DbMonitoringSchedule = typeof monitoringSchedulesTable.$inferSelect;

export const monitoringResultsTable = pgTable("monitoring_results", {
  id: serial("id").primaryKey(),
  scheduleId: integer("schedule_id").notNull(),
  scanId: varchar("scan_id"),
  status: varchar("status", { length: 20 }).notNull(), // success, failed, running
  changesDetected: boolean("changes_detected").default(false),
  newVulnerabilities: integer("new_vulnerabilities").default(0),
  resolvedVulnerabilities: integer("resolved_vulnerabilities").default(0),
  summary: jsonb("summary"),
  runAt: timestamp("run_at").notNull().defaultNow(),
});

export type DbMonitoringResult = typeof monitoringResultsTable.$inferSelect;

export interface MonitoringScheduleConfig {
  target: string;
  frequency: "daily" | "weekly" | "monthly";
  notifyOnChanges?: boolean;
  emailRecipients?: string[];
  scanDepth?: "quick" | "standard" | "comprehensive";
}

export const insertMonitoringScheduleSchema = z.object({
  target: z.string().min(1),
  frequency: z.enum(["daily", "weekly", "monthly"]),
  projectId: z.string().optional(),
  config: z.object({
    notifyOnChanges: z.boolean().optional(),
    emailRecipients: z.array(z.string().email()).optional(),
    scanDepth: z.enum(["quick", "standard", "comprehensive"]).optional(),
  }).optional(),
});

export type InsertMonitoringSchedule = z.infer<typeof insertMonitoringScheduleSchema>;

// =====================================================
// PHISHING SIMULATION
// =====================================================

export const phishingCampaignsTable = pgTable("phishing_campaigns", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  name: varchar("name", { length: 200 }).notNull(),
  templateType: varchar("template_type", { length: 50 }).notNull(), // credential_harvest, malware_download, awareness
  status: varchar("status", { length: 20 }).notNull().default("draft"), // draft, scheduled, running, completed
  targetEmails: jsonb("target_emails"),
  scheduledAt: timestamp("scheduled_at"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  config: jsonb("config"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export type DbPhishingCampaign = typeof phishingCampaignsTable.$inferSelect;

export const phishingResultsTable = pgTable("phishing_results", {
  id: serial("id").primaryKey(),
  campaignId: integer("campaign_id").notNull(),
  targetEmail: varchar("target_email", { length: 255 }).notNull(),
  emailSent: boolean("email_sent").default(false),
  emailOpened: boolean("email_opened").default(false),
  linkClicked: boolean("link_clicked").default(false),
  credentialsSubmitted: boolean("credentials_submitted").default(false),
  reported: boolean("reported").default(false),
  sentAt: timestamp("sent_at"),
  openedAt: timestamp("opened_at"),
  clickedAt: timestamp("clicked_at"),
  submittedAt: timestamp("submitted_at"),
  reportedAt: timestamp("reported_at"),
});

export type DbPhishingResult = typeof phishingResultsTable.$inferSelect;

export interface PhishingTemplate {
  id: string;
  name: string;
  type: "credential_harvest" | "malware_download" | "awareness";
  subject: string;
  senderName: string;
  previewText: string;
  difficulty: "easy" | "medium" | "hard";
}

export interface PhishingCampaignRequest {
  name: string;
  templateType: string;
  targetEmails: string[];
  scheduledAt?: string;
  config?: {
    customSubject?: string;
    customSenderName?: string;
    landingPageUrl?: string;
  };
}

export interface PhishingCampaignStats {
  campaignId: number;
  totalTargets: number;
  emailsSent: number;
  emailsOpened: number;
  linksClicked: number;
  credentialsSubmitted: number;
  reported: number;
  openRate: number;
  clickRate: number;
  submissionRate: number;
  reportRate: number;
}

export const insertPhishingCampaignSchema = z.object({
  name: z.string().min(1).max(200),
  templateType: z.enum(["credential_harvest", "malware_download", "awareness"]),
  targetEmails: z.array(z.string().email()).min(1),
  scheduledAt: z.string().datetime().optional(),
  config: z.object({
    customSubject: z.string().optional(),
    customSenderName: z.string().optional(),
    landingPageUrl: z.string().url().optional(),
  }).optional(),
});

export type InsertPhishingCampaign = z.infer<typeof insertPhishingCampaignSchema>;

// =====================================================
// MULTI-CLOUD SECURITY ENHANCEMENTS
// =====================================================

export const cloudScanConfigsTable = pgTable("cloud_scan_configs", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  provider: varchar("provider", { length: 20 }).notNull(), // aws, azure, gcp
  name: varchar("name", { length: 100 }).notNull(),
  credentialsId: integer("credentials_id"),
  regions: jsonb("regions"),
  services: jsonb("services"),
  enabled: boolean("enabled").default(true),
  lastScanAt: timestamp("last_scan_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export type DbCloudScanConfig = typeof cloudScanConfigsTable.$inferSelect;

export interface CloudSecurityFinding {
  id: string;
  provider: "aws" | "azure" | "gcp";
  resourceId: string;
  resourceType: string;
  region: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  recommendation: string;
  complianceFrameworks?: string[];
  remediation?: {
    cli?: string;
    terraform?: string;
    console?: string;
  };
}
