import type { Express } from "express";
import type { Server } from "http";
import { scanRateLimiter } from "./src/middlewares/rateLimiter";
import { apiKeyAuth } from "./src/middlewares/apiKeyAuth";
import { sessionAuth, optionalSessionAuth } from "./src/middlewares/sessionAuth";
import {
  startScan,
  getScanStatus,
  getAllScans,
  getScanById,
  deleteScan,
  downloadReport,
  getScanHistory,
} from "./src/controllers/scanController";
import {
  createApiKey,
  listApiKeys,
  deleteApiKey,
  getSecurityLogs,
} from "./src/controllers/apiKeyController";
import {
  getAllProjects,
  getProject,
  createProject,
  deleteProject,
} from "./src/controllers/projectController";
import { getActivities } from "./src/controllers/activityController";
import { getReports, getReport, createReportFromScan } from "./src/controllers/reportController";
import { getSettings, updateSettings } from "./src/controllers/settingsController";
import { getDashboardMetrics, getRecentVulnerabilities } from "./src/controllers/dashboardController";
import {
  getUserCredits,
  addCredits,
  refundCredits,
  getTransactionHistory,
  checkCredits,
  setPlanLevel,
} from "./src/controllers/creditsController";
import {
  analyzeApiSpec,
  getAnalysisTypes,
  parseSpec,
} from "./src/controllers/apiSecurityController";
import {
  startCSPMScan,
  getCSPMCost,
  getProviderMisconfigurations,
} from "./src/controllers/cspmController";
import {
  adminLogin,
  verifyAdmin,
  adminLogout,
  getAdminStats,
  getAdminUsers,
  toggleAgent,
  adjustCredits,
  updateThreatFeed,
  getThreatFeeds,
  requireAdmin,
} from "./src/controllers/adminController";
import {
  getCurrentUser,
  clientLogout,
} from "./src/controllers/userController";
import {
  register,
  login,
} from "./src/controllers/authController";
import { requireFeature, requireMinPlan } from "./src/middlewares/planAccess";
import secretScanRoutes from "./src/routes/secretScanRoutes";
import {
  startShadowLogicScan,
  getShadowLogicScanStatus,
  getShadowLogicThoughts,
  getShadowLogicResult,
  getShadowLogicTestTypes,
  getShadowLogicCost,
  cancelShadowLogicScan,
} from "./src/controllers/shadowLogicController";
import {
  searchThreatIntel,
  searchShodanTarget,
  createSandbox,
  getSandboxData,
  deleteSandbox,
  generateRemediation,
  generateBatchRemediation,
  generateComplianceReport,
  getComplianceFrameworks,
  generateAttackPath,
  createMonitoringSchedule,
  getMonitoringSchedules,
  updateMonitoringSchedule,
  deleteMonitoringSchedule,
  getMonitoringResults,
  runManualMonitoringScan,
  getPhishingTemplates,
  createPhishingCampaign,
  getPhishingCampaigns,
  getPhishingCampaign,
  launchPhishingCampaign,
  getPhishingCampaignStats,
  deletePhishingCampaign,
  getFeatureAccess,
} from "./src/controllers/advancedFeaturesController";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  
  app.post("/api/keys", createApiKey);
  app.get("/api/keys/:userId", listApiKeys);
  app.delete("/api/keys/:keyId", deleteApiKey);
  app.get("/api/security/logs", getSecurityLogs);

  app.post("/api/scan", scanRateLimiter, apiKeyAuth, startScan);
  app.get("/api/scan/status/:id", scanRateLimiter, apiKeyAuth, getScanStatus);
  app.get("/api/scan/report/:id", scanRateLimiter, apiKeyAuth, downloadReport);
  app.get("/api/scan/history/:userId", scanRateLimiter, apiKeyAuth, getScanHistory);

  app.post("/api/scans", sessionAuth, startScan);
  app.get("/api/scans", optionalSessionAuth, getAllScans);
  app.get("/api/scans/:id", optionalSessionAuth, getScanById);
  app.post("/api/scans/:id/stop", sessionAuth, stopScan);
  app.delete("/api/scans/:id", sessionAuth, deleteScan);
  
  app.get("/api/projects", getAllProjects);
  app.get("/api/projects/:id", getProject);
  app.post("/api/projects", createProject);
  app.delete("/api/projects/:id", deleteProject);
  
  app.get("/api/activity", getActivities);
  
  app.get("/api/reports", getReports);
  app.get("/api/reports/:id", getReport);
  app.post("/api/reports", createReportFromScan);
  
  app.get("/api/settings", getSettings);
  app.patch("/api/settings", updateSettings);
  
  app.get("/api/dashboard/metrics", getDashboardMetrics);
  app.get("/api/dashboard/vulnerabilities", getRecentVulnerabilities);

  // Credits System Routes
  app.get("/api/credits/:userId", getUserCredits);
  app.post("/api/credits/add", addCredits);
  app.post("/api/credits/refund", refundCredits);
  app.get("/api/credits/:userId/history", getTransactionHistory);
  app.get("/api/credits/:userId/check", checkCredits);
  app.post("/api/credits/plan", setPlanLevel);

  // API Security Analysis Routes
  app.post("/api/security/api/analyze", analyzeApiSpec);
  app.get("/api/security/api/types", getAnalysisTypes);
  app.post("/api/security/api/parse", parseSpec);

  // CSPM (Cloud Security Posture Management) Routes
  app.post("/api/cspm/scan", scanRateLimiter, apiKeyAuth, startCSPMScan);
  app.get("/api/cspm/cost", apiKeyAuth, getCSPMCost);
  app.get("/api/cspm/checks/:provider", getProviderMisconfigurations);

  // Auth Routes (Registration and Login)
  app.post("/api/auth/register", register);
  app.post("/api/auth/login", login);

  // User Routes (Client-side user session)
  app.get("/api/user/me", getCurrentUser);
  app.post("/api/user/logout", clientLogout);

  // Admin Routes (Protected with admin authentication)
  app.post("/api/admin/login", adminLogin);
  app.get("/api/admin/verify", verifyAdmin);
  app.post("/api/admin/logout", adminLogout);
  app.get("/api/admin/stats", requireAdmin, getAdminStats);
  app.get("/api/admin/users", requireAdmin, getAdminUsers);
  app.post("/api/admin/agents/toggle", requireAdmin, toggleAgent);
  app.post("/api/admin/credits/adjust", requireAdmin, adjustCredits);
  app.get("/api/admin/threat-feeds", requireAdmin, getThreatFeeds);
  app.post("/api/admin/threat-feeds/update", requireAdmin, updateThreatFeed);

  // =====================================================
  // ADVANCED FEATURES - Plan Gated Routes
  // =====================================================
  
  // Feature Access Check (all authenticated users)
  app.get("/api/features/access", sessionAuth, getFeatureAccess);

  // Threat Intelligence (ELITE only)
  app.get("/api/threat-intel/search", requireFeature("ai_threat_intel"), searchThreatIntel);
  app.get("/api/threat-intel/shodan/:target", requireFeature("ai_threat_intel"), searchShodanTarget);

  // Database Sandbox (ELITE only)
  app.post("/api/sandbox", requireFeature("database_sandbox"), createSandbox);
  app.get("/api/sandbox/:schemaName", requireFeature("database_sandbox"), getSandboxData);
  app.delete("/api/sandbox/:schemaName", requireFeature("database_sandbox"), deleteSandbox);

  // AI-Powered Remediation (ELITE only)
  app.post("/api/remediation/generate", requireFeature("ai_remediation"), generateRemediation);
  app.post("/api/remediation/batch", requireFeature("ai_remediation"), generateBatchRemediation);

  // Compliance Reports (ELITE only)
  app.get("/api/compliance/frameworks", getComplianceFrameworks);
  app.post("/api/compliance/report", requireFeature("compliance_reports"), generateComplianceReport);

  // Visual Attack Path (PRO and ELITE)
  app.get("/api/attack-path/:scanId", requireFeature("visual_attack_path"), generateAttackPath);

  // Continuous Monitoring (PRO: weekly, ELITE: daily)
  app.post("/api/monitoring/schedules", requireFeature("weekly_monitoring"), createMonitoringSchedule);
  app.get("/api/monitoring/schedules", requireFeature("weekly_monitoring"), getMonitoringSchedules);
  app.patch("/api/monitoring/schedules/:scheduleId", requireFeature("weekly_monitoring"), updateMonitoringSchedule);
  app.delete("/api/monitoring/schedules/:scheduleId", requireFeature("weekly_monitoring"), deleteMonitoringSchedule);
  app.get("/api/monitoring/schedules/:scheduleId/results", requireFeature("weekly_monitoring"), getMonitoringResults);
  app.post("/api/monitoring/schedules/:scheduleId/run", requireFeature("weekly_monitoring"), runManualMonitoringScan);

  // Phishing Simulation (ELITE only)
  app.get("/api/phishing/templates", requireFeature("phishing_simulation"), getPhishingTemplates);
  app.post("/api/phishing/campaigns", requireFeature("phishing_simulation"), createPhishingCampaign);
  app.get("/api/phishing/campaigns", requireFeature("phishing_simulation"), getPhishingCampaigns);
  app.get("/api/phishing/campaigns/:campaignId", requireFeature("phishing_simulation"), getPhishingCampaign);
  app.post("/api/phishing/campaigns/:campaignId/launch", requireFeature("phishing_simulation"), launchPhishingCampaign);
  app.get("/api/phishing/campaigns/:campaignId/stats", requireFeature("phishing_simulation"), getPhishingCampaignStats);
  app.delete("/api/phishing/campaigns/:campaignId", requireFeature("phishing_simulation"), deletePhishingCampaign);

  // Cloud Security (PRO and ELITE) - Enhanced CSPM with plan gating
  app.post("/api/cloud-security/scan", requireFeature("cloud_security"), scanRateLimiter, startCSPMScan);

  // ShadowLogic™ - Autonomous AI Business Logic Auditor (ELITE only)
  app.post("/api/shadow-logic/scan", requireFeature("shadow_logic"), startShadowLogicScan);
  app.get("/api/shadow-logic/scan/:scanId/status", requireFeature("shadow_logic"), getShadowLogicScanStatus);
  app.get("/api/shadow-logic/scan/:scanId/thoughts", requireFeature("shadow_logic"), getShadowLogicThoughts);
  app.get("/api/shadow-logic/scan/:scanId/result", requireFeature("shadow_logic"), getShadowLogicResult);
  app.delete("/api/shadow-logic/scan/:scanId", requireFeature("shadow_logic"), cancelShadowLogicScan);
  app.get("/api/shadow-logic/test-types", getShadowLogicTestTypes);
  app.get("/api/shadow-logic/cost", getShadowLogicCost);

  // Secret Scan Routes - JS-Secret Workflow with Real-Time Output
  app.use("/api/secret-scan", secretScanRoutes);

  return httpServer;
}
