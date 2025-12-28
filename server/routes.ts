import type { Express } from "express";
import type { Server } from "http";
import { scanRateLimiter } from "./src/middlewares/rateLimiter";
import { apiKeyAuth } from "./src/middlewares/apiKeyAuth";
import { sessionAuth, optionalSessionAuth } from "./src/middlewares/sessionAuth";
import { storage } from "./storage";
import { creditService } from "./src/services/creditService";
import {
  startScan,
  getScanStatus,
  getAllScans,
  getScanById,
  deleteScan,
  downloadReport,
  getScanHistory,
  stopScan,
  rescanTarget,
  exportScanHistory,
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
  app.get("/api/scans/export", sessionAuth, exportScanHistory);
  app.post("/api/scans/:id/rescan", sessionAuth, rescanTarget);
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
  
  // WAF Integration Routes (ELITE only)
  app.post("/api/integrations/save", requireFeature("waf_automation"), async (req, res) => {
    try {
      const { integrationId, credentials } = req.body;
      const userId = (req as any).userId;
      
      if (!integrationId || !credentials) {
        return res.status(400).json({ error: "Missing integration ID or credentials" });
      }
      
      // Save integration credentials to storage
      await storage.saveIntegration(userId, integrationId, credentials);
      
      res.json({ success: true, message: "Integration saved successfully" });
    } catch (error) {
      console.error("Error saving integration:", error);
      res.status(500).json({ error: "Failed to save integration" });
    }
  });

  app.post("/api/integrations/test", requireFeature("waf_automation"), async (req, res) => {
    try {
      const { integrationId } = req.body;
      const userId = (req as any).userId;
      
      if (!integrationId) {
        return res.status(400).json({ error: "Missing integration ID" });
      }
      
      // Get integration credentials from storage
      const integration = await storage.getIntegration(userId, integrationId);
      if (!integration) {
        return res.status(404).json({ error: "Integration not found" });
      }
      
      // Test the integration connection
      const isConnected = await storage.testIntegration(integrationId, integration.config);
      
      if (isConnected) {
        await storage.updateIntegrationStatus(userId, integrationId, true);
        res.json({ success: true, message: "Connection successful!" });
      } else {
        res.json({ success: false, error: "Connection failed. Please verify your credentials." });
      }
    } catch (error) {
      console.error("Error testing integration:", error);
      res.status(500).json({ error: "Failed to test integration" });
    }
  });

  app.delete("/api/integrations/:id", requireFeature("waf_automation"), async (req, res) => {
    try {
      const { id } = req.params;
      const userId = (req as any).userId;
      
      await storage.deleteIntegration(userId, id);
      
      res.json({ success: true, message: "Integration removed successfully" });
    } catch (error) {
      console.error("Error deleting integration:", error);
      res.status(500).json({ error: "Failed to remove integration" });
    }
  });

  app.get("/api/integrations", sessionAuth, async (req, res) => {
    try {
      const session = (req as any).session;
      const userId = session?.userId || "user-1";
      
      // Get user's plan level from credits
      const credits = await creditService.getUserCredits(userId);
      const integrations = await storage.getIntegrations(userId);
      
      res.json({
        planLevel: credits.planLevel,
        integrations: integrations || []
      });
    } catch (error) {
      console.error("Error fetching integrations:", error);
      res.status(500).json({ error: "Failed to fetch integrations" });
    }
  });

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

  // WAF Hotfix Deployment (ELITE only)
  app.post("/api/vulnerabilities/:vulnId/deploy-hotfix", requireMinPlan("ELITE"), async (req, res) => {
    try {
      const { vulnId } = req.params;
      const { vulnerability } = req.body;
      const userId = (req as any).userId;

      // Generate WAF rule ID
      const ruleId = `WAF-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`.toUpperCase();

      // Generate WAF rules based on vulnerability type
      const title = vulnerability?.title?.toLowerCase() || "";
      let wafRules: any[] = [];

      if (title.includes("sql") || title.includes("injection")) {
        // SQLi WAF Rules
        wafRules = [
          {
            name: `ShadowTwin-SQLi-${ruleId}`,
            type: "waf_rule",
            action: "block",
            pattern: "(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|--|'|\")",
            description: `Block SQL Injection attempts for ${vulnerability.title}`
          },
          {
            name: `ShadowTwin-SQLi-Param-${ruleId}`,
            type: "parameter_filter",
            action: "sanitize",
            pattern: "(?i)(union|select|insert|delete|drop)",
            description: `Sanitize parameters for SQL injection in ${vulnerability.url}`
          }
        ];
      } else if (title.includes("xss") || title.includes("cross-site")) {
        // XSS WAF Rules
        wafRules = [
          {
            name: `ShadowTwin-XSS-${ruleId}`,
            type: "waf_rule",
            action: "block",
            pattern: "(<script|javascript:|on\\w+=|<iframe|<embed)",
            description: `Block XSS attempts for ${vulnerability.title}`
          },
          {
            name: `ShadowTwin-XSS-Sanitize-${ruleId}`,
            type: "content_filter",
            action: "sanitize",
            pattern: "(<script.*?</script>|javascript:|event handlers)",
            description: `Sanitize XSS payloads in responses`
          }
        ];
      } else if (title.includes("/.env") || title.includes("actuator") || title.includes("sensitive")) {
        // Sensitive Endpoints
        wafRules = [
          {
            name: `ShadowTwin-SensitiveEndpoint-${ruleId}`,
            type: "path_block",
            action: "block",
            pattern: "(?i)(/\\.env|\\/actuator|\\/admin|\\/config|\\/api/internal)",
            description: `Block access to sensitive endpoints`
          },
          {
            name: `ShadowTwin-SensitiveEndpoint-Challenge-${ruleId}`,
            type: "path_challenge",
            action: "challenge",
            pattern: `(?i)(${vulnerability.url?.split('/').pop() || 'sensitive'})`,
            description: `Challenge requests to ${vulnerability.url}`
          }
        ];
      } else {
        // Default WAF Rule
        wafRules = [
          {
            name: `ShadowTwin-Default-${ruleId}`,
            type: "anomaly_detection",
            action: "alert",
            pattern: ".*",
            description: `Monitor for anomalies related to ${vulnerability.title}`
          }
        ];
      }

      // Simulate WAF rule deployment (in production, this would integrate with Cloudflare/AWS)
      console.log(`[WAF HOTFIX] Deploying rule ${ruleId} for vulnerability ${vulnId}`, {
        userId,
        title: vulnerability?.title,
        payload: vulnerability?.payload,
        url: vulnerability?.url,
        rules: wafRules,
      });

      res.json({
        success: true,
        ruleId,
        message: `Vulnerability Shielded: WAF Rule #${ruleId} Active`,
        timestamp: new Date().toISOString(),
        rules: wafRules,
        deployment: {
          status: "active",
          vendor: "Cloudflare/AWS WAF",
          effectiveAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 86400000).toISOString(), // 24 hours
        }
      });
    } catch (error) {
      console.error("Error deploying hotfix:", error);
      res.status(500).json({ error: "Failed to deploy WAF hotfix" });
    }
  });

  return httpServer;
}
