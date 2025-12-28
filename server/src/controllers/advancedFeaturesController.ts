import type { Request, Response } from "express";
import type { PlanGatedRequest } from "../middlewares/planAccess";
import { threatIntelService } from "../services/threatIntel";
import { sandboxService } from "../services/sandbox";
import { remediationService } from "../services/remediation";
import { complianceService } from "../services/compliance";
import { attackPathService } from "../services/attackPath";
import { monitoringService } from "../services/monitoring";
import { phishingService } from "../services/phishing";
import { employeeRiskRadarService } from "../services/employeeRiskRadarService";
import { storage } from "../../storage";
import { insertMonitoringScheduleSchema, insertPhishingCampaignSchema } from "@shared/advancedFeatures";
import type { PlanLevel } from "@shared/schema";

export async function getRadarData(req: PlanGatedRequest, res: Response) {
  try {
    const userId = req.userId!;
    const data = await employeeRiskRadarService.getRadarData(userId);
    res.json({ success: true, data: data || { status: "no_data" } });
  } catch (error) {
    console.error("[AdvancedFeatures] Radar data fetch error:", error);
    res.status(500).json({ success: false, error: "Failed to fetch radar data" });
  }
}

export async function startRadarScan(req: PlanGatedRequest, res: Response) {
  try {
    const userId = req.userId!;
    const { domain } = req.body;

    if (!domain) {
      return res.status(400).json({ success: false, error: "Target domain is required" });
    }

    const result = await employeeRiskRadarService.performRadarScan(userId, domain);
    res.json({ success: true, ...result });
  } catch (error) {
    console.error("[AdvancedFeatures] Radar scan start error:", error);
    res.status(500).json({ success: false, error: "Failed to start radar scan" });
  }
}

export async function searchThreatIntel(req: PlanGatedRequest, res: Response) {
  try {
    const { cve, keyword, severity, source, limit } = req.query;
    
    const results = await threatIntelService.search({
      cve: cve as string,
      keyword: keyword as string,
      severity: severity as "critical" | "high" | "medium" | "low",
      source: source as "shodan" | "nvd" | "all",
      limit: limit ? parseInt(limit as string, 10) : 20,
    });

    res.json({ success: true, data: results, count: results.length });
  } catch (error) {
    console.error("[AdvancedFeatures] Threat intel search error:", error);
    res.status(500).json({ success: false, error: "Failed to search threat intelligence" });
  }
}

export async function searchShodanTarget(req: PlanGatedRequest, res: Response) {
  try {
    const { target } = req.params;
    
    if (!target) {
      return res.status(400).json({ success: false, error: "Target is required" });
    }

    const results = await threatIntelService.searchShodan(target);
    res.json({ success: true, data: results, target });
  } catch (error) {
    console.error("[AdvancedFeatures] Shodan search error:", error);
    res.status(500).json({ success: false, error: "Failed to search Shodan" });
  }
}

export async function createSandbox(req: PlanGatedRequest, res: Response) {
  try {
    const { scanId } = req.body;
    const userId = req.userId!;

    if (!scanId) {
      return res.status(400).json({ success: false, error: "Scan ID is required" });
    }

    const result = await sandboxService.createSandbox({ scanId, userId });
    res.json({ ...result });
  } catch (error) {
    console.error("[AdvancedFeatures] Sandbox creation error:", error);
    res.status(500).json({ success: false, error: "Failed to create sandbox" });
  }
}

export async function getSandboxData(req: PlanGatedRequest, res: Response) {
  try {
    const { schemaName } = req.params;

    if (!schemaName) {
      return res.status(400).json({ success: false, error: "Schema name is required" });
    }

    const data = await sandboxService.getSandboxData(schemaName);
    res.json({ success: true, data });
  } catch (error) {
    console.error("[AdvancedFeatures] Sandbox data retrieval error:", error);
    res.status(500).json({ success: false, error: "Failed to get sandbox data" });
  }
}

export async function deleteSandbox(req: PlanGatedRequest, res: Response) {
  try {
    const { schemaName } = req.params;

    if (!schemaName) {
      return res.status(400).json({ success: false, error: "Schema name is required" });
    }

    await sandboxService.cleanupSandbox(schemaName);
    res.json({ success: true, message: "Sandbox deleted successfully" });
  } catch (error) {
    console.error("[AdvancedFeatures] Sandbox deletion error:", error);
    res.status(500).json({ success: false, error: "Failed to delete sandbox" });
  }
}

export async function generateRemediation(req: PlanGatedRequest, res: Response) {
  try {
    const { scanId, vulnerabilityId, vulnerabilityTitle, vulnerabilityDescription, severity, affectedCode, technology } = req.body;

    if (!vulnerabilityId || !vulnerabilityTitle || !vulnerabilityDescription || !severity) {
      return res.status(400).json({ 
        success: false, 
        error: "Missing required fields: vulnerabilityId, vulnerabilityTitle, vulnerabilityDescription, severity" 
      });
    }

    const result = await remediationService.generateRemediation({
      scanId,
      vulnerabilityId,
      vulnerabilityTitle,
      vulnerabilityDescription,
      severity,
      affectedCode,
      technology,
    });

    res.json({ success: true, data: result });
  } catch (error) {
    console.error("[AdvancedFeatures] Remediation generation error:", error);
    res.status(500).json({ success: false, error: "Failed to generate remediation" });
  }
}

export async function generateBatchRemediation(req: PlanGatedRequest, res: Response) {
  try {
    const { vulnerabilities } = req.body;

    if (!vulnerabilities || !Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
      return res.status(400).json({ success: false, error: "Vulnerabilities array is required" });
    }

    const results = await remediationService.generateBatchRemediation(vulnerabilities);
    res.json({ success: true, data: results, count: results.length });
  } catch (error) {
    console.error("[AdvancedFeatures] Batch remediation error:", error);
    res.status(500).json({ success: false, error: "Failed to generate batch remediation" });
  }
}

export async function generateComplianceReport(req: PlanGatedRequest, res: Response) {
  try {
    const { scanId, frameworks, includeRemediation } = req.body;

    if (!scanId) {
      return res.status(400).json({ success: false, error: "Scan ID is required" });
    }

    if (!frameworks || !Array.isArray(frameworks) || frameworks.length === 0) {
      return res.status(400).json({ success: false, error: "At least one framework is required" });
    }

    const scan = await storage.getScan(scanId);
    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    const scannerData = scan.agentResults?.scanner?.data as any;
    if (!scannerData) {
      return res.status(400).json({ success: false, error: "Scan has no scanner data" });
    }

    const reports = await complianceService.generateComplianceReport(scannerData, {
      scanId,
      frameworks,
      includeRemediation,
    });

    res.json({ success: true, data: reports, scanId });
  } catch (error) {
    console.error("[AdvancedFeatures] Compliance report error:", error);
    res.status(500).json({ success: false, error: "Failed to generate compliance report" });
  }
}

export async function getComplianceFrameworks(req: Request, res: Response) {
  const frameworks = [
    { id: "iso27001", name: "ISO 27001", description: "Information Security Management System" },
    { id: "gdpr", name: "GDPR", description: "General Data Protection Regulation" },
    { id: "pci_dss", name: "PCI DSS", description: "Payment Card Industry Data Security Standard" },
    { id: "hipaa", name: "HIPAA", description: "Health Insurance Portability and Accountability Act" },
    { id: "soc2", name: "SOC 2", description: "Service Organization Control 2" },
  ];
  res.json({ success: true, data: frameworks });
}

export async function generateAttackPath(req: PlanGatedRequest, res: Response) {
  try {
    const { scanId } = req.params;

    if (!scanId) {
      return res.status(400).json({ success: false, error: "Scan ID is required" });
    }

    const scan = await storage.getScan(scanId);
    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    const scannerData = scan.agentResults?.scanner?.data as any;
    const exploiterData = scan.agentResults?.exploiter?.data as any;

    if (!scannerData) {
      return res.status(400).json({ success: false, error: "Scan has no scanner data" });
    }

    const graph = attackPathService.generateAttackGraph(scannerData, exploiterData, scan.target);
    res.json({ success: true, data: graph, scanId, target: scan.target });
  } catch (error) {
    console.error("[AdvancedFeatures] Attack path generation error:", error);
    res.status(500).json({ success: false, error: "Failed to generate attack path" });
  }
}

export async function createMonitoringSchedule(req: PlanGatedRequest, res: Response) {
  try {
    const userId = req.userId!;
    const planLevel = req.userPlanLevel || "PRO";

    const validation = insertMonitoringScheduleSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({ success: false, error: validation.error.errors });
    }

    const schedule = await monitoringService.createSchedule(userId, validation.data, planLevel);
    res.json({ success: true, data: schedule });
  } catch (error: any) {
    console.error("[AdvancedFeatures] Monitoring schedule creation error:", error);
    res.status(400).json({ success: false, error: error.message || "Failed to create schedule" });
  }
}

export async function getMonitoringSchedules(req: PlanGatedRequest, res: Response) {
  try {
    const userId = req.userId!;
    const schedules = await monitoringService.getUserSchedules(userId);
    res.json({ success: true, data: schedules });
  } catch (error) {
    console.error("[AdvancedFeatures] Get schedules error:", error);
    res.status(500).json({ success: false, error: "Failed to get schedules" });
  }
}

export async function updateMonitoringSchedule(req: PlanGatedRequest, res: Response) {
  try {
    const { scheduleId } = req.params;
    const { enabled, frequency, config } = req.body;

    const schedule = await monitoringService.updateSchedule(
      parseInt(scheduleId, 10),
      { enabled, frequency, config }
    );

    if (!schedule) {
      return res.status(404).json({ success: false, error: "Schedule not found" });
    }

    res.json({ success: true, data: schedule });
  } catch (error) {
    console.error("[AdvancedFeatures] Update schedule error:", error);
    res.status(500).json({ success: false, error: "Failed to update schedule" });
  }
}

export async function deleteMonitoringSchedule(req: PlanGatedRequest, res: Response) {
  try {
    const { scheduleId } = req.params;
    const deleted = await monitoringService.deleteSchedule(parseInt(scheduleId, 10));

    if (!deleted) {
      return res.status(404).json({ success: false, error: "Schedule not found" });
    }

    res.json({ success: true, message: "Schedule deleted" });
  } catch (error) {
    console.error("[AdvancedFeatures] Delete schedule error:", error);
    res.status(500).json({ success: false, error: "Failed to delete schedule" });
  }
}

export async function getMonitoringResults(req: PlanGatedRequest, res: Response) {
  try {
    const { scheduleId } = req.params;
    const limit = parseInt(req.query.limit as string, 10) || 10;

    const results = await monitoringService.getScheduleResults(parseInt(scheduleId, 10), limit);
    res.json({ success: true, data: results });
  } catch (error) {
    console.error("[AdvancedFeatures] Get results error:", error);
    res.status(500).json({ success: false, error: "Failed to get results" });
  }
}

export async function runManualMonitoringScan(req: PlanGatedRequest, res: Response) {
  try {
    const { scheduleId } = req.params;
    const result = await monitoringService.runScheduledScan(parseInt(scheduleId, 10));
    res.json({ success: true, data: result });
  } catch (error: any) {
    console.error("[AdvancedFeatures] Manual scan error:", error);
    res.status(400).json({ success: false, error: error.message || "Failed to run scan" });
  }
}

export async function getPhishingTemplates(req: Request, res: Response) {
  const templates = phishingService.getTemplates();
  res.json({ success: true, data: templates });
}

export async function createPhishingCampaign(req: PlanGatedRequest, res: Response) {
  try {
    const userId = req.userId!;

    const validation = insertPhishingCampaignSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({ success: false, error: validation.error.errors });
    }

    const campaign = await phishingService.createCampaign(userId, validation.data);
    res.json({ success: true, data: campaign });
  } catch (error) {
    console.error("[AdvancedFeatures] Create campaign error:", error);
    res.status(500).json({ success: false, error: "Failed to create campaign" });
  }
}

export async function getPhishingCampaigns(req: PlanGatedRequest, res: Response) {
  try {
    const userId = req.userId!;
    const campaigns = await phishingService.getUserCampaigns(userId);
    res.json({ success: true, data: campaigns });
  } catch (error) {
    console.error("[AdvancedFeatures] Get campaigns error:", error);
    res.status(500).json({ success: false, error: "Failed to get campaigns" });
  }
}

export async function getPhishingCampaign(req: PlanGatedRequest, res: Response) {
  try {
    const { campaignId } = req.params;
    const campaign = await phishingService.getCampaign(parseInt(campaignId, 10));

    if (!campaign) {
      return res.status(404).json({ success: false, error: "Campaign not found" });
    }

    res.json({ success: true, data: campaign });
  } catch (error) {
    console.error("[AdvancedFeatures] Get campaign error:", error);
    res.status(500).json({ success: false, error: "Failed to get campaign" });
  }
}

export async function launchPhishingCampaign(req: PlanGatedRequest, res: Response) {
  try {
    const { campaignId } = req.params;
    const campaign = await phishingService.launchCampaign(parseInt(campaignId, 10));
    res.json({ success: true, data: campaign });
  } catch (error: any) {
    console.error("[AdvancedFeatures] Launch campaign error:", error);
    res.status(400).json({ success: false, error: error.message || "Failed to launch campaign" });
  }
}

export async function getPhishingCampaignStats(req: PlanGatedRequest, res: Response) {
  try {
    const { campaignId } = req.params;
    const stats = await phishingService.getCampaignStats(parseInt(campaignId, 10));
    res.json({ success: true, data: stats });
  } catch (error) {
    console.error("[AdvancedFeatures] Get stats error:", error);
    res.status(500).json({ success: false, error: "Failed to get campaign stats" });
  }
}

export async function deletePhishingCampaign(req: PlanGatedRequest, res: Response) {
  try {
    const { campaignId } = req.params;
    const deleted = await phishingService.deleteCampaign(parseInt(campaignId, 10));

    if (!deleted) {
      return res.status(404).json({ success: false, error: "Campaign not found" });
    }

    res.json({ success: true, message: "Campaign deleted" });
  } catch (error) {
    console.error("[AdvancedFeatures] Delete campaign error:", error);
    res.status(500).json({ success: false, error: "Failed to delete campaign" });
  }
}

export async function getFeatureAccess(req: PlanGatedRequest, res: Response) {
  try {
    const userId = req.userId!;
    const credits = await storage.getUserCredits(userId);
    const planLevel = credits.planLevel as PlanLevel;

    const { PLAN_FEATURE_CONFIGS } = await import("@shared/schema");
    const features = PLAN_FEATURE_CONFIGS[planLevel];

    res.json({
      success: true,
      planLevel,
      features: features.allowedFeatures,
      agents: features.allowedAgents,
      monitoringFrequency: features.monitoringFrequency,
      maxScansPerMonth: features.maxScansPerMonth,
    });
  } catch (error) {
    console.error("[AdvancedFeatures] Get feature access error:", error);
    res.status(500).json({ success: false, error: "Failed to get feature access" });
  }
}
