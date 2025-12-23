import { Request, Response } from "express";
import { insertCSPMScanSchema, type CSPMScanRequest } from "@shared/cspm";
import { runCSPMScan, validateCSPMScan } from "../services/cspm";
import { storage } from "../../storage";

export async function startCSPMScan(req: Request, res: Response) {
  try {
    const validatedData = insertCSPMScanSchema.parse(req.body);
    const userId = req.headers["x-user-id"] as string || "default-user";
    
    const userCredits = await storage.getUserCredits(userId);
    const validation = await validateCSPMScan(userId, userCredits.planLevel);
    
    if (!validation.valid) {
      return res.status(402).json({
        success: false,
        error: validation.error,
        estimatedCost: validation.estimatedCost,
        currentBalance: validation.currentBalance,
      });
    }
    
    const request: CSPMScanRequest = {
      projectId: validatedData.projectId,
      provider: validatedData.provider,
      regions: validatedData.regions,
      categories: validatedData.categories,
      includeRemediation: validatedData.includeRemediation,
    };
    
    const result = await runCSPMScan(request, userId, (progress) => {
      console.log(`CSPM Scan progress: ${progress}%`);
    });
    
    res.json({
      success: true,
      data: result,
    });
  } catch (error: unknown) {
    console.error("CSPM scan error:", error);
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({
      success: false,
      error: message,
    });
  }
}

export async function getCSPMCost(req: Request, res: Response) {
  try {
    const userId = req.headers["x-user-id"] as string || "default-user";
    const userCredits = await storage.getUserCredits(userId);
    const validation = await validateCSPMScan(userId, userCredits.planLevel);
    
    res.json({
      estimatedCost: validation.estimatedCost,
      currentBalance: validation.currentBalance,
      canRun: validation.valid,
      planLevel: userCredits.planLevel,
    });
  } catch (error: unknown) {
    console.error("CSPM cost check error:", error);
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({
      success: false,
      error: message,
    });
  }
}

export async function getProviderMisconfigurations(req: Request, res: Response) {
  const { provider } = req.params;
  
  if (!["aws", "azure", "gcp"].includes(provider)) {
    return res.status(400).json({
      success: false,
      error: "Invalid provider. Must be aws, azure, or gcp.",
    });
  }
  
  const { AWS_MISCONFIGURATIONS, AZURE_MISCONFIGURATIONS, GCP_MISCONFIGURATIONS } = await import("@shared/cspm");
  
  let templates;
  switch (provider) {
    case "aws":
      templates = AWS_MISCONFIGURATIONS;
      break;
    case "azure":
      templates = AZURE_MISCONFIGURATIONS;
      break;
    case "gcp":
      templates = GCP_MISCONFIGURATIONS;
      break;
    default:
      templates = [];
  }
  
  res.json({
    provider,
    totalChecks: templates.length,
    checks: templates.map(t => ({
      checkId: t.checkId,
      title: t.title,
      severity: t.severity,
      category: t.category,
      resourceType: t.resourceType,
      complianceFrameworks: t.complianceFrameworks,
      benchmarkId: t.benchmarkId,
    })),
  });
}
