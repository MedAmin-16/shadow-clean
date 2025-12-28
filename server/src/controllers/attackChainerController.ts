import type { Request, Response } from "express";
import type { PlanGatedRequest } from "../middlewares/planAccess";
import { attackChainerService } from "../services/attackChainer";

export async function getAttackChains(req: PlanGatedRequest, res: Response) {
  try {
    const { scanId } = req.params;
    const userId = req.userId!;

    if (!scanId) {
      return res.status(400).json({ success: false, error: "Scan ID is required" });
    }

    const chains = await attackChainerService.getAttackChainsForScan(scanId, userId);
    res.json({ success: true, data: chains, count: chains.length });
  } catch (error) {
    console.error("[AttackChainer] Error fetching attack chains:", error);
    res.status(500).json({ success: false, error: "Failed to fetch attack chains" });
  }
}

export async function correlateVulnerabilities(req: PlanGatedRequest, res: Response) {
  try {
    const { scanId } = req.body;
    const userId = req.userId!;

    if (!scanId) {
      return res.status(400).json({ success: false, error: "Scan ID is required" });
    }

    const chains = await attackChainerService.correlateVulnerabilities(scanId, userId);
    res.json({ success: true, data: chains, chainsFound: chains.length });
  } catch (error) {
    console.error("[AttackChainer] Error correlating vulnerabilities:", error);
    res.status(500).json({ success: false, error: "Failed to correlate vulnerabilities" });
  }
}
