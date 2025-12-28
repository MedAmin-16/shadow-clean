import type { Request, Response } from "express";
import type { PlanGatedRequest } from "../middlewares/planAccess";
import { attackChainerService } from "../services/attackChainer";
import { executiveReportService } from "../services/executiveReportService";
import { db } from "../../db";
import { scansTable } from "@shared/schema";
import { eq } from "drizzle-orm";

export async function generateExecutiveReport(req: PlanGatedRequest, res: Response) {
  try {
    const { scanId } = req.params;
    const userId = req.userId!;

    if (!scanId) {
      return res.status(400).json({ success: false, error: "Scan ID is required" });
    }

    // Get scan details
    const scan = await db.select().from(scansTable).where(eq(scansTable.id, scanId)).limit(1);

    if (!scan || scan.length === 0) {
      return res.status(404).json({ success: false, error: "Scan not found" });
    }

    // Get attack chains
    const chains = await attackChainerService.getAttackChainsForScan(scanId, userId);

    const criticalChains = chains.filter(c => c.severity === "critical");
    const highChains = chains.filter(c => c.severity === "high");
    const mediumChains = chains.filter(c => c.severity === "medium");

    // Generate PDF
    const pdfBuffer = await executiveReportService.generateExecutiveReport({
      scanId,
      scanDate: new Date(scan[0].startedAt || new Date()),
      totalChains: chains.length,
      criticalChains,
      highChains,
      mediumChains,
    });

    // Send as downloadable file
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="executive-risk-report-${scanId.substring(0, 8)}.pdf"`);
    res.setHeader("Content-Length", pdfBuffer.length);

    res.send(pdfBuffer);
  } catch (error) {
    console.error("[ExecutiveReport] Error generating report:", error);
    res.status(500).json({ success: false, error: "Failed to generate executive report" });
  }
}

export const exportExecutiveReport = generateExecutiveReport;
