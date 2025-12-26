import type { Response, Request } from "express";
import type { AuthenticatedRequest, ScanJobData } from "../types";
import { storage } from "../../storage";
import { insertScanSchema, scansTable, vulnerabilitiesTable } from "@shared/schema";
import { runSequentialScan, killScanProcess } from "../../agents/sequentialScan";
import { addScanJob, getJobStatus, getScanQueue } from "../queues/scanQueue";
import { getReportByJobId, getReportsByUser, generatePdfReport, getPdfPath, createReport } from "../services/reportService";
import { emitScanCompleted, emitInfoLog, emitStdoutLog, emitTerminalLog, emitToScan } from "../sockets/socketManager";
import { createLogger } from "../utils/logger";
import { db } from "../../db";
import { eq } from "drizzle-orm";
import { unlink } from "fs/promises";
import { glob } from "glob";

const logger = createLogger("controller");

export async function stopScan(req: Request, res: Response): Promise<void> {
  const { id } = req.params;
  try {
    const scan = await storage.getScan(id);
    if (!scan) {
      res.status(404).json({ error: "Scan not found" });
      return;
    }
    killScanProcess(id);
    await storage.updateScan(id, { 
      status: "failed",
      error: "Scan force-stopped by user",
      completedAt: new Date()
    });
    await db.update(vulnerabilitiesTable)
      .set({ isArchived: true })
      .where(eq(vulnerabilitiesTable.scanId, id));
    const tempFiles = await glob(`/tmp/*${id}*`);
    for (const file of tempFiles) {
      try { await unlink(file); } catch (e) {}
    }
    emitTerminalLog(id, {
      id: `sys-stop-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: "info",
      message: "[SYSTEM] Scan force-stopped by user. Process tree terminated and temp files cleared.",
      isAiLog: false,
    });
    emitToScan(id, "scan:stopped", { scanId: id });
    res.json({ success: true, message: "Scan stopped successfully" });
  } catch (error) {
    logger.error("[STOP-SCAN] Error:", { error: String(error) });
    res.status(500).json({ error: "Failed to stop scan" });
  }
}

export async function rescanTarget(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const oldScan = await storage.getScan(id);
    if (!oldScan) {
      res.status(404).json({ error: "Original scan not found" });
      return;
    }
    const newScan = await storage.createScan({
      target: oldScan.target,
      userId: oldScan.userId,
    });
    res.status(201).json({ id: newScan.id, message: "Re-scan initialized" });
  } catch (error) {
    logger.error("Error re-scanning target", { error: String(error) });
    res.status(500).json({ error: "Failed to re-scan target" });
  }
}

export async function exportScanHistory(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    const scans = await storage.getAllScans();
    const format = req.query.format === 'csv' ? 'csv' : 'json';
    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename=scan-history.json');
      res.send(JSON.stringify(scans, null, 2));
    } else {
      const headers = "ID,Target,Status,StartedAt,CompletedAt\n";
      const rows = scans.map(s => `${s.id},${s.target},${s.status},${s.startedAt},${s.completedAt}`).join("\n");
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=scan-history.csv');
      res.send(headers + rows);
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to export data" });
  }
}

export async function startScan(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.userId) {
      res.status(401).json({ error: "Authentication required to start a scan" });
      return;
    }
    const userId = req.userId;
    const parseResult = insertScanSchema.safeParse({ ...req.body, userId });
    if (!parseResult.success) {
      res.status(400).json({ error: "Invalid request", details: parseResult.error.errors });
      return;
    }
    const scan = await storage.createScan(parseResult.data);
    const jobData: ScanJobData = { jobId: scan.id, target: scan.target, options: req.body.options || {}, userId };
    const queueJobId = await addScanJob(jobData);
    if (!queueJobId) {
      const scanId = scan.id;
      const scanTarget = scan.target;
      const scanUserId = userId;
      emitInfoLog(scanId, `Scan created for target: ${scanTarget}`);
      emitStdoutLog(scanId, `[SYSTEM] Pipeline starting...`);
      emitStdoutLog(scanId, `[REAL-TIME]: Initializing scan pipeline for ${scanTarget}...`);
      (async () => {
        try {
          await new Promise(resolve => setTimeout(resolve, 2000));
          await storage.updateScan(scanId, { status: 'running', progress: 5 });
          await runSequentialScan(scanId, scanTarget);
          const completedScan = await storage.getScan(scanId);
          if (completedScan) {
            const report = await createReport({ jobId: scanId, userId: scanUserId, target: scanTarget, result: completedScan.agentResults as Record<string, unknown> });
            if (report) await generatePdfReport(report.id);
            emitScanCompleted({ jobId: scanId, userId: scanUserId, target: scanTarget, status: "completed", result: completedScan.agentResults as Record<string, unknown> });
          }
        } catch (err) {
          logger.error(`Scan ${scanId} failed:`, { error: String(err) });
          await storage.updateScan(scanId, { status: "failed", error: String(err) });
          emitScanCompleted({ jobId: scanId, userId: scanUserId, target: scanTarget, status: "failed", error: String(err) });
        }
      })();
    }
    res.status(201).json({ id: scan.id, jobId: scan.id, status: "pending", message: queueJobId ? "Scan queued for processing" : "Scan started" });
  } catch (error) {
    logger.error("Error creating scan", { error: String(error) });
    res.status(500).json({ error: "Failed to create scan" });
  }
}

export async function getScanStatus(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const queueStatus = await getJobStatus(id);
    const scan = await storage.getScan(id);
    if (!scan && !queueStatus) {
      res.status(404).json({ error: "Scan not found" });
      return;
    }
    res.json({ id, scanStatus: scan?.status || "unknown", queueStatus: queueStatus?.status, progress: queueStatus?.progress || scan?.progress || 0, currentAgent: scan?.currentAgent, result: scan?.agentResults });
  } catch (error) {
    logger.error("Error fetching scan status", { error: String(error) });
    res.status(500).json({ error: "Failed to fetch scan status" });
  }
}

export async function getAllScans(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    const scans = await storage.getAllScans();
    res.json(scans);
  } catch (error) {
    logger.error("Error fetching scans", { error: String(error) });
    res.status(500).json({ error: "Failed to fetch scans" });
  }
}

export async function getScanById(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    const scan = await storage.getScan(req.params.id);
    if (!scan) {
      res.status(404).json({ error: "Scan not found" });
      return;
    }
    res.json(scan);
  } catch (error) {
    logger.error("Error fetching scan", { error: String(error) });
    res.status(500).json({ error: "Failed to fetch scan" });
  }
}

export async function deleteScan(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    const deleted = await storage.deleteScan(req.params.id);
    if (!deleted) {
      res.status(404).json({ error: "Scan not found" });
      return;
    }
    res.status(204).send();
  } catch (error) {
    logger.error("Error deleting scan", { error: String(error) });
    res.status(500).json({ error: "Failed to delete scan" });
  }
}

export async function downloadReport(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.userId) {
      res.status(401).json({ error: "Authentication required to download reports" });
      return;
    }
    const { id } = req.params;
    let report = await getReportByJobId(id);
    if (!report) {
      const scan = await storage.getScan(id);
      if (!scan) {
        res.status(404).json({ error: "Scan not found" });
        return;
      }
      report = await createReport({ jobId: id, userId: req.userId!, target: scan.target, result: scan.agentResults as Record<string, unknown> });
    }
    if (!report.pdfPath) await generatePdfReport(report.id);
    const pdfPath = getPdfPath(report.id);
    if (!pdfPath) {
      res.status(500).json({ error: "Failed to generate PDF" });
      return;
    }
    res.download(pdfPath, `scan-report-${id}.pdf`);
  } catch (error) {
    logger.error("Error downloading report", { error: String(error) });
    res.status(500).json({ error: "Failed to download report" });
  }
}

export async function getScanHistory(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    const { userId } = req.params;
    if (req.userId && req.userId !== userId) {
      res.status(403).json({ error: "Access denied" });
      return;
    }
    const reports = await getReportsByUser(userId);
    res.json(reports.map((r) => ({ id: r.id, jobId: r.jobId, target: r.target, createdAt: r.createdAt, hasPdf: !!r.pdfPath })));
  } catch (error) {
    logger.error("Error fetching scan history", { error: String(error) });
    res.status(500).json({ error: "Failed to fetch scan history" });
  }
}
