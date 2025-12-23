import type { Request, Response } from "express";
import { storage } from "../../storage";

export async function getReports(req: Request, res: Response) {
  try {
    const reports = await storage.getReports();
    res.json(reports);
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).json({ error: "Failed to fetch reports" });
  }
}

export async function getReport(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const report = await storage.getReport(id);
    if (!report) {
      return res.status(404).json({ error: "Report not found" });
    }
    res.json(report);
  } catch (error) {
    console.error("Error fetching report:", error);
    res.status(500).json({ error: "Failed to fetch report" });
  }
}

export async function createReportFromScan(req: Request, res: Response) {
  try {
    const { scanId } = req.body;
    if (!scanId) {
      return res.status(400).json({ error: "scanId is required" });
    }
    
    const report = await storage.createReportFromScan(scanId);
    if (!report) {
      return res.status(400).json({ error: "Cannot create report. Scan not found or not complete." });
    }
    
    res.status(201).json(report);
  } catch (error) {
    console.error("Error creating report:", error);
    res.status(500).json({ error: "Failed to create report" });
  }
}
