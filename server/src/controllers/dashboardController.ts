import type { Request, Response } from "express";
import { storage } from "../../storage";

export async function getDashboardMetrics(req: Request, res: Response) {
  try {
    const [projects, scans, reports] = await Promise.all([
      storage.getAllProjects(),
      storage.getAllScans(),
      storage.getReports(),
    ]);
    
    const avgScore = projects.length > 0 
      ? Math.round(projects.reduce((sum, p) => sum + p.securityScore, 0) / projects.length)
      : 0;
    
    const activeScans = scans.filter(s => s.status === "running" || s.status === "pending");
    const completedScans = scans.filter(s => s.status === "complete");
    
    const totalVulnerabilities = reports.reduce((sum, r) => sum + r.vulnerabilities, 0);
    
    res.json({
      securityScore: avgScore,
      totalProjects: projects.length,
      activeScans: activeScans.length,
      completedScans: completedScans.length,
      totalScans: scans.length,
      totalVulnerabilities,
      totalReports: reports.length,
    });
  } catch (error) {
    console.error("Error fetching dashboard metrics:", error);
    res.status(500).json({ error: "Failed to fetch dashboard metrics" });
  }
}

export async function getRecentVulnerabilities(req: Request, res: Response) {
  try {
    const reports = await storage.getReports();
    const vulnerabilities: Array<{
      id: string;
      title: string;
      severity: string;
      project: string;
      date: string;
    }> = [];
    
    for (const report of reports) {
      if (report.details?.vulnerabilities) {
        for (const vuln of report.details.vulnerabilities) {
          vulnerabilities.push({
            id: vuln.id,
            title: vuln.title,
            severity: vuln.severity,
            project: report.projectName,
            date: report.date,
          });
        }
      }
    }
    
    res.json(vulnerabilities.slice(0, 10));
  } catch (error) {
    console.error("Error fetching vulnerabilities:", error);
    res.status(500).json({ error: "Failed to fetch vulnerabilities" });
  }
}
