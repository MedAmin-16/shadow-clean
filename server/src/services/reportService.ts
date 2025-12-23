import PDFDocument from "pdfkit";
import { createWriteStream, existsSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { randomUUID } from "crypto";
import type { ScanReport } from "../types";
import { createLogger } from "../utils/logger";
import type {
  EnhancedReporterOutput,
  FinancialRiskAssessment,
  AudienceSpecificSummary,
  RemediationSnippet,
  ExploitationEvidence,
  PlanLevel
} from "@shared/schema";
import type { AutonomousDefenseResult } from "@shared/level7";

const logger = createLogger("report");

const reports = new Map<string, ScanReport>();
const REPORTS_DIR = join(process.cwd(), "reports");

if (!existsSync(REPORTS_DIR)) {
  mkdirSync(REPORTS_DIR, { recursive: true });
}

export interface CreateReportInput {
  jobId: string;
  userId: string;
  target: string;
  result: Record<string, unknown>;
}

export async function createReport(input: CreateReportInput): Promise<ScanReport> {
  const report: ScanReport = {
    id: randomUUID(),
    jobId: input.jobId,
    userId: input.userId,
    target: input.target,
    result: input.result,
    pdfPath: null,
    createdAt: new Date(),
  };

  reports.set(report.id, report);
  logger.info(`Report created: ${report.id}`);
  return report;
}

export async function getReport(id: string): Promise<ScanReport | null> {
  return reports.get(id) || null;
}

export async function getReportByJobId(jobId: string): Promise<ScanReport | null> {
  const allReports = Array.from(reports.values());
  for (const report of allReports) {
    if (report.jobId === jobId) {
      return report;
    }
  }
  return null;
}

export async function getReportsByUser(userId: string): Promise<ScanReport[]> {
  return Array.from(reports.values())
    .filter((r) => r.userId === userId)
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
}

function addHeader(doc: PDFKit.PDFDocument, title: string) {
  doc.rect(0, 0, doc.page.width, 80).fill("#1e3a5f");
  doc.fontSize(28).fillColor("#ffffff").text(title, 50, 30);
  doc.moveDown(3);
}

function addSectionTitle(doc: PDFKit.PDFDocument, title: string) {
  doc.moveDown(0.5);
  doc.fontSize(16).fillColor("#1e3a5f").text(title);
  doc.moveTo(50, doc.y).lineTo(doc.page.width - 50, doc.y).stroke("#1e3a5f");
  doc.moveDown(0.5);
}

function addKeyMetric(doc: PDFKit.PDFDocument, label: string, value: string, color = "#374151") {
  doc.fontSize(11).fillColor("#6b7280").text(`${label}: `, { continued: true });
  doc.fillColor(color).text(value);
}

export async function generateExecutivePdf(
  reportId: string,
  reporterData: EnhancedReporterOutput,
  target: string,
  autonomousDefenseData?: AutonomousDefenseResult
): Promise<string | null> {
  const pdfPath = join(REPORTS_DIR, `${reportId}_executive.pdf`);

  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50, size: "A4" });
      const stream = createWriteStream(pdfPath);
      doc.pipe(stream);

      addHeader(doc, "SHADOWTWIN SECURITY REPORT");
      
      doc.fontSize(12).fillColor("#6b7280").text(`Executive Summary`, 50, 100);
      doc.fontSize(10).fillColor("#9ca3af").text(`Generated: ${new Date().toLocaleDateString()} | Target: ${target}`);
      doc.moveDown(2);

      doc.rect(50, doc.y, doc.page.width - 100, 80).fill("#f0f9ff");
      const scoreY = doc.y + 20;
      doc.fontSize(48).fillColor(reporterData.securityScore >= 70 ? "#059669" : reporterData.securityScore >= 50 ? "#d97706" : "#dc2626")
        .text(`${reporterData.securityScore}`, 80, scoreY);
      doc.fontSize(14).fillColor("#374151").text("/100", 150, scoreY + 30);
      doc.fontSize(12).fillColor("#6b7280").text("Security Score", 80, scoreY + 50);
      
      const statsX = 250;
      doc.fontSize(11).fillColor("#374151");
      doc.text(`Total Vulnerabilities: ${reporterData.totalVulnerabilities}`, statsX, scoreY);
      doc.fillColor("#dc2626").text(`Critical: ${reporterData.criticalCount}`, statsX, scoreY + 15);
      doc.fillColor("#ea580c").text(`High: ${reporterData.highCount}`, statsX, scoreY + 30);
      doc.fillColor("#ca8a04").text(`Medium: ${reporterData.mediumCount}`, statsX, scoreY + 45);
      doc.fillColor("#16a34a").text(`Low: ${reporterData.lowCount}`, statsX, scoreY + 60);
      
      doc.y = scoreY + 100;

      if (reporterData.planLevel === "ELITE" && reporterData.financialRiskAssessments) {
        addSectionTitle(doc, "FINANCIAL RISK EXPOSURE");
        
        const totalMin = reporterData.totalEstimatedRiskMin || 0;
        const totalMax = reporterData.totalEstimatedRiskMax || 0;
        
        doc.fontSize(14).fillColor("#dc2626")
          .text(`Estimated Loss Range: $${totalMin.toLocaleString()} - $${totalMax.toLocaleString()}`);
        doc.moveDown(0.5);
        doc.fontSize(10).fillColor("#6b7280")
          .text("This represents potential financial impact including incident response, legal fees, regulatory fines, and reputation damage.");
        doc.moveDown();

        const topRisks = reporterData.financialRiskAssessments.slice(0, 5);
        for (const risk of topRisks) {
          const severityColor = risk.severity === "critical" ? "#dc2626" : 
                               risk.severity === "high" ? "#ea580c" : 
                               risk.severity === "medium" ? "#ca8a04" : "#16a34a";
          doc.fontSize(10).fillColor(severityColor)
            .text(`• ${risk.vulnerabilityTitle}`, { continued: true });
          doc.fillColor("#374151")
            .text(` - $${risk.estimatedLossMin.toLocaleString()} to $${risk.estimatedLossMax.toLocaleString()}`);
        }
      }

      if (reporterData.industryBenchmark) {
        addSectionTitle(doc, "INDUSTRY BENCHMARKING");
        const bench = reporterData.industryBenchmark;
        
        doc.fontSize(11).fillColor("#374151");
        addKeyMetric(doc, "Industry", bench.industryName);
        addKeyMetric(doc, "Your Percentile", `${bench.companyPercentile}th`, bench.companyPercentile >= 75 ? "#059669" : "#d97706");
        addKeyMetric(doc, "Industry Average Score", `${bench.averageSecurityScore}/100`);
        addKeyMetric(doc, "Top Performer Score", `${bench.topPerformerScore}/100`);
        doc.moveDown(0.5);
        doc.fontSize(10).fillColor("#6b7280").text(`Compliance Standards: ${bench.complianceStandards.join(", ")}`);
      }

      if (reporterData.securityStatusHistory) {
        addSectionTitle(doc, "LIABILITY STATUS");
        const history = reporterData.securityStatusHistory;
        
        addKeyMetric(doc, "Last Full Scan", new Date(history.lastFullScanDate).toLocaleDateString());
        addKeyMetric(doc, "Pending Remediations", `${history.pendingRemediations}`, history.pendingRemediations > 0 ? "#dc2626" : "#059669");
        addKeyMetric(doc, "Confirmed Remediations", `${history.confirmedRemediations}`);
      }

      if (reporterData.planLevel === "ELITE" && autonomousDefenseData) {
        addSectionTitle(doc, "AGENT 7 ORCHESTRATOR - EXECUTIVE SUMMARY");
        
        const protectionScore = (autonomousDefenseData.overallProtectionScore * 100).toFixed(1);
        const riskReduction = (autonomousDefenseData.estimatedRiskReduction * 100).toFixed(1);
        
        const boxStartY = doc.y;
        doc.rect(50, boxStartY, doc.page.width - 100, 120).fill("#f0fdf4");
        
        doc.y = boxStartY + 15;
        doc.fontSize(12).fillColor("#059669").text("Autonomous Defense Orchestration", 60);
        doc.moveDown(0.5);
        
        doc.fontSize(10).fillColor("#374151");
        doc.text(`Vulnerabilities Protected: ${autonomousDefenseData.vulnerabilitiesProtected}`, 60);
        const coverageColor = parseFloat(protectionScore) >= 80 ? "#059669" : "#d97706";
        doc.fillColor(coverageColor).text(`Protection Coverage: ${protectionScore}%`, 60);
        const reductionColor = parseFloat(riskReduction) >= 50 ? "#059669" : "#d97706";
        doc.fillColor(reductionColor).text(`Estimated Risk Reduction: ${riskReduction}%`, 60);
        doc.fillColor("#374151").text(`Hotfixes Deployed: ${autonomousDefenseData.hotfixesDeployed?.length || 0}`, 60);
        const integrations = autonomousDefenseData.integrationsUsed?.map(i => i.name).join(", ") || "None";
        doc.text(`Integrations Used: ${integrations}`, 60);
        
        doc.y = boxStartY + 130;
        
        if (autonomousDefenseData.manualHotfixRules && autonomousDefenseData.manualHotfixRules.length > 0) {
          doc.fontSize(10).fillColor("#d97706")
            .text(`Manual Review Required: ${autonomousDefenseData.manualHotfixRules.length} hotfix rules provided for manual deployment`);
          doc.moveDown(0.5);
        }
        
        doc.fontSize(10).fillColor("#6b7280")
          .text("Agent 7 coordinates with Agent 3 (Exploitation) and Agent 5 (Causal Prophet) to deliver automated defense recommendations and ROI-justified remediation priorities.");
        doc.moveDown();
      }

      addSectionTitle(doc, "RECOMMENDATIONS");
      doc.fontSize(10).fillColor("#374151");
      reporterData.recommendations.slice(0, 5).forEach((rec, index) => {
        doc.text(`${index + 1}. ${rec}`);
      });

      doc.moveDown(2);
      doc.fontSize(8).fillColor("#9ca3af").text(
        `Generated by ShadowTwin Security Platform | Model: ${reporterData.llmModelUsed} | Plan: ${reporterData.planLevel}`,
        { align: "center" }
      );

      doc.end();

      stream.on("finish", () => {
        logger.info(`Executive PDF generated: ${pdfPath}`);
        resolve(pdfPath);
      });

      stream.on("error", (error) => {
        logger.error("Executive PDF generation failed", { error: String(error) });
        reject(error);
      });
    } catch (error) {
      logger.error("Executive PDF generation failed", { error: String(error) });
      reject(error);
    }
  });
}

export async function generateTechnicalPdf(
  reportId: string,
  reporterData: EnhancedReporterOutput,
  target: string,
  scannerVulnerabilities: Array<{ id: string; title: string; severity: string; description: string; cve?: string }>
): Promise<string | null> {
  const pdfPath = join(REPORTS_DIR, `${reportId}_technical.pdf`);

  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50, size: "A4" });
      const stream = createWriteStream(pdfPath);
      doc.pipe(stream);

      addHeader(doc, "TECHNICAL SECURITY REPORT");
      
      doc.fontSize(12).fillColor("#6b7280").text(`Detailed Vulnerability Analysis`, 50, 100);
      doc.fontSize(10).fillColor("#9ca3af").text(`Target: ${target} | Generated: ${new Date().toISOString()}`);
      doc.moveDown(2);

      addSectionTitle(doc, "VULNERABILITY DETAILS");
      
      for (const vuln of scannerVulnerabilities) {
        const severityColor = vuln.severity === "critical" ? "#dc2626" : 
                             vuln.severity === "high" ? "#ea580c" : 
                             vuln.severity === "medium" ? "#ca8a04" : 
                             vuln.severity === "low" ? "#16a34a" : "#6b7280";
        
        doc.rect(50, doc.y, doc.page.width - 100, 20).fill(severityColor);
        doc.fontSize(11).fillColor("#ffffff").text(`${vuln.severity.toUpperCase()}: ${vuln.title}`, 55, doc.y + 5);
        doc.y += 25;
        
        doc.fontSize(10).fillColor("#374151");
        if (vuln.cve) {
          doc.text(`CVE: ${vuln.cve}`);
        }
        doc.text(vuln.description, { width: doc.page.width - 100 });
        doc.moveDown();
      }

      if (reporterData.exploitationEvidence && reporterData.exploitationEvidence.length > 0) {
        doc.addPage();
        addSectionTitle(doc, "EXPLOITATION EVIDENCE");
        
        for (const evidence of reporterData.exploitationEvidence) {
          doc.fontSize(11).fillColor(evidence.success ? "#dc2626" : "#059669")
            .text(`${evidence.success ? "✓ EXPLOITED" : "✗ Not Exploited"}: ${evidence.exploitTechnique}`);
          
          if (evidence.logSnippet) {
            doc.fontSize(9).fillColor("#6b7280").font("Courier")
              .text(evidence.logSnippet, { width: doc.page.width - 100 });
            doc.font("Helvetica");
          }
          doc.moveDown(0.5);
        }
      }

      if (reporterData.remediationSnippets && reporterData.remediationSnippets.length > 0) {
        doc.addPage();
        addSectionTitle(doc, "REMEDIATION CODE SNIPPETS");
        
        for (const snippet of reporterData.remediationSnippets.slice(0, 10)) {
          doc.fontSize(11).fillColor("#1e3a5f").text(`${snippet.vulnerabilityTitle}`);
          doc.fontSize(9).fillColor("#6b7280").text(`Language: ${snippet.language} | Effort: ${snippet.estimatedEffort}`);
          
          doc.rect(50, doc.y + 5, doc.page.width - 100, 60).fill("#f3f4f6");
          doc.fontSize(8).fillColor("#374151").font("Courier")
            .text(snippet.codeSnippet.slice(0, 300), 55, doc.y + 10, { width: doc.page.width - 110 });
          doc.font("Helvetica");
          doc.y += 70;
          
          doc.fontSize(9).fillColor("#374151").text(`Implementation: ${snippet.implementation}`);
          doc.moveDown();
        }
      }

      doc.moveDown(2);
      doc.fontSize(8).fillColor("#9ca3af").text(
        `ShadowTwin Technical Report | Confidential | ${reporterData.planLevel} Tier`,
        { align: "center" }
      );

      doc.end();

      stream.on("finish", () => {
        logger.info(`Technical PDF generated: ${pdfPath}`);
        resolve(pdfPath);
      });

      stream.on("error", (error) => {
        logger.error("Technical PDF generation failed", { error: String(error) });
        reject(error);
      });
    } catch (error) {
      logger.error("Technical PDF generation failed", { error: String(error) });
      reject(error);
    }
  });
}

export interface RawDataExport {
  jsonPath: string;
  csvPath: string;
}

export async function generateRawDataExport(
  reportId: string,
  reporterData: EnhancedReporterOutput,
  scannerData: Record<string, unknown>,
  exploiterData: Record<string, unknown>
): Promise<RawDataExport> {
  const jsonPath = join(REPORTS_DIR, `${reportId}_data.json`);
  const csvPath = join(REPORTS_DIR, `${reportId}_vulnerabilities.csv`);

  const exportData = {
    reportId,
    generatedAt: reporterData.generatedAt,
    planLevel: reporterData.planLevel,
    llmModelUsed: reporterData.llmModelUsed,
    summary: {
      securityScore: reporterData.securityScore,
      totalVulnerabilities: reporterData.totalVulnerabilities,
      criticalCount: reporterData.criticalCount,
      highCount: reporterData.highCount,
      mediumCount: reporterData.mediumCount,
      lowCount: reporterData.lowCount,
    },
    financialRisk: reporterData.financialRiskAssessments ? {
      totalEstimatedRiskMin: reporterData.totalEstimatedRiskMin,
      totalEstimatedRiskMax: reporterData.totalEstimatedRiskMax,
      annualizedRiskExposure: reporterData.annualizedRiskExposure,
      assessments: reporterData.financialRiskAssessments,
    } : null,
    industryBenchmark: reporterData.industryBenchmark,
    recommendations: reporterData.recommendations,
    exploitationEvidence: reporterData.exploitationEvidence,
    remediationSnippets: reporterData.remediationSnippets,
    securityStatusHistory: reporterData.securityStatusHistory,
    rawScannerData: scannerData,
    rawExploiterData: exploiterData,
  };

  writeFileSync(jsonPath, JSON.stringify(exportData, null, 2));
  logger.info(`JSON export generated: ${jsonPath}`);

  const vulnerabilities = (scannerData.vulnerabilities as Array<Record<string, unknown>>) || [];
  const csvHeader = "ID,Title,Severity,Description,CVE,Port,Service\n";
  const csvRows = vulnerabilities.map((v) => 
    `"${v.id || ""}","${String(v.title || "").replace(/"/g, '""')}","${v.severity || ""}","${String(v.description || "").replace(/"/g, '""').slice(0, 200)}","${v.cve || ""}","${v.port || ""}","${v.service || ""}"`
  ).join("\n");
  
  writeFileSync(csvPath, csvHeader + csvRows);
  logger.info(`CSV export generated: ${csvPath}`);

  return { jsonPath, csvPath };
}

export async function generatePdfReport(reportId: string): Promise<string | null> {
  const report = reports.get(reportId);
  if (!report) {
    logger.error(`Report not found: ${reportId}`);
    return null;
  }

  const pdfPath = join(REPORTS_DIR, `${reportId}.pdf`);

  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50 });
      const stream = createWriteStream(pdfPath);

      doc.pipe(stream);

      doc.fontSize(24).fillColor("#6366f1").text("Security Scan Report", { align: "center" });
      doc.moveDown();

      doc.fontSize(12).fillColor("#374151");
      doc.text(`Report ID: ${report.id}`);
      doc.text(`Target: ${report.target}`);
      doc.text(`Generated: ${report.createdAt.toISOString()}`);
      doc.moveDown(2);

      doc.fontSize(18).fillColor("#1f2937").text("Executive Summary");
      doc.moveDown(0.5);
      doc.fontSize(11).fillColor("#4b5563");

      const result = report.result as Record<string, unknown>;
      const reporter = result.reporter as Record<string, unknown> | undefined;
      const reporterData = reporter?.data as Record<string, unknown> | undefined;

      if (reporterData?.executiveSummary) {
        doc.text(String(reporterData.executiveSummary));
      } else {
        doc.text("Scan completed. See detailed results below.");
      }
      doc.moveDown(2);

      doc.fontSize(18).fillColor("#1f2937").text("Vulnerability Summary");
      doc.moveDown(0.5);

      if (reporterData) {
        const criticalCount = reporterData.criticalCount || 0;
        const highCount = reporterData.highCount || 0;
        const mediumCount = reporterData.mediumCount || 0;
        const lowCount = reporterData.lowCount || 0;
        const totalVulns = reporterData.totalVulnerabilities || 0;
        const securityScore = reporterData.securityScore || 0;

        doc.fontSize(11).fillColor("#4b5563");
        doc.text(`Total Vulnerabilities: ${totalVulns}`);
        doc.fillColor("#dc2626").text(`Critical: ${criticalCount}`);
        doc.fillColor("#ea580c").text(`High: ${highCount}`);
        doc.fillColor("#ca8a04").text(`Medium: ${mediumCount}`);
        doc.fillColor("#16a34a").text(`Low: ${lowCount}`);
        doc.moveDown();
        doc.fillColor("#6366f1").fontSize(14).text(`Security Score: ${securityScore}/100`);
      }
      doc.moveDown(2);

      doc.fontSize(18).fillColor("#1f2937").text("Recommendations");
      doc.moveDown(0.5);
      doc.fontSize(11).fillColor("#4b5563");

      if (reporterData?.recommendations && Array.isArray(reporterData.recommendations)) {
        (reporterData.recommendations as string[]).forEach((rec, index) => {
          doc.text(`${index + 1}. ${rec}`);
        });
      } else {
        doc.text("No specific recommendations at this time.");
      }
      doc.moveDown(2);

      doc.fontSize(10).fillColor("#9ca3af").text("Generated by ShadowTwin Security Scanner", { align: "center" });

      doc.end();

      stream.on("finish", () => {
        report.pdfPath = pdfPath;
        reports.set(reportId, report);
        logger.info(`PDF generated: ${pdfPath}`);
        resolve(pdfPath);
      });

      stream.on("error", (error) => {
        logger.error("PDF generation failed", { error: String(error) });
        reject(error);
      });
    } catch (error) {
      logger.error("PDF generation failed", { error: String(error) });
      reject(error);
    }
  });
}

export function getPdfPath(reportId: string): string | null {
  const report = reports.get(reportId);
  return report?.pdfPath || null;
}

export async function generateAllReportFormats(
  reportId: string,
  reporterData: EnhancedReporterOutput,
  target: string,
  scannerData: Record<string, unknown>,
  exploiterData: Record<string, unknown>,
  autonomousDefenseData?: AutonomousDefenseResult
): Promise<{ executivePdf?: string; technicalPdf?: string; jsonExport?: string; csvExport?: string }> {
  const result: { executivePdf?: string; technicalPdf?: string; jsonExport?: string; csvExport?: string } = {};

  try {
    if (reporterData.planLevel === "ELITE" || reporterData.planLevel === "STANDARD") {
      const execPdf = await generateExecutivePdf(reportId, reporterData, target, autonomousDefenseData);
      if (execPdf) result.executivePdf = execPdf;
    }

    if (reporterData.planLevel === "ELITE") {
      const vulns = (scannerData.vulnerabilities as Array<{ id: string; title: string; severity: string; description: string; cve?: string }>) || [];
      const techPdf = await generateTechnicalPdf(reportId, reporterData, target, vulns);
      if (techPdf) result.technicalPdf = techPdf;

      const rawExport = await generateRawDataExport(reportId, reporterData, scannerData, exploiterData);
      result.jsonExport = rawExport.jsonPath;
      result.csvExport = rawExport.csvPath;
    }
  } catch (error) {
    logger.error("Error generating report formats", { error: String(error) });
  }

  return result;
}
