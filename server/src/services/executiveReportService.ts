import PDFDocument from "pdfkit";
import type { AttackChain } from "./attackChainer";

interface ExecutiveReportData {
  scanId: string;
  scanDate: Date;
  totalChains: number;
  criticalChains: AttackChain[];
  highChains: AttackChain[];
  mediumChains: AttackChain[];
}

export async function generateExecutiveReport(data: ExecutiveReportData): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      margin: 50,
    });

    const buffers: Buffer[] = [];

    doc.on("data", (chunk: Buffer) => {
      buffers.push(chunk);
    });

    doc.on("end", () => {
      resolve(Buffer.concat(buffers));
    });

    doc.on("error", reject);

    // Header
    doc.fontSize(28).font("Helvetica-Bold").text("EXECUTIVE RISK REPORT", { align: "center" });
    doc.fontSize(11).text("Cybersecurity Vulnerability Assessment Summary", { align: "center" });
    doc.moveDown(0.5);

    // Date and Scan Info
    const reportDate = new Date().toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
    doc.fontSize(10).text(`Report Generated: ${reportDate}`, { align: "right" });
    doc.text(`Scan ID: ${data.scanId.substring(0, 8)}...`, { align: "right" });
    doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
    doc.moveDown(1);

    // Executive Summary Box
    doc.fontSize(14).font("Helvetica-Bold").text("EXECUTIVE SUMMARY", { underline: true });
    doc.moveDown(0.3);
    doc.fontSize(10).font("Helvetica");

    const criticalCount = data.criticalChains.length;
    const highCount = data.highChains.length;

    if (criticalCount === 0 && highCount === 0) {
      doc.text(
        "Your organization has achieved a strong security posture with no critical or high-severity vulnerability chains detected. Continue monitoring for emerging threats.",
        { align: "left", width: 445 }
      );
    } else {
      doc.text(
        `Your organization faces ${criticalCount} CRITICAL and ${highCount} HIGH-severity vulnerability chains that require immediate remediation to prevent potential data breaches and regulatory violations.`,
        { align: "left", width: 445 }
      );
    }

    doc.moveDown(1);

    // Financial Exposure
    doc.fontSize(12).font("Helvetica-Bold").text("POTENTIAL FINANCIAL EXPOSURE", { underline: true });
    doc.moveDown(0.3);

    const totalMinLoss = [...data.criticalChains, ...data.highChains].reduce(
      (sum, chain) => sum + chain.estimatedLossMin,
      0
    );
    const totalMaxLoss = [...data.criticalChains, ...data.highChains].reduce(
      (sum, chain) => sum + chain.estimatedLossMax,
      0
    );

    const formatCurrency = (val: number) =>
      new Intl.NumberFormat("en-US", {
        style: "currency",
        currency: "USD",
        minimumFractionDigits: 0,
      }).format(val);

    doc
      .fontSize(11)
      .font("Helvetica-Bold")
      .fillColor("#d32f2f")
      .text(formatCurrency(totalMinLoss) + " - " + formatCurrency(totalMaxLoss), {
        align: "center",
      });

    doc
      .fillColor("#000000")
      .fontSize(9)
      .font("Helvetica")
      .text("(Based on industry recovery costs, breach notifications, and regulatory fines)", {
        align: "center",
      });

    doc.moveDown(1);

    // Compliance Gaps
    doc.fontSize(12).font("Helvetica-Bold").text("REGULATORY & COMPLIANCE GAPS", { underline: true });
    doc.moveDown(0.3);

    const allChains = [...data.criticalChains, ...data.highChains];
    const complianceSet = new Set<string>();
    allChains.forEach(chain => {
      chain.complianceRisks.forEach(risk => complianceSet.add(risk));
    });

    if (complianceSet.size === 0) {
      doc.fontSize(10).text("No identified compliance gaps.");
    } else {
      const complianceList = Array.from(complianceSet).sort();
      complianceList.forEach((compliance) => {
        doc.fontSize(10).text(`• ${compliance}`);
      });
    }

    doc.moveDown(1);

    // Critical Chains Summary
    if (criticalCount > 0) {
      doc.fontSize(12).font("Helvetica-Bold").text("CRITICAL RISK FACTORS", { underline: true });
      doc.moveDown(0.3);

      data.criticalChains.slice(0, 3).forEach((chain, idx) => {
        doc.fontSize(10).font("Helvetica-Bold").text(`${idx + 1}. ${chain.name}`);
        doc.fontSize(9).font("Helvetica").text(chain.executiveSummary, {
          width: 445,
          align: "left",
        });
        doc.moveDown(0.5);
      });

      if (criticalCount > 3) {
        doc
          .fillColor("#d32f2f")
          .fontSize(9)
          .font("Helvetica-Oblique")
          .text(`...and ${criticalCount - 3} more critical risks (see detailed report)`);
        doc.fillColor("#000000");
      }
    }

    doc.moveDown(1);

    // Recommendations
    doc.fontSize(12).font("Helvetica-Bold").text("RECOMMENDED ACTIONS", { underline: true });
    doc.moveDown(0.3);
    doc.fontSize(10).font("Helvetica");

    const recommendations = [
      "Schedule emergency security review meeting with IT leadership",
      "Prioritize remediation of CRITICAL-rated vulnerability chains",
      "Engage legal/compliance team regarding regulatory exposure",
      "Review and update cyber insurance coverage",
      "Brief Board of Directors and audit committee on findings",
      "Implement continuous monitoring for emerging threats",
    ];

    recommendations.forEach((rec, idx) => {
      doc.text(`${idx + 1}. ${rec}`, { width: 445 });
    });

    doc.moveDown(1);

    // Footer
    doc
      .fillColor("#666666")
      .fontSize(8)
      .text("For detailed technical analysis, review the full vulnerability assessment report.", {
        align: "center",
      });
    doc.text("This report contains confidential security information and should be restricted to authorized personnel.", {
      align: "center",
    });

    // Finalize PDF
    doc.end();
  });
}

export const executiveReportService = {
  generateExecutiveReport,
};
