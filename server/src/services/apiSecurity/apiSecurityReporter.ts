import { type BOLAAnalysisResult } from "./bolaAnalyzer";
import { type MassAssignmentAnalysisResult } from "./massAssignmentAnalyzer";
import { type RateLimitAnalysisResult } from "./rateLimitAnalyzer";
import { type ParsedOpenApiSpec } from "./openApiParser";

export interface ApiSecurityFinding {
  id: string;
  category: "BOLA" | "Mass Assignment" | "Rate Limiting";
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  endpoint: string;
  method: string;
  recommendation: string;
  owaspCategory: string;
  cwe: string;
  confidenceScore: number;
  additionalInfo?: Record<string, unknown>;
}

export interface ApiSecurityReportData {
  specInfo: {
    title: string;
    version: string;
    endpointCount: number;
    servers: string[];
  };
  findings: ApiSecurityFinding[];
  summary: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    securityScore: number;
    riskLevel: "critical" | "high" | "medium" | "low" | "minimal";
  };
  categoryBreakdown: {
    bola: { count: number; criticalCount: number };
    massAssignment: { count: number; criticalCount: number };
    rateLimit: { count: number; criticalCount: number };
  };
  topRecommendations: string[];
  analysisTimestamp: string;
}

export interface GenerateReportOptions {
  spec: ParsedOpenApiSpec;
  bolaResults?: BOLAAnalysisResult;
  massAssignmentResults?: MassAssignmentAnalysisResult;
  rateLimitResults?: RateLimitAnalysisResult;
}

class ApiSecurityReporterService {
  generateReport(options: GenerateReportOptions): ApiSecurityReportData {
    const { spec, bolaResults, massAssignmentResults, rateLimitResults } = options;
    const findings: ApiSecurityFinding[] = [];

    if (bolaResults) {
      for (const vuln of bolaResults.vulnerabilities) {
        findings.push({
          id: vuln.id,
          category: "BOLA",
          title: vuln.title,
          severity: vuln.severity,
          description: vuln.description,
          endpoint: vuln.endpoint,
          method: vuln.method,
          recommendation: vuln.recommendation,
          owaspCategory: vuln.owaspCategory,
          cwe: vuln.cwe,
          confidenceScore: vuln.confidenceScore,
          additionalInfo: {
            vulnerabilityType: vuln.vulnerabilityType,
            affectedParameter: vuln.affectedParameter,
          },
        });
      }
    }

    if (massAssignmentResults) {
      for (const vuln of massAssignmentResults.vulnerabilities) {
        findings.push({
          id: vuln.id,
          category: "Mass Assignment",
          title: vuln.title,
          severity: vuln.severity,
          description: vuln.description,
          endpoint: vuln.endpoint,
          method: vuln.method,
          recommendation: vuln.recommendation,
          owaspCategory: vuln.owaspCategory,
          cwe: vuln.cwe,
          confidenceScore: vuln.confidenceScore,
          additionalInfo: {
            sensitiveFields: vuln.sensitiveFields,
          },
        });
      }
    }

    if (rateLimitResults) {
      for (const vuln of rateLimitResults.vulnerabilities) {
        findings.push({
          id: vuln.id,
          category: "Rate Limiting",
          title: vuln.title,
          severity: vuln.severity,
          description: vuln.description,
          endpoint: vuln.endpoint,
          method: vuln.method,
          recommendation: vuln.recommendation,
          owaspCategory: vuln.owaspCategory,
          cwe: vuln.cwe,
          confidenceScore: vuln.confidenceScore,
          additionalInfo: {
            vulnerabilityType: vuln.vulnerabilityType,
            bypassVector: vuln.bypassVector,
          },
        });
      }
    }

    const sortedFindings = this.sortFindingsBySeverity(findings);
    const summary = this.generateSummary(sortedFindings);
    const categoryBreakdown = this.generateCategoryBreakdown(bolaResults, massAssignmentResults, rateLimitResults);
    const topRecommendations = this.extractTopRecommendations(sortedFindings);

    return {
      specInfo: {
        title: spec.title,
        version: spec.version,
        endpointCount: spec.endpoints.length,
        servers: spec.servers.map(s => s.url),
      },
      findings: sortedFindings,
      summary,
      categoryBreakdown,
      topRecommendations,
      analysisTimestamp: new Date().toISOString(),
    };
  }

  private sortFindingsBySeverity(findings: ApiSecurityFinding[]): ApiSecurityFinding[] {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return findings.sort((a, b) => {
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityDiff !== 0) return severityDiff;
      return b.confidenceScore - a.confidenceScore;
    });
  }

  private generateSummary(findings: ApiSecurityFinding[]): ApiSecurityReportData["summary"] {
    const criticalCount = findings.filter(f => f.severity === "critical").length;
    const highCount = findings.filter(f => f.severity === "high").length;
    const mediumCount = findings.filter(f => f.severity === "medium").length;
    const lowCount = findings.filter(f => f.severity === "low").length;
    const infoCount = findings.filter(f => f.severity === "info").length;

    const securityScore = this.calculateSecurityScore(criticalCount, highCount, mediumCount, lowCount);
    const riskLevel = this.determineRiskLevel(criticalCount, highCount, mediumCount);

    return {
      totalFindings: findings.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      securityScore,
      riskLevel,
    };
  }

  private calculateSecurityScore(critical: number, high: number, medium: number, low: number): number {
    const baseScore = 100;
    const criticalPenalty = critical * 25;
    const highPenalty = high * 15;
    const mediumPenalty = medium * 5;
    const lowPenalty = low * 1;

    const totalPenalty = criticalPenalty + highPenalty + mediumPenalty + lowPenalty;
    return Math.max(0, baseScore - totalPenalty);
  }

  private determineRiskLevel(critical: number, high: number, medium: number): ApiSecurityReportData["summary"]["riskLevel"] {
    if (critical > 0) return "critical";
    if (high > 2) return "high";
    if (high > 0 || medium > 5) return "medium";
    if (medium > 0) return "low";
    return "minimal";
  }

  private generateCategoryBreakdown(
    bola?: BOLAAnalysisResult,
    massAssignment?: MassAssignmentAnalysisResult,
    rateLimit?: RateLimitAnalysisResult
  ): ApiSecurityReportData["categoryBreakdown"] {
    return {
      bola: {
        count: bola?.vulnerabilities.length || 0,
        criticalCount: bola?.criticalCount || 0,
      },
      massAssignment: {
        count: massAssignment?.vulnerabilities.length || 0,
        criticalCount: massAssignment?.criticalCount || 0,
      },
      rateLimit: {
        count: rateLimit?.vulnerabilities.length || 0,
        criticalCount: rateLimit?.criticalCount || 0,
      },
    };
  }

  private extractTopRecommendations(findings: ApiSecurityFinding[]): string[] {
    const uniqueRecommendations = new Map<string, { severity: string; recommendation: string }>();

    for (const finding of findings) {
      const key = finding.recommendation.slice(0, 50);
      if (!uniqueRecommendations.has(key)) {
        uniqueRecommendations.set(key, {
          severity: finding.severity,
          recommendation: finding.recommendation,
        });
      }
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sortedRecs = Array.from(uniqueRecommendations.values())
      .sort((a, b) => severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder])
      .map(r => r.recommendation);

    return sortedRecs.slice(0, 10);
  }

  generateExecutiveSummary(reportData: ApiSecurityReportData): string {
    const { summary, specInfo, categoryBreakdown } = reportData;

    const riskDescriptions = {
      critical: "CRITICAL - Immediate action required. Your API has severe security vulnerabilities that could lead to data breaches or system compromise.",
      high: "HIGH - Urgent attention needed. Multiple significant vulnerabilities were identified that pose substantial risk.",
      medium: "MEDIUM - Some security concerns identified. Remediation should be planned and executed promptly.",
      low: "LOW - Minor issues found. Your API demonstrates good security practices with room for improvement.",
      minimal: "MINIMAL - Excellent security posture. Only minor observations were noted.",
    };

    let summary_text = `API Security Assessment for "${specInfo.title}" (v${specInfo.version})\n\n`;
    summary_text += `Risk Level: ${riskDescriptions[summary.riskLevel]}\n\n`;
    summary_text += `Security Score: ${summary.securityScore}/100\n\n`;
    summary_text += `Analysis covered ${specInfo.endpointCount} API endpoints across ${specInfo.servers.length} server(s).\n\n`;

    summary_text += `Findings Summary:\n`;
    summary_text += `- Critical Issues: ${summary.criticalCount}\n`;
    summary_text += `- High Severity: ${summary.highCount}\n`;
    summary_text += `- Medium Severity: ${summary.mediumCount}\n`;
    summary_text += `- Low Severity: ${summary.lowCount}\n\n`;

    if (categoryBreakdown.bola.count > 0) {
      summary_text += `Authorization Issues (BOLA): ${categoryBreakdown.bola.count} findings (${categoryBreakdown.bola.criticalCount} critical)\n`;
    }
    if (categoryBreakdown.massAssignment.count > 0) {
      summary_text += `Mass Assignment Issues: ${categoryBreakdown.massAssignment.count} findings (${categoryBreakdown.massAssignment.criticalCount} critical)\n`;
    }
    if (categoryBreakdown.rateLimit.count > 0) {
      summary_text += `Rate Limiting Issues: ${categoryBreakdown.rateLimit.count} findings (${categoryBreakdown.rateLimit.criticalCount} critical)\n`;
    }

    if (reportData.topRecommendations.length > 0) {
      summary_text += `\nTop Priority Actions:\n`;
      reportData.topRecommendations.slice(0, 5).forEach((rec, i) => {
        summary_text += `${i + 1}. ${rec}\n`;
      });
    }

    return summary_text;
  }

  formatForMainReport(reportData: ApiSecurityReportData): {
    vulnerabilities: Array<{
      id: string;
      title: string;
      severity: string;
      description: string;
      recommendation: string;
      cwe: string;
    }>;
    securityScore: number;
    recommendations: string[];
    executiveSummary: string;
  } {
    return {
      vulnerabilities: reportData.findings.map(f => ({
        id: f.id,
        title: `[${f.category}] ${f.title}`,
        severity: f.severity,
        description: `${f.method} ${f.endpoint}: ${f.description}`,
        recommendation: f.recommendation,
        cwe: f.cwe,
      })),
      securityScore: reportData.summary.securityScore,
      recommendations: reportData.topRecommendations,
      executiveSummary: this.generateExecutiveSummary(reportData),
    };
  }
}

export const apiSecurityReporter = new ApiSecurityReporterService();
