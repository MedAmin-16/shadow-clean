import type { Request, Response } from "express";
import { openApiParser } from "../services/apiSecurity/openApiParser";
import { bolaAnalyzer } from "../services/apiSecurity/bolaAnalyzer";
import { massAssignmentAnalyzer } from "../services/apiSecurity/massAssignmentAnalyzer";
import { rateLimitAnalyzer } from "../services/apiSecurity/rateLimitAnalyzer";

export interface ApiSecurityScanRequest {
  specContent: string;
  analysisTypes?: ("bola" | "mass-assignment" | "rate-limit" | "all")[];
  format?: "json" | "summary";
}

export interface ApiSecurityScanResult {
  success: boolean;
  specInfo?: {
    title: string;
    version: string;
    endpointCount: number;
  };
  analysis?: {
    bola?: ReturnType<typeof bolaAnalyzer.analyze>;
    massAssignment?: ReturnType<typeof massAssignmentAnalyzer.analyze>;
    rateLimit?: ReturnType<typeof rateLimitAnalyzer.analyze>;
  };
  summary?: {
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    topRisks: Array<{
      category: string;
      severity: string;
      endpoint: string;
      description: string;
    }>;
  };
  errors?: string[];
  warnings?: string[];
  analysisTimestamp: string;
}

export async function analyzeApiSpec(req: Request, res: Response) {
  try {
    const { specContent, analysisTypes = ["all"], format = "json" } = req.body as ApiSecurityScanRequest;

    if (!specContent) {
      return res.status(400).json({
        success: false,
        errors: ["specContent is required"],
      });
    }

    const parseResult = openApiParser.parse(specContent);

    if (!parseResult.success || !parseResult.spec) {
      return res.status(400).json({
        success: false,
        errors: parseResult.errors || ["Failed to parse OpenAPI specification"],
        warnings: parseResult.warnings,
      });
    }

    const spec = parseResult.spec;
    const runAll = analysisTypes.includes("all");

    const result: ApiSecurityScanResult = {
      success: true,
      specInfo: {
        title: spec.title,
        version: spec.version,
        endpointCount: spec.endpoints.length,
      },
      analysis: {},
      warnings: parseResult.warnings,
      analysisTimestamp: new Date().toISOString(),
    };

    if (runAll || analysisTypes.includes("bola")) {
      result.analysis!.bola = bolaAnalyzer.analyze(spec);
    }

    if (runAll || analysisTypes.includes("mass-assignment")) {
      result.analysis!.massAssignment = massAssignmentAnalyzer.analyze(spec);
    }

    if (runAll || analysisTypes.includes("rate-limit")) {
      result.analysis!.rateLimit = rateLimitAnalyzer.analyze(spec);
    }

    if (format === "summary" || format === "json") {
      result.summary = generateSummary(result.analysis!);
    }

    return res.json(result);
  } catch (error) {
    console.error("[ApiSecurityController] Analysis error:", error);
    return res.status(500).json({
      success: false,
      errors: [error instanceof Error ? error.message : "Internal server error"],
      analysisTimestamp: new Date().toISOString(),
    });
  }
}

export async function getAnalysisTypes(req: Request, res: Response) {
  return res.json({
    analysisTypes: [
      {
        id: "bola",
        name: "Broken Object Level Authorization (BOLA)",
        description: "Detects IDOR vulnerabilities, missing authorization, and privilege escalation risks",
        owaspCategory: "API1:2023",
      },
      {
        id: "mass-assignment",
        name: "Mass Assignment",
        description: "Identifies endpoints accepting sensitive fields that could be exploited for privilege escalation",
        owaspCategory: "API6:2023",
      },
      {
        id: "rate-limit",
        name: "Rate Limiting Bypass",
        description: "Finds endpoints vulnerable to brute force, DoS, and rate limit bypass attacks",
        owaspCategory: "API4:2023",
      },
      {
        id: "all",
        name: "Full Security Scan",
        description: "Runs all available security analyzers",
        owaspCategory: "Multiple",
      },
    ],
  });
}

export async function parseSpec(req: Request, res: Response) {
  try {
    const { specContent } = req.body;

    if (!specContent) {
      return res.status(400).json({
        success: false,
        errors: ["specContent is required"],
      });
    }

    const parseResult = openApiParser.parse(specContent);

    if (!parseResult.success || !parseResult.spec) {
      return res.status(400).json({
        success: false,
        errors: parseResult.errors,
        warnings: parseResult.warnings,
      });
    }

    return res.json({
      success: true,
      spec: {
        title: parseResult.spec.title,
        version: parseResult.spec.version,
        description: parseResult.spec.description,
        servers: parseResult.spec.servers,
        endpointCount: parseResult.spec.endpoints.length,
        endpoints: parseResult.spec.endpoints.map(e => ({
          path: e.path,
          method: e.method,
          operationId: e.operationId,
          summary: e.summary,
          tags: e.tags,
          hasSecurity: (e.security && e.security.length > 0) || false,
        })),
        securitySchemes: Object.keys(parseResult.spec.securitySchemes),
        hasGlobalSecurity: parseResult.spec.securityRequirements.length > 0,
      },
      warnings: parseResult.warnings,
    });
  } catch (error) {
    console.error("[ApiSecurityController] Parse error:", error);
    return res.status(500).json({
      success: false,
      errors: [error instanceof Error ? error.message : "Internal server error"],
    });
  }
}

function generateSummary(analysis: NonNullable<ApiSecurityScanResult["analysis"]>) {
  const allVulnerabilities: Array<{
    category: string;
    severity: string;
    endpoint: string;
    description: string;
  }> = [];

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  if (analysis.bola) {
    criticalCount += analysis.bola.criticalCount;
    highCount += analysis.bola.highCount;
    mediumCount += analysis.bola.mediumCount;
    lowCount += analysis.bola.lowCount;
    
    for (const vuln of analysis.bola.vulnerabilities) {
      allVulnerabilities.push({
        category: "BOLA",
        severity: vuln.severity,
        endpoint: `${vuln.method} ${vuln.endpoint}`,
        description: vuln.title,
      });
    }
  }

  if (analysis.massAssignment) {
    criticalCount += analysis.massAssignment.criticalCount;
    highCount += analysis.massAssignment.highCount;
    mediumCount += analysis.massAssignment.mediumCount;
    lowCount += analysis.massAssignment.lowCount;
    
    for (const vuln of analysis.massAssignment.vulnerabilities) {
      allVulnerabilities.push({
        category: "Mass Assignment",
        severity: vuln.severity,
        endpoint: `${vuln.method} ${vuln.endpoint}`,
        description: vuln.title,
      });
    }
  }

  if (analysis.rateLimit) {
    criticalCount += analysis.rateLimit.criticalCount;
    highCount += analysis.rateLimit.highCount;
    mediumCount += analysis.rateLimit.mediumCount;
    lowCount += analysis.rateLimit.lowCount;
    
    for (const vuln of analysis.rateLimit.vulnerabilities) {
      allVulnerabilities.push({
        category: "Rate Limiting",
        severity: vuln.severity,
        endpoint: `${vuln.method} ${vuln.endpoint}`,
        description: vuln.title,
      });
    }
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const topRisks = allVulnerabilities
    .sort((a, b) => severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder])
    .slice(0, 10);

  return {
    totalVulnerabilities: allVulnerabilities.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    topRisks,
  };
}
