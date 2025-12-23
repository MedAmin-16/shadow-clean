import { 
  type ParsedOpenApiSpec, 
  type OpenApiEndpoint,
  openApiParser 
} from "./openApiParser";

export type BOLASeverity = "critical" | "high" | "medium" | "low" | "info";

export interface BOLAVulnerability {
  id: string;
  title: string;
  severity: BOLASeverity;
  description: string;
  endpoint: string;
  method: string;
  vulnerabilityType: BOLAType;
  affectedParameter?: string;
  recommendation: string;
  owaspCategory: string;
  cwe: string;
  confidenceScore: number;
}

export type BOLAType = 
  | "direct_object_reference"
  | "predictable_id"
  | "missing_authorization"
  | "horizontal_privilege_escalation"
  | "vertical_privilege_escalation"
  | "function_level_access_control";

export interface BOLAAnalysisResult {
  vulnerabilities: BOLAVulnerability[];
  totalEndpointsAnalyzed: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  analysisTimestamp: string;
}

class BOLAAnalyzerService {
  private vulnerabilityCounter = 0;

  analyze(spec: ParsedOpenApiSpec): BOLAAnalysisResult {
    const vulnerabilities: BOLAVulnerability[] = [];
    this.vulnerabilityCounter = 0;

    const endpointsWithIds = openApiParser.findEndpointsWithIdParams(spec);
    
    for (const endpoint of endpointsWithIds) {
      this.analyzeEndpointForBOLA(endpoint, spec, vulnerabilities);
    }

    this.analyzeResourceGroups(spec, vulnerabilities);

    this.analyzeFunctionLevelAccess(spec, vulnerabilities);

    return {
      vulnerabilities,
      totalEndpointsAnalyzed: spec.endpoints.length,
      criticalCount: vulnerabilities.filter(v => v.severity === "critical").length,
      highCount: vulnerabilities.filter(v => v.severity === "high").length,
      mediumCount: vulnerabilities.filter(v => v.severity === "medium").length,
      lowCount: vulnerabilities.filter(v => v.severity === "low").length,
      analysisTimestamp: new Date().toISOString(),
    };
  }

  private analyzeEndpointForBOLA(
    endpoint: OpenApiEndpoint,
    spec: ParsedOpenApiSpec,
    vulnerabilities: BOLAVulnerability[]
  ): void {
    const idParams = endpoint.parameters.filter(p => 
      p.in === "path" && /[Ii]d$/.test(p.name)
    );

    for (const param of idParams) {
      const hasSecurity = this.hasSecurityRequirement(endpoint, spec);
      
      if (!hasSecurity) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "missing_authorization",
          severity: "critical",
          parameter: param.name,
          description: `Endpoint ${endpoint.method} ${endpoint.path} accepts ${param.name} parameter but has no security requirements defined. An attacker could potentially access any resource by manipulating the ID value.`,
          recommendation: "Implement proper authentication and authorization checks. Verify that the authenticated user has permission to access the requested resource.",
        }));
      }

      if (this.isPredictableId(param)) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "predictable_id",
          severity: hasSecurity ? "high" : "critical",
          parameter: param.name,
          description: `The ${param.name} parameter appears to use predictable sequential IDs (integer type). Attackers could enumerate resources by incrementing/decrementing the ID.`,
          recommendation: "Use UUIDs or other non-predictable identifiers. Implement rate limiting to prevent enumeration attacks.",
        }));
      }

      if (this.isDirectObjectReference(endpoint, param)) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "direct_object_reference",
          severity: hasSecurity ? "medium" : "high",
          parameter: param.name,
          description: `The endpoint directly uses ${param.name} to access resources. If authorization checks are insufficient, this could allow unauthorized access to other users' data.`,
          recommendation: "Implement object-level authorization. Verify that the current user has permission to access the specific resource before returning data.",
        }));
      }
    }
  }

  private analyzeResourceGroups(
    spec: ParsedOpenApiSpec,
    vulnerabilities: BOLAVulnerability[]
  ): void {
    const resourceMap = openApiParser.getResourceEndpoints(spec);

    for (const [resource, endpoints] of Array.from(resourceMap.entries())) {
      const hasListEndpoint = endpoints.some((e: OpenApiEndpoint) => 
        e.method === "GET" && !e.path.includes("{")
      );
      const hasGetByIdEndpoint = endpoints.some((e: OpenApiEndpoint) => 
        e.method === "GET" && e.path.includes("{")
      );

      if (hasGetByIdEndpoint && !hasListEndpoint) {
        const getByIdEndpoint = endpoints.find((e: OpenApiEndpoint) => 
          e.method === "GET" && e.path.includes("{")
        )!;
        
        if (!this.hasSecurityRequirement(getByIdEndpoint, spec)) {
          vulnerabilities.push(this.createVulnerability({
            endpoint: getByIdEndpoint,
            type: "horizontal_privilege_escalation",
            severity: "high",
            description: `Resource ${resource} has a GET by ID endpoint without a list endpoint and no security. This pattern is commonly exploited for horizontal privilege escalation.`,
            recommendation: "Implement user-scoped authorization. Ensure users can only access resources they own or have explicit permission to access.",
          }));
        }
      }

      const adminEndpoints = endpoints.filter((e: OpenApiEndpoint) => 
        e.path.includes("admin") || 
        e.tags?.some((t: string) => t.toLowerCase().includes("admin"))
      );

      for (const adminEndpoint of adminEndpoints) {
        if (!this.hasSecurityRequirement(adminEndpoint, spec)) {
          vulnerabilities.push(this.createVulnerability({
            endpoint: adminEndpoint,
            type: "vertical_privilege_escalation",
            severity: "critical",
            description: `Admin endpoint ${adminEndpoint.method} ${adminEndpoint.path} has no security requirements. Regular users could potentially access administrative functions.`,
            recommendation: "Implement role-based access control (RBAC). Ensure only users with admin privileges can access administrative endpoints.",
          }));
        }
      }
    }
  }

  private analyzeFunctionLevelAccess(
    spec: ParsedOpenApiSpec,
    vulnerabilities: BOLAVulnerability[]
  ): void {
    const sensitiveEndpoints = spec.endpoints.filter(e => 
      e.method !== "GET" && (
        e.path.includes("delete") ||
        e.path.includes("update") ||
        e.path.includes("modify") ||
        e.path.includes("create") ||
        e.method === "DELETE" ||
        e.method === "PUT" ||
        e.method === "PATCH"
      )
    );

    for (const endpoint of sensitiveEndpoints) {
      if (!this.hasSecurityRequirement(endpoint, spec)) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "function_level_access_control",
          severity: "high",
          description: `Sensitive ${endpoint.method} operation at ${endpoint.path} has no security requirements. Unauthorized users could potentially modify or delete resources.`,
          recommendation: "All state-changing operations (POST, PUT, PATCH, DELETE) should require authentication and appropriate authorization.",
        }));
      }
    }
  }

  private hasSecurityRequirement(endpoint: OpenApiEndpoint, spec: ParsedOpenApiSpec): boolean {
    if (endpoint.security && endpoint.security.length > 0) {
      return !endpoint.security.some(s => Object.keys(s).length === 0);
    }
    
    if (spec.securityRequirements && spec.securityRequirements.length > 0) {
      return true;
    }

    return false;
  }

  private isPredictableId(param: { name: string; schema?: { type?: string; format?: string } }): boolean {
    const schema = param.schema;
    if (!schema) return true;

    if (schema.type === "integer" || schema.type === "number") {
      return true;
    }

    if (schema.format === "uuid" || schema.format === "guid") {
      return false;
    }

    return false;
  }

  private isDirectObjectReference(
    endpoint: OpenApiEndpoint,
    param: { name: string }
  ): boolean {
    const pathWithoutParam = endpoint.path.replace(`{${param.name}}`, "");
    return /\/(users?|accounts?|profiles?|customers?|orders?|documents?|files?|messages?)/.test(pathWithoutParam);
  }

  private createVulnerability({
    endpoint,
    type,
    severity,
    parameter,
    description,
    recommendation,
  }: {
    endpoint: OpenApiEndpoint;
    type: BOLAType;
    severity: BOLASeverity;
    parameter?: string;
    description: string;
    recommendation: string;
  }): BOLAVulnerability {
    this.vulnerabilityCounter++;
    
    const titles: Record<BOLAType, string> = {
      direct_object_reference: "Insecure Direct Object Reference (IDOR)",
      predictable_id: "Predictable Resource Identifier",
      missing_authorization: "Missing Authorization Check",
      horizontal_privilege_escalation: "Horizontal Privilege Escalation Risk",
      vertical_privilege_escalation: "Vertical Privilege Escalation Risk",
      function_level_access_control: "Missing Function Level Access Control",
    };

    const confidenceScores: Record<BOLAType, number> = {
      missing_authorization: 0.95,
      vertical_privilege_escalation: 0.9,
      function_level_access_control: 0.85,
      predictable_id: 0.8,
      direct_object_reference: 0.75,
      horizontal_privilege_escalation: 0.7,
    };

    return {
      id: `BOLA-${this.vulnerabilityCounter.toString().padStart(3, "0")}`,
      title: titles[type],
      severity,
      description,
      endpoint: endpoint.path,
      method: endpoint.method,
      vulnerabilityType: type,
      affectedParameter: parameter,
      recommendation,
      owaspCategory: "API1:2023 Broken Object Level Authorization",
      cwe: "CWE-639: Authorization Bypass Through User-Controlled Key",
      confidenceScore: confidenceScores[type],
    };
  }
}

export const bolaAnalyzer = new BOLAAnalyzerService();
