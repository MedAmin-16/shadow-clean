import { 
  type ParsedOpenApiSpec, 
  type OpenApiEndpoint,
  type OpenApiSchema,
  openApiParser 
} from "./openApiParser";

export interface MassAssignmentVulnerability {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  endpoint: string;
  method: string;
  sensitiveFields: string[];
  recommendation: string;
  owaspCategory: string;
  cwe: string;
  confidenceScore: number;
}

export interface MassAssignmentAnalysisResult {
  vulnerabilities: MassAssignmentVulnerability[];
  totalEndpointsAnalyzed: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  analysisTimestamp: string;
}

const SENSITIVE_FIELD_PATTERNS = [
  /^(is_?)?admin$/i,
  /^(is_?)?superuser$/i,
  /^role(s)?$/i,
  /^permission(s)?$/i,
  /^privilege(s)?$/i,
  /^access_?level$/i,
  /^user_?type$/i,
  /^account_?type$/i,
  /^verified$/i,
  /^(is_?)?active$/i,
  /^(is_?)?enabled$/i,
  /^(is_?)?banned$/i,
  /^(is_?)?locked$/i,
  /^password(_?hash)?$/i,
  /^secret$/i,
  /^api_?key$/i,
  /^token$/i,
  /^balance$/i,
  /^credits?$/i,
  /^subscription(_?tier)?$/i,
  /^plan(_?level)?$/i,
  /^internal_?id$/i,
  /^created_?(at|by)$/i,
  /^updated_?(at|by)$/i,
  /^deleted_?(at|by)$/i,
  /^owner(_?id)?$/i,
  /^tenant(_?id)?$/i,
];

class MassAssignmentAnalyzerService {
  private vulnerabilityCounter = 0;

  analyze(spec: ParsedOpenApiSpec): MassAssignmentAnalysisResult {
    const vulnerabilities: MassAssignmentVulnerability[] = [];
    this.vulnerabilityCounter = 0;

    const endpointsWithObjects = openApiParser.findEndpointsAcceptingObjects(spec);

    for (const endpoint of endpointsWithObjects) {
      this.analyzeEndpoint(endpoint, spec, vulnerabilities);
    }

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

  private analyzeEndpoint(
    endpoint: OpenApiEndpoint,
    spec: ParsedOpenApiSpec,
    vulnerabilities: MassAssignmentVulnerability[]
  ): void {
    if (!endpoint.requestBody?.content["application/json"]?.schema) return;

    const schema = endpoint.requestBody.content["application/json"].schema;
    const resolvedSchema = this.resolveSchema(schema, spec.schemas);
    
    if (!resolvedSchema.properties) return;

    const sensitiveFields = this.findSensitiveFields(resolvedSchema);
    const hasAdditionalProperties = resolvedSchema.additionalProperties !== false;

    if (sensitiveFields.length > 0) {
      const severity = this.calculateSeverity(sensitiveFields, endpoint);
      
      vulnerabilities.push(this.createVulnerability({
        endpoint,
        sensitiveFields,
        severity,
        type: "sensitive_field_exposure",
        description: `Endpoint ${endpoint.method} ${endpoint.path} accepts potentially sensitive fields in the request body: ${sensitiveFields.join(", ")}. If not properly validated, attackers could modify protected attributes.`,
      }));
    }

    if (hasAdditionalProperties && (endpoint.method === "POST" || endpoint.method === "PUT" || endpoint.method === "PATCH")) {
      vulnerabilities.push(this.createVulnerability({
        endpoint,
        sensitiveFields: [],
        severity: "medium",
        type: "additional_properties_allowed",
        description: `Endpoint ${endpoint.method} ${endpoint.path} allows additional properties in the request body. Attackers could inject unexpected fields that may be processed by the backend.`,
      }));
    }
  }

  private resolveSchema(schema: OpenApiSchema, schemas: Record<string, OpenApiSchema>): OpenApiSchema {
    if (schema.$ref) {
      const refPath = schema.$ref.split("/").pop();
      if (refPath && schemas[refPath]) {
        return this.resolveSchema(schemas[refPath], schemas);
      }
    }
    return schema;
  }

  private findSensitiveFields(schema: OpenApiSchema, prefix = ""): string[] {
    const sensitiveFields: string[] = [];

    if (!schema.properties) return sensitiveFields;

    for (const [fieldName, fieldSchema] of Object.entries(schema.properties)) {
      const fullPath = prefix ? `${prefix}.${fieldName}` : fieldName;

      if (this.isSensitiveField(fieldName)) {
        sensitiveFields.push(fullPath);
      }

      if (fieldSchema.type === "object" && fieldSchema.properties) {
        sensitiveFields.push(...this.findSensitiveFields(fieldSchema, fullPath));
      }
    }

    return sensitiveFields;
  }

  private isSensitiveField(fieldName: string): boolean {
    return SENSITIVE_FIELD_PATTERNS.some(pattern => pattern.test(fieldName));
  }

  private calculateSeverity(
    sensitiveFields: string[],
    endpoint: OpenApiEndpoint
  ): "critical" | "high" | "medium" | "low" {
    const hasCriticalFields = sensitiveFields.some(f => 
      /admin|superuser|role|permission|privilege/i.test(f)
    );
    
    const hasHighFields = sensitiveFields.some(f =>
      /password|secret|api_?key|token|balance|credit/i.test(f)
    );

    const isUserCreation = endpoint.path.includes("user") && endpoint.method === "POST";
    const isUserUpdate = endpoint.path.includes("user") && (endpoint.method === "PUT" || endpoint.method === "PATCH");

    if (hasCriticalFields && (isUserCreation || isUserUpdate)) {
      return "critical";
    }
    if (hasCriticalFields || (hasHighFields && isUserUpdate)) {
      return "high";
    }
    if (hasHighFields) {
      return "medium";
    }
    return "low";
  }

  private createVulnerability({
    endpoint,
    sensitiveFields,
    severity,
    type,
    description,
  }: {
    endpoint: OpenApiEndpoint;
    sensitiveFields: string[];
    severity: "critical" | "high" | "medium" | "low";
    type: "sensitive_field_exposure" | "additional_properties_allowed";
    description: string;
  }): MassAssignmentVulnerability {
    this.vulnerabilityCounter++;

    const recommendations: Record<string, string> = {
      sensitive_field_exposure: "Implement a whitelist of allowed fields for mass assignment. Use DTOs (Data Transfer Objects) to explicitly define which fields can be set by users. Never bind request data directly to database models.",
      additional_properties_allowed: "Set 'additionalProperties: false' in your OpenAPI schema. Implement strict input validation that rejects unexpected fields.",
    };

    return {
      id: `MA-${this.vulnerabilityCounter.toString().padStart(3, "0")}`,
      title: type === "sensitive_field_exposure" 
        ? "Mass Assignment - Sensitive Field Exposure" 
        : "Mass Assignment - Additional Properties Allowed",
      severity,
      description,
      endpoint: endpoint.path,
      method: endpoint.method,
      sensitiveFields,
      recommendation: recommendations[type],
      owaspCategory: "API6:2023 Unrestricted Access to Sensitive Business Flows",
      cwe: "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
      confidenceScore: type === "sensitive_field_exposure" ? 0.85 : 0.7,
    };
  }
}

export const massAssignmentAnalyzer = new MassAssignmentAnalyzerService();
