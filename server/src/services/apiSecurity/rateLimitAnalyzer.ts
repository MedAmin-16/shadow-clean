import { 
  type ParsedOpenApiSpec, 
  type OpenApiEndpoint,
  type OpenApiSecurityScheme,
  type OpenApiResponse
} from "./openApiParser";

export interface RateLimitVulnerability {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  endpoint: string;
  method: string;
  vulnerabilityType: RateLimitVulnType;
  bypassVector?: string;
  recommendation: string;
  owaspCategory: string;
  cwe: string;
  confidenceScore: number;
}

export type RateLimitVulnType = 
  | "missing_rate_limit"
  | "resource_exhaustion"
  | "authentication_bypass"
  | "header_manipulation"
  | "ip_rotation"
  | "batch_endpoint_abuse"
  | "graphql_batching"
  | "race_condition"
  | "weak_rate_limit";

export interface RateLimitAnalysisResult {
  vulnerabilities: RateLimitVulnerability[];
  totalEndpointsAnalyzed: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  rateLimitIndicators: RateLimitIndicators;
  analysisTimestamp: string;
}

export interface RateLimitIndicators {
  has429Responses: boolean;
  hasRateLimitHeaders: boolean;
  hasThrottlingScheme: boolean;
  endpointsWithRateLimiting: string[];
  globalRateLimitDetected: boolean;
}

const SENSITIVE_ENDPOINTS_PATTERNS = [
  /\/(auth|login|signin|authenticate)/i,
  /\/(register|signup|create-?account)/i,
  /\/(password|reset|forgot|recover)/i,
  /\/(otp|verify|confirm|2fa|mfa)/i,
  /\/(payment|checkout|purchase|transaction)/i,
  /\/(email|sms|notification|message)/i,
];

const RESOURCE_INTENSIVE_PATTERNS = [
  /\/(export|download|generate)/i,
  /\/(bulk|batch|import)/i,
  /\/(ai|ml|predict)/i,
  /\/(pdf|report)/i,
];

class RateLimitAnalyzerService {
  private vulnerabilityCounter = 0;

  analyze(spec: ParsedOpenApiSpec): RateLimitAnalysisResult {
    const vulnerabilities: RateLimitVulnerability[] = [];
    this.vulnerabilityCounter = 0;

    const indicators = this.detectRateLimitIndicators(spec);

    if (!indicators.globalRateLimitDetected) {
      this.analyzeAuthenticationEndpoints(spec, vulnerabilities, indicators);
      this.analyzeResourceIntensiveEndpoints(spec, vulnerabilities, indicators);
    }

    this.analyzeBatchEndpoints(spec, vulnerabilities, indicators);
    this.analyzeBypassVectors(spec, vulnerabilities, indicators);

    if (!indicators.globalRateLimitDetected && !indicators.has429Responses) {
      this.analyzeUnauthenticatedEndpoints(spec, vulnerabilities, indicators);
    }

    return {
      vulnerabilities,
      totalEndpointsAnalyzed: spec.endpoints.length,
      criticalCount: vulnerabilities.filter(v => v.severity === "critical").length,
      highCount: vulnerabilities.filter(v => v.severity === "high").length,
      mediumCount: vulnerabilities.filter(v => v.severity === "medium").length,
      lowCount: vulnerabilities.filter(v => v.severity === "low").length,
      rateLimitIndicators: indicators,
      analysisTimestamp: new Date().toISOString(),
    };
  }

  private detectRateLimitIndicators(spec: ParsedOpenApiSpec): RateLimitIndicators {
    const endpointsWithRateLimiting: string[] = [];
    let has429Responses = false;
    let hasRateLimitHeaders = false;
    let hasThrottlingScheme = false;

    for (const [name, scheme] of Object.entries(spec.securitySchemes)) {
      if (name.toLowerCase().includes("throttl") || 
          name.toLowerCase().includes("ratelimit") ||
          name.toLowerCase().includes("rate_limit")) {
        hasThrottlingScheme = true;
      }
    }

    for (const endpoint of spec.endpoints) {
      const endpointKey = `${endpoint.method} ${endpoint.path}`;

      if (endpoint.responses["429"]) {
        has429Responses = true;
        endpointsWithRateLimiting.push(endpointKey);
      }

      for (const [code, response] of Object.entries(endpoint.responses)) {
        const responseContent = response as OpenApiResponse;
        if (responseContent.description) {
          const desc = responseContent.description.toLowerCase();
          if (desc.includes("rate limit") || 
              desc.includes("too many requests") ||
              desc.includes("throttl")) {
            has429Responses = true;
            if (!endpointsWithRateLimiting.includes(endpointKey)) {
              endpointsWithRateLimiting.push(endpointKey);
            }
          }
        }
      }

      const hasRateLimitParam = endpoint.parameters.some(p =>
        p.in === "header" && (
          /x-rate-?limit/i.test(p.name) ||
          /retry-after/i.test(p.name)
        )
      );
      if (hasRateLimitParam) {
        hasRateLimitHeaders = true;
        if (!endpointsWithRateLimiting.includes(endpointKey)) {
          endpointsWithRateLimiting.push(endpointKey);
        }
      }
    }

    const globalRateLimitDetected = 
      (has429Responses && endpointsWithRateLimiting.length > spec.endpoints.length * 0.5) ||
      hasThrottlingScheme;

    return {
      has429Responses,
      hasRateLimitHeaders,
      hasThrottlingScheme,
      endpointsWithRateLimiting,
      globalRateLimitDetected,
    };
  }

  private endpointHasRateLimiting(endpoint: OpenApiEndpoint, indicators: RateLimitIndicators): boolean {
    const endpointKey = `${endpoint.method} ${endpoint.path}`;
    return indicators.endpointsWithRateLimiting.includes(endpointKey) ||
           indicators.globalRateLimitDetected;
  }

  private analyzeAuthenticationEndpoints(
    spec: ParsedOpenApiSpec,
    vulnerabilities: RateLimitVulnerability[],
    indicators: RateLimitIndicators
  ): void {
    for (const endpoint of spec.endpoints) {
      if (this.endpointHasRateLimiting(endpoint, indicators)) continue;

      const isLoginEndpoint = /\/(auth|login|signin)/i.test(endpoint.path);
      const isPasswordReset = /\/(password|reset|forgot|recover)/i.test(endpoint.path);
      const isOtpEndpoint = /\/(otp|verify|confirm|2fa|mfa)/i.test(endpoint.path);
      const isRegistration = /\/(register|signup)/i.test(endpoint.path);

      if (endpoint.method !== "POST") continue;

      if (isLoginEndpoint) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "authentication_bypass",
          severity: "critical",
          description: `Login endpoint ${endpoint.path} has no documented rate limiting (missing 429 response or rate-limit headers). Without proper rate limiting, attackers can attempt credential stuffing and brute force attacks.`,
          bypassVector: "Credential stuffing, brute force attacks",
          recommendation: "Implement strict rate limiting (e.g., 5 attempts per 15 minutes per IP/account). Document 429 responses in API spec.",
        }));
      } else if (isOtpEndpoint) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "authentication_bypass",
          severity: "critical",
          description: `OTP/2FA verification endpoint ${endpoint.path} lacks documented rate limiting. 4-6 digit OTPs can be brute-forced within minutes.`,
          bypassVector: "OTP brute-force (10,000-1,000,000 combinations)",
          recommendation: "Limit OTP attempts to 3-5 per code. Document 429 responses and implement exponential backoff.",
        }));
      } else if (isPasswordReset) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "authentication_bypass",
          severity: "high",
          description: `Password reset endpoint ${endpoint.path} has no documented rate limiting, enabling account enumeration and token brute-forcing.`,
          bypassVector: "Token brute-force, account enumeration",
          recommendation: "Limit password reset requests to 3 per hour per email/IP. Document rate limiting in API spec.",
        }));
      } else if (isRegistration) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "resource_exhaustion",
          severity: "medium",
          description: `Registration endpoint ${endpoint.path} lacks rate limiting documentation, potentially allowing mass account creation.`,
          bypassVector: "Mass account creation, bot registration",
          recommendation: "Implement CAPTCHA, email verification, and limit registrations per IP.",
        }));
      }
    }
  }

  private analyzeResourceIntensiveEndpoints(
    spec: ParsedOpenApiSpec,
    vulnerabilities: RateLimitVulnerability[],
    indicators: RateLimitIndicators
  ): void {
    for (const endpoint of spec.endpoints) {
      if (this.endpointHasRateLimiting(endpoint, indicators)) continue;

      const isResourceIntensive = RESOURCE_INTENSIVE_PATTERNS.some(pattern =>
        pattern.test(endpoint.path)
      );
      if (!isResourceIntensive) continue;

      const isExport = /\/(export|download|generate|pdf|report)/i.test(endpoint.path);
      const isAI = /\/(ai|ml|predict|analyze)/i.test(endpoint.path);

      if (isAI) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "resource_exhaustion",
          severity: "critical",
          description: `AI/ML endpoint ${endpoint.method} ${endpoint.path} has no documented rate limiting. These expensive compute operations can cause massive cost overruns.`,
          bypassVector: "Compute resource exhaustion, cost amplification attacks",
          recommendation: "Implement strict per-user rate limits and cost caps. Document 429 responses.",
        }));
      } else if (isExport) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "resource_exhaustion",
          severity: "high",
          description: `Resource-intensive endpoint ${endpoint.method} ${endpoint.path} lacks rate limiting documentation, enabling DoS via repeated expensive operations.`,
          bypassVector: "CPU/memory exhaustion, disk space exhaustion",
          recommendation: "Implement rate limits and document 429 responses. Add job queuing and size limits.",
        }));
      }
    }
  }

  private analyzeBatchEndpoints(
    spec: ParsedOpenApiSpec,
    vulnerabilities: RateLimitVulnerability[],
    indicators: RateLimitIndicators
  ): void {
    for (const endpoint of spec.endpoints) {
      const isBatchEndpoint = /\/(bulk|batch|import|multiple)/i.test(endpoint.path);
      
      if (endpoint.requestBody) {
        const jsonSchema = endpoint.requestBody.content["application/json"]?.schema;
        const acceptsArray = jsonSchema?.type === "array";
        
        if ((isBatchEndpoint || acceptsArray) && !this.endpointHasRateLimiting(endpoint, indicators)) {
          vulnerabilities.push(this.createVulnerability({
            endpoint,
            type: "batch_endpoint_abuse",
            severity: "high",
            description: `Batch endpoint ${endpoint.method} ${endpoint.path} accepts arrays and lacks rate limiting documentation. Per-request limits can be bypassed by packing multiple operations.`,
            bypassVector: "Rate limit bypass through request batching",
            recommendation: "Rate limit based on total items processed, not request count. Limit batch size (max 100 items).",
          }));
        }
      }

      if (endpoint.path.toLowerCase().includes("graphql") && !this.endpointHasRateLimiting(endpoint, indicators)) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "graphql_batching",
          severity: "high",
          description: `GraphQL endpoint ${endpoint.path} may allow query batching to bypass rate limits.`,
          bypassVector: "GraphQL query batching, alias abuse",
          recommendation: "Implement query complexity analysis and cost-based rate limiting. Limit query depth and batching.",
        }));
      }
    }
  }

  private analyzeBypassVectors(
    spec: ParsedOpenApiSpec,
    vulnerabilities: RateLimitVulnerability[],
    indicators: RateLimitIndicators
  ): void {
    for (const endpoint of spec.endpoints) {
      const forwardedHeaders = endpoint.parameters.filter(p =>
        p.in === "header" && /x-forwarded|x-real-ip|x-client-ip/i.test(p.name)
      );

      if (forwardedHeaders.length > 0 && indicators.has429Responses) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "header_manipulation",
          severity: "medium",
          description: `Endpoint ${endpoint.path} accepts IP forwarding headers (${forwardedHeaders.map(h => h.name).join(", ")}). If rate limiting is based on these headers, attackers can bypass limits by spoofing.`,
          bypassVector: "IP header spoofing (X-Forwarded-For, X-Real-IP)",
          recommendation: "Only trust forwarded headers from known proxies. Use connection IP for rate limiting.",
        }));
      }
    }

    const financialEndpoints = spec.endpoints.filter(e =>
      /\/(payment|transfer|withdraw|purchase|order)/i.test(e.path) &&
      e.method === "POST"
    );

    for (const endpoint of financialEndpoints) {
      if (!this.endpointHasRateLimiting(endpoint, indicators)) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "race_condition",
          severity: "critical",
          description: `Financial endpoint ${endpoint.path} has no documented rate limiting, making it vulnerable to race condition attacks where concurrent requests bypass balance checks.`,
          bypassVector: "Race condition exploitation, TOCTOU",
          recommendation: "Implement database-level locking, idempotency keys, and document rate limits.",
        }));
      }
    }
  }

  private analyzeUnauthenticatedEndpoints(
    spec: ParsedOpenApiSpec,
    vulnerabilities: RateLimitVulnerability[],
    indicators: RateLimitIndicators
  ): void {
    const sensitivePatterns = [...SENSITIVE_ENDPOINTS_PATTERNS, ...RESOURCE_INTENSIVE_PATTERNS];
    
    for (const endpoint of spec.endpoints) {
      if (this.endpointHasRateLimiting(endpoint, indicators)) continue;
      
      const hasSecurity = this.hasSecurityRequirement(endpoint, spec);
      const isSensitive = sensitivePatterns.some(pattern => pattern.test(endpoint.path));
      
      if (!hasSecurity && endpoint.method === "POST" && !isSensitive) {
        vulnerabilities.push(this.createVulnerability({
          endpoint,
          type: "missing_rate_limit",
          severity: "low",
          description: `Unauthenticated POST endpoint ${endpoint.path} has no documented rate limiting.`,
          bypassVector: "Unauthenticated abuse, spam",
          recommendation: "Consider adding IP-based rate limiting and documenting 429 responses.",
        }));
      }
    }
  }

  private hasSecurityRequirement(endpoint: OpenApiEndpoint, spec: ParsedOpenApiSpec): boolean {
    if (endpoint.security && endpoint.security.length > 0) {
      return !endpoint.security.some(s => Object.keys(s).length === 0);
    }
    return spec.securityRequirements && spec.securityRequirements.length > 0;
  }

  private createVulnerability({
    endpoint,
    type,
    severity,
    description,
    bypassVector,
    recommendation,
  }: {
    endpoint: OpenApiEndpoint;
    type: RateLimitVulnType;
    severity: "critical" | "high" | "medium" | "low";
    description: string;
    bypassVector?: string;
    recommendation: string;
  }): RateLimitVulnerability {
    this.vulnerabilityCounter++;

    const titles: Record<RateLimitVulnType, string> = {
      missing_rate_limit: "Missing Rate Limiting",
      resource_exhaustion: "Resource Exhaustion Risk",
      authentication_bypass: "Authentication Rate Limit Bypass",
      header_manipulation: "Rate Limit Header Manipulation",
      ip_rotation: "IP-Based Rate Limit Bypass",
      batch_endpoint_abuse: "Batch Endpoint Rate Limit Bypass",
      graphql_batching: "GraphQL Batching Rate Limit Bypass",
      race_condition: "Race Condition Vulnerability",
      weak_rate_limit: "Weak Rate Limiting Configuration",
    };

    const confidenceScores: Record<RateLimitVulnType, number> = {
      authentication_bypass: 0.9,
      race_condition: 0.85,
      batch_endpoint_abuse: 0.8,
      graphql_batching: 0.8,
      resource_exhaustion: 0.75,
      header_manipulation: 0.7,
      missing_rate_limit: 0.6,
      ip_rotation: 0.55,
      weak_rate_limit: 0.5,
    };

    return {
      id: `RL-${this.vulnerabilityCounter.toString().padStart(3, "0")}`,
      title: titles[type],
      severity,
      description,
      endpoint: endpoint.path,
      method: endpoint.method,
      vulnerabilityType: type,
      bypassVector,
      recommendation,
      owaspCategory: "API4:2023 Unrestricted Resource Consumption",
      cwe: "CWE-770: Allocation of Resources Without Limits or Throttling",
      confidenceScore: confidenceScores[type],
    };
  }
}

export const rateLimitAnalyzer = new RateLimitAnalyzerService();
