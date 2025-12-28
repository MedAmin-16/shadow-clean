type VulnerabilityType = "sqli" | "xss" | "sensitive_endpoint" | "unknown";

function detectVulnerabilityType(title: string, payload?: string): VulnerabilityType {
  const titleLower = title.toLowerCase();
  const payloadLower = payload?.toLowerCase() || "";

  if (titleLower.includes("sql") || payloadLower.includes("union") || payloadLower.includes("select")) {
    return "sqli";
  }
  if (titleLower.includes("xss") || titleLower.includes("script") || payloadLower.includes("<script")) {
    return "xss";
  }
  if (titleLower.includes("env") || titleLower.includes("actuator") || titleLower.includes("sensitive")) {
    return "sensitive_endpoint";
  }
  return "unknown";
}

interface WAFRule {
  id: string;
  name: string;
  description: string;
  type: "block" | "challenge";
  pattern: string;
  target: string;
  priority: number;
}

export function generateWAFRule(
  vulnerability: {
    id: string;
    title: string;
    payload?: string;
    url?: string;
  }
): WAFRule {
  const vulnType = detectVulnerabilityType(vulnerability.title, vulnerability.payload);
  const ruleId = `WAF-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`.toUpperCase();
  
  let rule: WAFRule;

  if (vulnType === "sqli") {
    rule = {
      id: ruleId,
      name: `SQL Injection Protection - ${vulnerability.title}`,
      description: `Blocks SQL injection attempts matching the detected pattern from ${vulnerability.title}`,
      type: "block",
      pattern: vulnerability.payload || "(union|select|insert|update|delete|drop)",
      target: vulnerability.url || "/*",
      priority: 1,
    };
  } else if (vulnType === "xss") {
    rule = {
      id: ruleId,
      name: `XSS Protection - ${vulnerability.title}`,
      description: `Blocks XSS attempts matching the detected pattern from ${vulnerability.title}`,
      type: "block",
      pattern: vulnerability.payload || "(<script|onerror|onload|javascript:)",
      target: vulnerability.url || "/*",
      priority: 1,
    };
  } else if (vulnType === "sensitive_endpoint") {
    const path = vulnerability.url?.split("?")[0] || "/.env";
    rule = {
      id: ruleId,
      name: `Sensitive Endpoint Protection - ${path}`,
      description: `Challenges (Captcha) or blocks access to sensitive endpoint: ${path}`,
      type: "challenge",
      pattern: path,
      target: path,
      priority: 2,
    };
  } else {
    rule = {
      id: ruleId,
      name: `Generic Protection - ${vulnerability.title}`,
      description: `Generic WAF rule for ${vulnerability.title}`,
      type: "block",
      pattern: vulnerability.payload || ".*",
      target: vulnerability.url || "/*",
      priority: 3,
    };
  }

  return rule;
}

export function formatWAFRuleForCloudflare(rule: WAFRule): Record<string, unknown> {
  return {
    name: rule.name,
    description: rule.description,
    expression: `(cf.threat_score > 0) or (http.request.uri.path contains "${rule.pattern}")`,
    action: rule.type === "challenge" ? "challenge" : "block",
    priority: rule.priority,
    enabled: true,
  };
}

export function formatWAFRuleForAWS(rule: WAFRule): Record<string, unknown> {
  return {
    Name: rule.name,
    MetricName: rule.id,
    Statements: [
      {
        ByteMatchStatement: {
          SearchString: rule.pattern,
          FieldToMatch: { UriPath: {} },
          TextTransformation: "URL_DECODE",
          PositionalConstraint: "CONTAINS",
        },
      },
    ],
    Action: {
      [rule.type === "challenge" ? "CaptchaAction" : "BlockAction"]: {},
    },
    VisibilityConfig: {
      SampledRequestsEnabled: true,
      CloudWatchMetricsEnabled: true,
      MetricName: rule.id,
    },
  };
}
