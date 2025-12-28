export type ShadowLogicTestType = 
  | "price_manipulation"
  | "quantity_manipulation"
  | "privilege_escalation"
  | "idor"
  | "workflow_bypass"
  | "parameter_tampering"
  | "race_condition"
  | "session_hijacking";

export type ShadowLogicPhase = 
  | "initializing"
  | "registering"
  | "mapping"
  | "analyzing"
  | "testing"
  | "reporting"
  | "completed"
  | "error";

export type ThoughtType = 
  | "observation"
  | "reasoning"
  | "action"
  | "discovery"
  | "warning"
  | "success"
  | "error";

export interface ShadowLogicThought {
  id: string;
  timestamp: string;
  type: ThoughtType;
  message: string;
  details?: string;
  screenshot?: string;
}

export interface BusinessFlowNode {
  id: string;
  url: string;
  title: string;
  type: "page" | "form" | "action" | "api_call" | "redirect";
  method?: string;
  parameters?: Record<string, string>;
  nextNodes: string[];
}

export interface BusinessFlow {
  id: string;
  name: string;
  description: string;
  nodes: BusinessFlowNode[];
  startNodeId: string;
  endNodeId: string;
  criticalNodes: string[];
}

export interface HackerProof {
  step1_normalRequest: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  step2_maliciousManipulation: {
    description: string;
    modifiedParameter: string;
    originalValue: string;
    injectedValue: string;
  };
  step3_unexpectedResponse: {
    statusCode: number;
    responseHeaders: Record<string, string>;
    responseBody: string;
    proofIndicator: string;
  };
  whyItWorked: string;
  exploitSeverity: "instant_compromise" | "confirmed_bypass" | "likely_vulnerable";
}

export interface BusinessLogicVulnerability {
  id: string;
  type: ShadowLogicTestType;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  affectedFlow: string;
  affectedEndpoint: string;
  evidence: {
    originalRequest?: string;
    modifiedRequest?: string;
    originalResponse?: string;
    exploitedResponse?: string;
    screenshot?: string;
  };
  impact: string;
  remediation: string;
  cweId?: string;
  cvssScore?: number;
  hackerProof?: HackerProof;
  verifiedExploit: boolean;
  watermark?: string;
}

export interface ShadowLogicScanConfig {
  targetUrl: string;
  registrationUrl?: string;
  loginUrl?: string;
  testCredentials?: {
    username?: string;
    password?: string;
    email?: string;
  };
  testTypes: ShadowLogicTestType[];
  maxDepth: number;
  excludeUrls?: string[];
  safetyMode: boolean;
  headless: boolean;
}

export interface ShadowLogicScanResult {
  id: string;
  userId: string;
  targetUrl: string;
  status: ShadowLogicPhase;
  startedAt: string;
  completedAt?: string;
  businessFlows: BusinessFlow[];
  vulnerabilities: BusinessLogicVulnerability[];
  thoughts: ShadowLogicThought[];
  statistics: {
    pagesVisited: number;
    formsAnalyzed: number;
    apiEndpointsDiscovered: number;
    testsExecuted: number;
    vulnerabilitiesFound: number;
    timeElapsed: number;
  };
  error?: string;
  creditCost: number;
}

export interface ShadowLogicLiveUpdate {
  scanId: string;
  type: "thought" | "phase_change" | "vulnerability" | "flow_discovered" | "completed" | "error";
  data: ShadowLogicThought | ShadowLogicPhase | BusinessLogicVulnerability | BusinessFlow | ShadowLogicScanResult | string;
  timestamp: string;
}

export const SHADOW_LOGIC_COSTS = {
  baseCost: 250,
  perFlowCost: 25,
  perVulnCost: 10,
  aiAnalysisCost: 50,
} as const;

export const SHADOW_LOGIC_TEST_DESCRIPTIONS: Record<ShadowLogicTestType, { name: string; description: string; riskLevel: string }> = {
  price_manipulation: {
    name: "Price Manipulation",
    description: "Attempts to modify prices during checkout or cart operations",
    riskLevel: "Critical"
  },
  quantity_manipulation: {
    name: "Quantity Manipulation", 
    description: "Tests for negative quantity or zero-cost order exploits",
    riskLevel: "High"
  },
  privilege_escalation: {
    name: "Privilege Escalation",
    description: "Attempts to access higher privilege functions or admin areas",
    riskLevel: "Critical"
  },
  idor: {
    name: "IDOR (Insecure Direct Object Reference)",
    description: "Tests accessing other users' resources by modifying IDs",
    riskLevel: "High"
  },
  workflow_bypass: {
    name: "Workflow Bypass",
    description: "Attempts to skip mandatory steps in business processes",
    riskLevel: "High"
  },
  parameter_tampering: {
    name: "Parameter Tampering",
    description: "Modifies hidden or client-side parameters in requests",
    riskLevel: "Medium"
  },
  race_condition: {
    name: "Race Condition",
    description: "Tests for time-of-check/time-of-use vulnerabilities",
    riskLevel: "High"
  },
  session_hijacking: {
    name: "Session Hijacking",
    description: "Analyzes session management for weaknesses",
    riskLevel: "Critical"
  }
};

export const DEFAULT_SHADOW_LOGIC_CONFIG: Partial<ShadowLogicScanConfig> = {
  maxDepth: 5,
  safetyMode: true,
  headless: true,
  testTypes: [
    "price_manipulation",
    "quantity_manipulation", 
    "privilege_escalation",
    "idor",
    "workflow_bypass",
    "parameter_tampering"
  ]
};
