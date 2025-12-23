import { z } from "zod";

export type EvasionTechnique = 
  | "timing_jitter"
  | "request_fragmentation"
  | "encoding_obfuscation"
  | "protocol_manipulation"
  | "header_spoofing"
  | "payload_polymorphism"
  | "traffic_mimicry"
  | "decoy_requests";

export type StealthLevel = "passive" | "cautious" | "aggressive" | "maximum";

export interface EvasionConfig {
  technique: EvasionTechnique;
  enabled: boolean;
  parameters: Record<string, unknown>;
  successRate: number;
  detectionRisk: number;
}

export const EVASION_TECHNIQUES: Record<EvasionTechnique, EvasionConfig> = {
  timing_jitter: {
    technique: "timing_jitter",
    enabled: true,
    parameters: {
      minDelayMs: 500,
      maxDelayMs: 3000,
      burstLimit: 3,
      cooldownMs: 5000,
    },
    successRate: 0.85,
    detectionRisk: 0.1,
  },
  request_fragmentation: {
    technique: "request_fragmentation",
    enabled: true,
    parameters: {
      chunkSize: 256,
      fragmentDelay: 100,
      reassemblyTimeout: 5000,
    },
    successRate: 0.7,
    detectionRisk: 0.2,
  },
  encoding_obfuscation: {
    technique: "encoding_obfuscation",
    enabled: true,
    parameters: {
      encodings: ["base64", "url", "unicode", "hex", "double-url"],
      mixedEncoding: true,
      caseRandomization: true,
    },
    successRate: 0.75,
    detectionRisk: 0.25,
  },
  protocol_manipulation: {
    technique: "protocol_manipulation",
    enabled: true,
    parameters: {
      httpVersionVariation: true,
      methodOverride: true,
      headerCasing: "random",
      connectionReuse: false,
    },
    successRate: 0.65,
    detectionRisk: 0.3,
  },
  header_spoofing: {
    technique: "header_spoofing",
    enabled: true,
    parameters: {
      rotateUserAgent: true,
      spoofReferer: true,
      addXForwardedFor: true,
      randomizeAcceptHeaders: true,
    },
    successRate: 0.8,
    detectionRisk: 0.15,
  },
  payload_polymorphism: {
    technique: "payload_polymorphism",
    enabled: true,
    parameters: {
      mutationRate: 0.3,
      commentInjection: true,
      whitespaceManipulation: true,
      equivalentSubstitution: true,
    },
    successRate: 0.7,
    detectionRisk: 0.35,
  },
  traffic_mimicry: {
    technique: "traffic_mimicry",
    enabled: true,
    parameters: {
      mimicBrowser: "chrome",
      includeTypicalHeaders: true,
      naturalTimingPattern: true,
      mixWithLegitRequests: true,
    },
    successRate: 0.9,
    detectionRisk: 0.05,
  },
  decoy_requests: {
    technique: "decoy_requests",
    enabled: false,
    parameters: {
      decoyRatio: 0.3,
      decoyEndpoints: ["/", "/about", "/contact", "/api/health"],
      blendPattern: "random",
    },
    successRate: 0.6,
    detectionRisk: 0.4,
  },
};

export const STEALTH_PROFILES: Record<StealthLevel, EvasionTechnique[]> = {
  passive: ["timing_jitter", "header_spoofing"],
  cautious: ["timing_jitter", "header_spoofing", "traffic_mimicry", "encoding_obfuscation"],
  aggressive: ["timing_jitter", "header_spoofing", "traffic_mimicry", "encoding_obfuscation", "request_fragmentation", "payload_polymorphism"],
  maximum: ["timing_jitter", "header_spoofing", "traffic_mimicry", "encoding_obfuscation", "request_fragmentation", "payload_polymorphism", "protocol_manipulation", "decoy_requests"],
};

export interface VulnerabilityChainStep {
  stepNumber: number;
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  exploitTechnique: string;
  preconditions: string[];
  expectedOutcome: string;
  accessLevel: "none" | "read" | "write" | "execute" | "admin";
  persistence: boolean;
}

export interface VulnerabilityChain {
  id: string;
  name: string;
  description: string;
  steps: VulnerabilityChainStep[];
  totalRiskScore: number;
  estimatedTimeMinutes: number;
  requiredCredits: number;
  successProbability: number;
  accessLevelAchieved: "none" | "read" | "write" | "execute" | "admin";
  impactCategories: string[];
}

export interface ChainTemplate {
  id: string;
  name: string;
  description: string;
  entryVulnerabilities: string[];
  escalationPaths: string[][];
  impactCategories: string[];
}

export const VULNERABILITY_CHAIN_TEMPLATES: ChainTemplate[] = [
  {
    id: "chain-sql-rce",
    name: "SQL Injection to Remote Code Execution",
    description: "Leverages SQL injection to write files, then achieves code execution through file upload or command injection.",
    entryVulnerabilities: ["SQL Injection Vulnerability"],
    escalationPaths: [
      ["SQL Injection", "File Write", "Web Shell Upload", "Remote Code Execution"],
      ["SQL Injection", "Credential Extraction", "SSH Access", "Privilege Escalation"],
    ],
    impactCategories: ["data_exfiltration", "system_compromise", "persistence"],
  },
  {
    id: "chain-ssrf-internal",
    name: "SSRF to Internal Network Access",
    description: "Uses SSRF to access internal services, potentially leading to cloud metadata exposure or internal API abuse.",
    entryVulnerabilities: ["Server-Side Request Forgery (SSRF)"],
    escalationPaths: [
      ["SSRF", "Cloud Metadata Access", "IAM Credential Theft", "Cloud Account Compromise"],
      ["SSRF", "Internal API Discovery", "Authentication Bypass", "Data Access"],
    ],
    impactCategories: ["cloud_compromise", "credential_theft", "internal_network_access"],
  },
  {
    id: "chain-xss-takeover",
    name: "XSS to Account Takeover",
    description: "Exploits XSS to steal session tokens or credentials, leading to account compromise.",
    entryVulnerabilities: ["Cross-Site Scripting (XSS)"],
    escalationPaths: [
      ["XSS", "Session Token Theft", "Session Hijacking", "Account Takeover"],
      ["XSS", "Credential Harvesting", "Password Reset Abuse", "Account Takeover"],
    ],
    impactCategories: ["account_takeover", "session_hijacking", "credential_theft"],
  },
  {
    id: "chain-idor-admin",
    name: "IDOR to Admin Privilege Escalation",
    description: "Exploits insecure direct object references to access admin resources or escalate privileges.",
    entryVulnerabilities: ["Insecure Direct Object Reference (IDOR)", "Privilege Escalation Vulnerability"],
    escalationPaths: [
      ["IDOR", "Admin Panel Access", "Configuration Modification", "System Control"],
      ["IDOR", "User Data Access", "Role Manipulation", "Privilege Escalation"],
    ],
    impactCategories: ["privilege_escalation", "unauthorized_access", "data_breach"],
  },
  {
    id: "chain-auth-bypass-persistence",
    name: "Authentication Bypass to Persistent Access",
    description: "Bypasses authentication mechanisms to gain access, then establishes persistence.",
    entryVulnerabilities: ["Broken Authentication - Session Fixation", "Default MySQL Credentials"],
    escalationPaths: [
      ["Auth Bypass", "Session Manipulation", "Backdoor Account Creation", "Persistent Access"],
      ["Default Credentials", "Database Access", "User Creation", "Persistent Access"],
    ],
    impactCategories: ["authentication_bypass", "persistence", "backdoor"],
  },
];

export interface StealthExploitResult {
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  success: boolean;
  technique: string;
  stealthLevel: StealthLevel;
  evasionTechniquesUsed: EvasionTechnique[];
  wafEvaded: boolean;
  idsEvaded: boolean;
  detectionEvents: number;
  evidence?: string;
  chainPosition?: number;
  chainId?: string;
}

export interface StealthModeConfig {
  enabled: boolean;
  stealthLevel: StealthLevel;
  wafDetected: boolean;
  idsDetected: boolean;
  adaptiveMode: boolean;
  maxDetectionEvents: number;
  abortOnDetection: boolean;
}

export const insertStealthConfigSchema = z.object({
  enabled: z.boolean().default(true),
  stealthLevel: z.enum(["passive", "cautious", "aggressive", "maximum"]).default("cautious"),
  adaptiveMode: z.boolean().default(true),
  maxDetectionEvents: z.number().min(0).max(10).default(3),
  abortOnDetection: z.boolean().default(false),
});

export interface ExploiterStealthFindings {
  exploitAttempts: StealthExploitResult[];
  accessGained: boolean;
  riskLevel: "critical" | "high" | "medium" | "low";
  stealthMode: StealthModeConfig;
  vulnerabilityChains: VulnerabilityChain[];
  totalDetectionEvents: number;
  evasionSuccessRate: number;
  creditsDeducted: number;
  stealthDecisionLog: StealthDecisionLog[];
}

export type StealthDecisionType =
  | "stealth_mode_activated"
  | "evasion_technique_applied"
  | "waf_detected_adapting"
  | "ids_detected_adapting"
  | "chain_identified"
  | "chain_step_executed"
  | "detection_event"
  | "abort_triggered"
  | "stealth_level_adjusted";

export interface StealthDecisionLog {
  timestamp: string;
  decisionType: StealthDecisionType;
  description: string;
  technique?: EvasionTechnique;
  chainId?: string;
  detectionRisk?: number;
  metadata?: Record<string, unknown>;
}

export const STEALTH_COSTS = {
  BASIC: { baseCost: 100, perChainCost: 50 },
  STANDARD: { baseCost: 300, perChainCost: 150 },
  ELITE: { baseCost: 750, perChainCost: 300 },
};
