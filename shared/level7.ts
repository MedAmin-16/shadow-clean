import { z } from "zod";
import type { PlanLevel, EnhancedVulnerability } from "./schema";

export type RLActionType =
  | "select_tool"
  | "adjust_payload"
  | "modify_timing"
  | "change_evasion"
  | "escalate_technique"
  | "abort_attack"
  | "switch_protocol";

export type ExploitToolType =
  | "sqlmap"
  | "ffuf"
  | "nuclei"
  | "burp_intruder"
  | "hydra"
  | "metasploit"
  | "custom_script"
  | "manual_exploit";

export type SandboxAnalysisType =
  | "static_analysis"
  | "dynamic_analysis"
  | "behavioral_analysis"
  | "memory_analysis"
  | "network_analysis"
  | "code_emulation";

export interface RLState {
  targetResponseCode: number;
  wafBlocking: boolean;
  idsTriggered: boolean;
  successfulPayloads: number;
  failedPayloads: number;
  detectionEvents: number;
  currentTool: ExploitToolType;
  currentEvasionLevel: number;
  timeElapsed: number;
  creditsRemaining: number;
}

export interface RLAction {
  actionType: RLActionType;
  tool?: ExploitToolType;
  payloadModification?: string;
  timingAdjustment?: number;
  evasionLevel?: number;
  confidence: number;
  expectedReward: number;
}

export interface RLExperience {
  state: RLState;
  action: RLAction;
  reward: number;
  nextState: RLState;
  done: boolean;
}

export interface RLModel {
  modelId: string;
  version: string;
  qTable: Record<string, Record<string, number>>;
  learningRate: number;
  discountFactor: number;
  explorationRate: number;
  totalEpisodes: number;
  averageReward: number;
}

export interface RLDecisionLog {
  timestamp: string;
  state: RLState;
  selectedAction: RLAction;
  alternativeActions: RLAction[];
  reward: number;
  reasoning: string;
  toolUsed: ExploitToolType;
  success: boolean;
}

export interface ToolSelectionResult {
  selectedTool: ExploitToolType;
  confidence: number;
  alternatives: { tool: ExploitToolType; score: number }[];
  selectionReasoning: string;
  expectedSuccessRate: number;
  estimatedTime: number;
  creditCost: number;
}

export const TOOL_CAPABILITIES: Record<ExploitToolType, {
  vulnerabilityTypes: string[];
  successModifier: number;
  evasionCapability: number;
  speed: number;
  creditCost: number;
  stealthRating: number;
}> = {
  sqlmap: {
    vulnerabilityTypes: ["SQL Injection Vulnerability", "Blind SQL Injection"],
    successModifier: 0.85,
    evasionCapability: 0.7,
    speed: 0.6,
    creditCost: 100,
    stealthRating: 0.5,
  },
  ffuf: {
    vulnerabilityTypes: ["Directory Listing Enabled", "Hidden Endpoints", "API Discovery"],
    successModifier: 0.9,
    evasionCapability: 0.8,
    speed: 0.9,
    creditCost: 50,
    stealthRating: 0.3,
  },
  nuclei: {
    vulnerabilityTypes: ["CVE-*", "Known Vulnerabilities", "Template-based"],
    successModifier: 0.75,
    evasionCapability: 0.6,
    speed: 0.95,
    creditCost: 75,
    stealthRating: 0.4,
  },
  burp_intruder: {
    vulnerabilityTypes: ["Cross-Site Scripting (XSS)", "Parameter Tampering", "CSRF"],
    successModifier: 0.8,
    evasionCapability: 0.75,
    speed: 0.5,
    creditCost: 150,
    stealthRating: 0.6,
  },
  hydra: {
    vulnerabilityTypes: ["Broken Authentication", "Weak Credentials", "Brute Force"],
    successModifier: 0.7,
    evasionCapability: 0.4,
    speed: 0.3,
    creditCost: 200,
    stealthRating: 0.2,
  },
  metasploit: {
    vulnerabilityTypes: ["Remote Code Execution", "Buffer Overflow", "Exploit Chain"],
    successModifier: 0.9,
    evasionCapability: 0.85,
    speed: 0.4,
    creditCost: 300,
    stealthRating: 0.7,
  },
  custom_script: {
    vulnerabilityTypes: ["Logic Flaws", "Business Logic", "Custom Vulnerabilities"],
    successModifier: 0.65,
    evasionCapability: 0.9,
    speed: 0.7,
    creditCost: 250,
    stealthRating: 0.8,
  },
  manual_exploit: {
    vulnerabilityTypes: ["Complex Chains", "Multi-stage", "Zero-day"],
    successModifier: 0.95,
    evasionCapability: 0.95,
    speed: 0.2,
    creditCost: 500,
    stealthRating: 0.9,
  },
};

export interface SandboxEnvironment {
  id: string;
  type: "linux_container" | "windows_vm" | "browser_sandbox" | "network_simulator";
  status: "ready" | "running" | "analyzing" | "completed" | "error";
  isolationLevel: "low" | "medium" | "high" | "maximum";
  resourceLimits: {
    cpuPercent: number;
    memoryMb: number;
    networkBandwidthKbps: number;
    executionTimeMs: number;
  };
  snapshotId?: string;
}

export interface BehavioralIndicator {
  type: "file_access" | "network_call" | "process_spawn" | "registry_access" | "memory_allocation" | "syscall";
  timestamp: string;
  details: string;
  severity: "benign" | "suspicious" | "malicious";
  confidence: number;
}

export interface MemoryAnalysisResult {
  heapLayout: string;
  stackOverflowRisk: number;
  bufferOverflowVectors: string[];
  useAfterFreeDetected: boolean;
  formatStringVulnerable: boolean;
  aslrBypassPotential: number;
}

export interface CodeEmulationResult {
  instructionsExecuted: number;
  branchesAnalyzed: number;
  loopsDetected: number;
  apiCallsIntercepted: string[];
  networkConnectionsAttempted: string[];
  fileSystemAccess: string[];
  registryModifications: string[];
  maliciousPatterns: string[];
  riskScore: number;
}

export interface SandboxAnalysisResult {
  sandboxId: string;
  analysisType: SandboxAnalysisType;
  vulnerabilityId: string;
  executionTime: number;
  behavioralIndicators: BehavioralIndicator[];
  memoryAnalysis?: MemoryAnalysisResult;
  codeEmulation?: CodeEmulationResult;
  exploitConfirmed: boolean;
  riskLevel: "critical" | "high" | "medium" | "low" | "safe";
  recommendation: string;
  safeToExploit: boolean;
  potentialCollateralDamage: string[];
}

export type CausalFactorType =
  | "misconfiguration"
  | "outdated_software"
  | "design_flaw"
  | "implementation_error"
  | "operational_failure"
  | "supply_chain"
  | "human_error"
  | "unknown";

export interface CausalNode {
  id: string;
  name: string;
  type: CausalFactorType;
  probability: number;
  impact: number;
  children: string[];
  parents: string[];
  evidence: string[];
}

export interface CausalGraph {
  nodes: CausalNode[];
  rootCauses: string[];
  intermediateFactors: string[];
  observedEffects: string[];
  confidenceScore: number;
}

export interface RootCauseAnalysis {
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  primaryRootCause: CausalNode;
  contributingFactors: CausalNode[];
  causalChain: string[];
  confidenceScore: number;
  remediationTarget: string;
  preventionStrategies: string[];
  recurrenceProbability: number;
}

export interface ProbabilisticLoss {
  scenarioName: string;
  probability: number;
  minLoss: number;
  maxLoss: number;
  expectedLoss: number;
  confidenceInterval: [number, number];
  timeToMaterialize: string;
  mitigationCostToPrevent: number;
}

export interface FinancialRiskModel {
  vulnerabilityId: string;
  modelType: "monte_carlo" | "bayesian" | "decision_tree" | "markov_chain";
  scenarios: ProbabilisticLoss[];
  aggregatedRisk: {
    totalExpectedLoss: number;
    valueAtRisk95: number;
    valueAtRisk99: number;
    conditionalVaR: number;
  };
  sensitivityAnalysis: {
    factor: string;
    impactOnLoss: number;
  }[];
  modelConfidence: number;
  assumptions: string[];
}

export interface ThreatIntelligenceFeed {
  feedId: string;
  source: "mitre_att&ck" | "nvd" | "cve_mitre" | "alienvault_otx" | "abuse_ch" | "internal";
  lastUpdated: string;
  entriesCount: number;
  relevantIndicators: number;
}

export interface ThreatIndicator {
  id: string;
  type: "ip" | "domain" | "hash" | "cve" | "technique" | "pattern";
  value: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  source: string;
  relatedVulnerabilities: string[];
  mitreTechniques: string[];
}

export interface ThreatContext {
  vulnerabilityId: string;
  matchedIndicators: ThreatIndicator[];
  mitreTechniques: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    description: string;
  }[];
  activeExploits: {
    exploitId: string;
    name: string;
    availability: "public" | "private" | "unknown";
    complexity: "low" | "medium" | "high";
  }[];
  threatActors: {
    name: string;
    motivation: string;
    sophistication: string;
  }[];
  exploitationLikelihood: number;
  trendingScore: number;
}

export interface HotfixRule {
  id: string;
  type: "waf_rule" | "firewall_rule" | "rate_limit" | "ip_block" | "signature" | "virtual_patch";
  priority: "emergency" | "high" | "medium" | "low";
  action: "block" | "alert" | "rate_limit" | "redirect" | "sanitize";
  target: string;
  pattern?: string;
  conditions: {
    field: string;
    operator: "equals" | "contains" | "regex" | "gt" | "lt";
    value: string;
  }[];
  duration: number;
  autoExpire: boolean;
  rollbackPlan: string;
}

export interface DefenseIntegration {
  id: string;
  name: string;
  type: "waf" | "firewall" | "ids" | "siem" | "soar" | "edr";
  vendor: string;
  apiEndpoint: string;
  status: "connected" | "disconnected" | "error" | "pending";
  capabilities: string[];
  lastSync: string;
}

export interface HotfixDeployment {
  id: string;
  vulnerabilityId: string;
  rules: HotfixRule[];
  integrations: string[];
  status: "pending" | "deploying" | "active" | "failed" | "rolled_back";
  deployedAt?: string;
  expiresAt?: string;
  effectivenessScore?: number;
  blockedAttempts?: number;
}

export interface ManualHotfixRule {
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  severity: string;
  rules: HotfixRule[];
  copyPasteInstructions: {
    platform: "cloudflare" | "aws_waf" | "nginx" | "apache" | "generic";
    instruction: string;
    codeSnippet: string;
  }[];
}

export interface AutonomousDefenseResult {
  scanId: string;
  vulnerabilitiesProtected: number;
  hotfixesDeployed: HotfixDeployment[];
  integrationsUsed: DefenseIntegration[];
  overallProtectionScore: number;
  estimatedRiskReduction: number;
  manualReviewRequired: string[];
  rollbackCommands: string[];
  manualHotfixRules: ManualHotfixRule[];
  gracefulDegradation: boolean;
}

export interface ProphetAnalysis {
  scanId: string;
  analysisTimestamp: string;
  planLevel: PlanLevel;
  
  causalAnalyses: RootCauseAnalysis[];
  financialModels: FinancialRiskModel[];
  threatContexts: ThreatContext[];
  
  aggregatedInsights: {
    topRootCauses: { cause: string; frequency: number; impact: number }[];
    totalFinancialExposure: number;
    criticalThreats: number;
    emergingPatterns: string[];
  };
  
  strategicRecommendations: {
    priority: number;
    recommendation: string;
    expectedRoi: number;
    implementationEffort: string;
    rootCausesAddressed: string[];
  }[];
  
  creditDeduction: number;
  remainingCredits: number;
  llmModelUsed: string;
}

export interface Level7ExploiterFindings {
  rlModel: {
    totalDecisions: number;
    averageReward: number;
    explorationRate: number;
    topPerformingTools: { tool: ExploitToolType; successRate: number }[];
  };
  rlDecisionLog: RLDecisionLog[];
  toolSelections: ToolSelectionResult[];
  sandboxAnalyses: SandboxAnalysisResult[];
  
  enhancedExploitAttempts: {
    vulnerabilityId: string;
    vulnerabilityTitle: string;
    toolUsed: ExploitToolType;
    rlOptimized: boolean;
    sandboxVerified: boolean;
    success: boolean;
    evidence?: string;
    evasionTechniques: string[];
    timeToExploit: number;
    creditsUsed: number;
  }[];
  
  cognitiveMetrics: {
    adaptationCount: number;
    learningRate: number;
    explorationToExploitationRatio: number;
    averageDecisionTime: number;
  };
}

export const LEVEL7_COSTS = {
  ELITE: {
    rlOptimization: 500,
    sandboxAnalysis: 300,
    causalInference: 400,
    financialModeling: 350,
    threatIntelligence: 250,
    autonomousDefense: 600,
    prophetFullAnalysis: 1500,
  },
  STANDARD: {
    rlOptimization: 0,
    sandboxAnalysis: 0,
    causalInference: 0,
    financialModeling: 0,
    threatIntelligence: 100,
    autonomousDefense: 0,
    prophetFullAnalysis: 0,
  },
  BASIC: {
    rlOptimization: 0,
    sandboxAnalysis: 0,
    causalInference: 0,
    financialModeling: 0,
    threatIntelligence: 0,
    autonomousDefense: 0,
    prophetFullAnalysis: 0,
  },
};

export const insertHotfixRuleSchema = z.object({
  type: z.enum(["waf_rule", "firewall_rule", "rate_limit", "ip_block", "signature", "virtual_patch"]),
  priority: z.enum(["emergency", "high", "medium", "low"]),
  action: z.enum(["block", "alert", "rate_limit", "redirect", "sanitize"]),
  target: z.string(),
  pattern: z.string().optional(),
  duration: z.number().min(60).max(86400 * 30),
  autoExpire: z.boolean().default(true),
});

export type InsertHotfixRule = z.infer<typeof insertHotfixRuleSchema>;
