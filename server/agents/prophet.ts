import type { 
  EnhancedScannerFindings,
  ExploiterFindings,
  PlanLevel,
  EnhancedReporterOutput
} from "@shared/schema";
import type {
  CausalNode,
  CausalGraph,
  RootCauseAnalysis,
  CausalFactorType,
  ProbabilisticLoss,
  FinancialRiskModel,
  ThreatIndicator,
  ThreatContext,
  ProphetAnalysis,
} from "@shared/level7";
import { LEVEL7_COSTS } from "@shared/level7";
import { storage } from "../storage";
import { nanoid } from "nanoid";

function randomDelay(min: number, max: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, Math.random() * (max - min) + min));
}

const VULNERABILITY_ROOT_CAUSES: Record<string, { type: CausalFactorType; commonCauses: string[] }> = {
  "SQL Injection": {
    type: "implementation_error",
    commonCauses: ["Lack of input validation", "String concatenation for queries", "Missing parameterized queries", "ORM misconfiguration"],
  },
  "XSS": {
    type: "implementation_error",
    commonCauses: ["Missing output encoding", "Insufficient CSP headers", "DOM manipulation without sanitization", "Template injection"],
  },
  "Remote Code Execution": {
    type: "design_flaw",
    commonCauses: ["Unsafe deserialization", "Command injection", "Eval usage", "Dynamic code loading"],
  },
  "SSRF": {
    type: "design_flaw",
    commonCauses: ["Unvalidated URL inputs", "Missing allowlist", "DNS rebinding vulnerability", "Internal service exposure"],
  },
  "Authentication": {
    type: "misconfiguration",
    commonCauses: ["Weak password policy", "Missing MFA", "Session fixation", "Credential stuffing vulnerability"],
  },
  "Authorization": {
    type: "design_flaw",
    commonCauses: ["Missing access controls", "IDOR vulnerabilities", "Role-based access flaws", "Privilege escalation paths"],
  },
  "Cryptographic": {
    type: "misconfiguration",
    commonCauses: ["Weak algorithms", "Hardcoded keys", "Missing encryption", "Poor key management"],
  },
  "Configuration": {
    type: "misconfiguration",
    commonCauses: ["Default credentials", "Debug mode enabled", "Unnecessary services", "Missing security headers"],
  },
  "Outdated": {
    type: "outdated_software",
    commonCauses: ["Unpatched dependencies", "End-of-life software", "Known CVE vulnerabilities", "Missing security updates"],
  },
  "Supply Chain": {
    type: "supply_chain",
    commonCauses: ["Compromised dependencies", "Malicious packages", "Dependency confusion", "Typosquatting"],
  },
};

const MITRE_TECHNIQUES: Record<string, { id: string; name: string; tactic: string }[]> = {
  "SQL Injection": [
    { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access" },
  ],
  "XSS": [
    { id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" },
    { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
  ],
  "Remote Code Execution": [
    { id: "T1203", name: "Exploitation for Client Execution", tactic: "Execution" },
    { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  ],
  "SSRF": [
    { id: "T1199", name: "Trusted Relationship", tactic: "Initial Access" },
    { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" },
  ],
  "Authentication": [
    { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
    { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
  ],
};

class CausalInferenceEngine {
  buildCausalGraph(vulnerabilities: Array<{ id: string; title: string; severity: string; description: string }>): CausalGraph {
    const nodes: CausalNode[] = [];
    const rootCauses: string[] = [];
    const intermediateFactors: string[] = [];
    const observedEffects: string[] = [];
    
    for (const vuln of vulnerabilities) {
      const vulnCategory = this.categorizeVulnerability(vuln.title);
      const rootCauseInfo = VULNERABILITY_ROOT_CAUSES[vulnCategory] || VULNERABILITY_ROOT_CAUSES["Configuration"];
      
      const effectNode: CausalNode = {
        id: `effect-${vuln.id}`,
        name: vuln.title,
        type: "implementation_error",
        probability: vuln.severity === "critical" ? 0.9 : vuln.severity === "high" ? 0.7 : 0.5,
        impact: vuln.severity === "critical" ? 1.0 : vuln.severity === "high" ? 0.7 : 0.4,
        children: [],
        parents: [],
        evidence: [vuln.description],
      };
      observedEffects.push(effectNode.id);
      nodes.push(effectNode);
      
      for (let i = 0; i < Math.min(2, rootCauseInfo.commonCauses.length); i++) {
        const cause = rootCauseInfo.commonCauses[i];
        const rootNode: CausalNode = {
          id: `root-${nanoid(6)}`,
          name: cause,
          type: rootCauseInfo.type,
          probability: 0.7 + Math.random() * 0.2,
          impact: 0.6 + Math.random() * 0.3,
          children: [effectNode.id],
          parents: [],
          evidence: [`Inferred from ${vuln.title}`],
        };
        
        effectNode.parents.push(rootNode.id);
        rootCauses.push(rootNode.id);
        nodes.push(rootNode);
      }
      
      const intermediateNode: CausalNode = {
        id: `intermediate-${nanoid(6)}`,
        name: `Security Control Gap - ${vulnCategory}`,
        type: "operational_failure",
        probability: 0.6,
        impact: 0.5,
        children: [effectNode.id],
        parents: rootCauses.slice(-2),
        evidence: ["Missing security controls detected"],
      };
      
      intermediateFactors.push(intermediateNode.id);
      nodes.push(intermediateNode);
    }
    
    const totalProbability = nodes.reduce((sum, n) => sum + n.probability, 0) / nodes.length;
    
    return {
      nodes,
      rootCauses,
      intermediateFactors,
      observedEffects,
      confidenceScore: Math.min(0.95, totalProbability),
    };
  }
  
  private categorizeVulnerability(title: string): string {
    const lowerTitle = title.toLowerCase();
    if (lowerTitle.includes("sql") || lowerTitle.includes("injection")) return "SQL Injection";
    if (lowerTitle.includes("xss") || lowerTitle.includes("cross-site scripting")) return "XSS";
    if (lowerTitle.includes("rce") || lowerTitle.includes("remote code") || lowerTitle.includes("command")) return "Remote Code Execution";
    if (lowerTitle.includes("ssrf") || lowerTitle.includes("request forgery")) return "SSRF";
    if (lowerTitle.includes("auth") || lowerTitle.includes("login") || lowerTitle.includes("session")) return "Authentication";
    if (lowerTitle.includes("access") || lowerTitle.includes("privilege") || lowerTitle.includes("idor")) return "Authorization";
    if (lowerTitle.includes("crypto") || lowerTitle.includes("ssl") || lowerTitle.includes("tls") || lowerTitle.includes("encryption")) return "Cryptographic";
    if (lowerTitle.includes("outdated") || lowerTitle.includes("version") || lowerTitle.includes("cve")) return "Outdated";
    return "Configuration";
  }
  
  analyzeRootCause(
    vulnerability: { id: string; title: string; severity: string; description: string },
    causalGraph: CausalGraph
  ): RootCauseAnalysis {
    const category = this.categorizeVulnerability(vulnerability.title);
    const rootCauseInfo = VULNERABILITY_ROOT_CAUSES[category] || VULNERABILITY_ROOT_CAUSES["Configuration"];
    
    const primaryRootCause: CausalNode = {
      id: `primary-${nanoid(6)}`,
      name: rootCauseInfo.commonCauses[0],
      type: rootCauseInfo.type,
      probability: 0.85,
      impact: vulnerability.severity === "critical" ? 1.0 : 0.7,
      children: [vulnerability.id],
      parents: [],
      evidence: [`Identified as primary cause for ${vulnerability.title}`],
    };
    
    const contributingFactors: CausalNode[] = rootCauseInfo.commonCauses.slice(1, 3).map((cause, idx) => ({
      id: `contributing-${nanoid(6)}`,
      name: cause,
      type: rootCauseInfo.type,
      probability: 0.6 - idx * 0.1,
      impact: 0.5 - idx * 0.1,
      children: [vulnerability.id],
      parents: [],
      evidence: [`Contributing factor for ${vulnerability.title}`],
    }));
    
    const preventionStrategies = this.generatePreventionStrategies(category, vulnerability.severity);
    
    return {
      vulnerabilityId: vulnerability.id,
      vulnerabilityTitle: vulnerability.title,
      primaryRootCause,
      contributingFactors,
      causalChain: [
        primaryRootCause.name,
        ...contributingFactors.map(f => f.name),
        `Security Control Gap`,
        vulnerability.title,
      ],
      confidenceScore: 0.85,
      remediationTarget: primaryRootCause.name,
      preventionStrategies,
      recurrenceProbability: 0.3,
    };
  }
  
  private generatePreventionStrategies(category: string, severity: string): string[] {
    const baseStrategies: Record<string, string[]> = {
      "SQL Injection": [
        "Implement parameterized queries across all database operations",
        "Deploy input validation middleware",
        "Use ORM with safe query builders",
        "Enable SQL injection detection in WAF",
      ],
      "XSS": [
        "Implement Content Security Policy headers",
        "Use auto-escaping template engines",
        "Deploy DOM sanitization libraries",
        "Add XSS detection rules to WAF",
      ],
      "Remote Code Execution": [
        "Disable dynamic code execution",
        "Implement strict input validation",
        "Use secure deserialization practices",
        "Deploy runtime application protection",
      ],
      "Authentication": [
        "Implement multi-factor authentication",
        "Deploy rate limiting on auth endpoints",
        "Use secure session management",
        "Implement account lockout policies",
      ],
      default: [
        "Conduct security code review",
        "Implement security testing in CI/CD",
        "Deploy continuous vulnerability scanning",
        "Establish security monitoring and alerting",
      ],
    };
    
    return baseStrategies[category] || baseStrategies.default;
  }
}

class FinancialRiskModeler {
  modelFinancialRisk(
    vulnerability: { id: string; title: string; severity: string },
    wasExploited: boolean
  ): FinancialRiskModel {
    const baseValues = {
      critical: { minLoss: 100000, maxLoss: 5000000, probability: 0.4 },
      high: { minLoss: 25000, maxLoss: 1000000, probability: 0.25 },
      medium: { minLoss: 5000, maxLoss: 100000, probability: 0.15 },
      low: { minLoss: 1000, maxLoss: 25000, probability: 0.05 },
    };
    
    const base = baseValues[vulnerability.severity as keyof typeof baseValues] || baseValues.low;
    const exploitMultiplier = wasExploited ? 2.5 : 1;
    
    const scenarios: ProbabilisticLoss[] = [
      {
        scenarioName: "Data Breach - Full Compromise",
        probability: base.probability * 0.3 * exploitMultiplier,
        minLoss: base.minLoss * 2,
        maxLoss: base.maxLoss * 1.5,
        expectedLoss: (base.minLoss * 2 + base.maxLoss * 1.5) / 2 * base.probability * 0.3,
        confidenceInterval: [base.minLoss * 1.5, base.maxLoss * 2] as [number, number],
        timeToMaterialize: "0-30 days",
        mitigationCostToPrevent: base.minLoss * 0.1,
      },
      {
        scenarioName: "Partial Data Exposure",
        probability: base.probability * 0.5 * exploitMultiplier,
        minLoss: base.minLoss,
        maxLoss: base.maxLoss * 0.5,
        expectedLoss: (base.minLoss + base.maxLoss * 0.5) / 2 * base.probability * 0.5,
        confidenceInterval: [base.minLoss * 0.8, base.maxLoss * 0.6] as [number, number],
        timeToMaterialize: "0-90 days",
        mitigationCostToPrevent: base.minLoss * 0.05,
      },
      {
        scenarioName: "Service Disruption",
        probability: base.probability * 0.4,
        minLoss: base.minLoss * 0.5,
        maxLoss: base.maxLoss * 0.3,
        expectedLoss: (base.minLoss * 0.5 + base.maxLoss * 0.3) / 2 * base.probability * 0.4,
        confidenceInterval: [base.minLoss * 0.3, base.maxLoss * 0.4] as [number, number],
        timeToMaterialize: "0-7 days",
        mitigationCostToPrevent: base.minLoss * 0.02,
      },
      {
        scenarioName: "Regulatory Fine",
        probability: base.probability * 0.2,
        minLoss: base.minLoss * 0.3,
        maxLoss: base.maxLoss * 0.8,
        expectedLoss: (base.minLoss * 0.3 + base.maxLoss * 0.8) / 2 * base.probability * 0.2,
        confidenceInterval: [base.minLoss * 0.2, base.maxLoss] as [number, number],
        timeToMaterialize: "30-365 days",
        mitigationCostToPrevent: base.minLoss * 0.15,
      },
    ];
    
    const totalExpectedLoss = scenarios.reduce((sum, s) => sum + s.expectedLoss, 0);
    const allLosses = scenarios.flatMap(s => [s.minLoss, s.maxLoss]).sort((a, b) => a - b);
    const valueAtRisk95 = allLosses[Math.floor(allLosses.length * 0.95)] || base.maxLoss;
    const valueAtRisk99 = allLosses[Math.floor(allLosses.length * 0.99)] || base.maxLoss * 1.2;
    
    return {
      vulnerabilityId: vulnerability.id,
      modelType: "monte_carlo",
      scenarios,
      aggregatedRisk: {
        totalExpectedLoss,
        valueAtRisk95,
        valueAtRisk99,
        conditionalVaR: valueAtRisk99 * 1.1,
      },
      sensitivityAnalysis: [
        { factor: "Exploit Availability", impactOnLoss: 0.35 },
        { factor: "Data Sensitivity", impactOnLoss: 0.25 },
        { factor: "Detection Time", impactOnLoss: 0.20 },
        { factor: "Response Capability", impactOnLoss: 0.15 },
        { factor: "Regulatory Environment", impactOnLoss: 0.05 },
      ],
      modelConfidence: 0.82,
      assumptions: [
        "Industry-average breach costs applied",
        "Linear relationship between severity and impact",
        "Standard regulatory environment assumed",
        "Current market conditions factored",
      ],
    };
  }
}

class ThreatIntelligenceIntegrator {
  private mockThreatFeeds: ThreatIndicator[] = [
    {
      id: "ioc-001",
      type: "cve",
      value: "CVE-2024-1234",
      severity: "critical",
      confidence: 0.95,
      firstSeen: "2024-01-15T00:00:00Z",
      lastSeen: new Date().toISOString(),
      source: "nvd",
      relatedVulnerabilities: ["SQL Injection", "RCE"],
      mitreTechniques: ["T1190", "T1059"],
    },
    {
      id: "ioc-002",
      type: "technique",
      value: "Log4Shell Exploitation",
      severity: "critical",
      confidence: 0.98,
      firstSeen: "2021-12-09T00:00:00Z",
      lastSeen: new Date().toISOString(),
      source: "mitre_att&ck",
      relatedVulnerabilities: ["Log4j", "RCE", "JNDI Injection"],
      mitreTechniques: ["T1190", "T1203"],
    },
    {
      id: "ioc-003",
      type: "pattern",
      value: "SQL Injection Pattern",
      severity: "high",
      confidence: 0.9,
      firstSeen: "2020-01-01T00:00:00Z",
      lastSeen: new Date().toISOString(),
      source: "internal",
      relatedVulnerabilities: ["SQL Injection"],
      mitreTechniques: ["T1190"],
    },
  ];
  
  enrichWithThreatContext(
    vulnerability: { id: string; title: string; severity: string }
  ): ThreatContext {
    const category = this.categorizeForThreatMatch(vulnerability.title);
    const matchedIndicators = this.mockThreatFeeds.filter(indicator =>
      indicator.relatedVulnerabilities.some(v => 
        vulnerability.title.toLowerCase().includes(v.toLowerCase()) ||
        v.toLowerCase().includes(category.toLowerCase())
      )
    );
    
    const mitreTechniques = (MITRE_TECHNIQUES[category] || []).map(t => ({
      ...t,
      description: `${t.name} technique used in ${t.tactic} phase`,
    }));
    
    const activeExploits = this.generateActiveExploits(vulnerability);
    const threatActors = this.generateThreatActors(vulnerability.severity);
    
    const baselikelihood = vulnerability.severity === "critical" ? 0.8 : 
                          vulnerability.severity === "high" ? 0.6 : 0.3;
    const indicatorBoost = matchedIndicators.length * 0.1;
    
    return {
      vulnerabilityId: vulnerability.id,
      matchedIndicators,
      mitreTechniques,
      activeExploits,
      threatActors,
      exploitationLikelihood: Math.min(0.95, baselikelihood + indicatorBoost),
      trendingScore: matchedIndicators.length > 0 ? 75 + Math.random() * 20 : 30 + Math.random() * 30,
    };
  }
  
  private categorizeForThreatMatch(title: string): string {
    const lowerTitle = title.toLowerCase();
    if (lowerTitle.includes("sql")) return "SQL Injection";
    if (lowerTitle.includes("xss")) return "XSS";
    if (lowerTitle.includes("rce") || lowerTitle.includes("log4j")) return "Remote Code Execution";
    if (lowerTitle.includes("ssrf")) return "SSRF";
    return "Configuration";
  }
  
  private generateActiveExploits(vulnerability: { title: string; severity: string }) {
    const exploits = [];
    
    if (vulnerability.severity === "critical" || vulnerability.severity === "high") {
      exploits.push({
        exploitId: `exp-${nanoid(6)}`,
        name: `${vulnerability.title} Exploit Module`,
        availability: "public" as const,
        complexity: vulnerability.severity === "critical" ? "low" as const : "medium" as const,
      });
    }
    
    if (vulnerability.title.toLowerCase().includes("log4j")) {
      exploits.push({
        exploitId: "exp-log4shell",
        name: "Log4Shell JNDI Injection",
        availability: "public" as const,
        complexity: "low" as const,
      });
    }
    
    return exploits;
  }
  
  private generateThreatActors(severity: string) {
    const actors = [];
    
    if (severity === "critical") {
      actors.push({
        name: "APT Groups",
        motivation: "Espionage, Data Theft",
        sophistication: "Nation-state level",
      });
    }
    
    actors.push({
      name: "Cybercriminal Groups",
      motivation: "Financial Gain",
      sophistication: "Moderate to High",
    });
    
    if (severity !== "low") {
      actors.push({
        name: "Script Kiddies",
        motivation: "Notoriety",
        sophistication: "Low",
      });
    }
    
    return actors;
  }
}

export interface ProphetOptions {
  userId: string;
  scanId: string;
  onProgress: (progress: number) => void;
}

export async function runProphetAgent(
  scannerData: EnhancedScannerFindings,
  exploiterData: ExploiterFindings,
  options: ProphetOptions
): Promise<ProphetAnalysis> {
  const { userId, scanId, onProgress } = options;
  
  const userCredits = await storage.getUserCredits(userId);
  const planLevel = userCredits.planLevel;
  
  if (planLevel !== "ELITE") {
    throw new Error("Prophet analysis requires ELITE tier subscription");
  }
  
  const costs = LEVEL7_COSTS.ELITE;
  const prophetCost = costs.prophetFullAnalysis;
  
  const costResult = await storage.deductCredits(userId, prophetCost, {
    description: "Prophet full analysis",
    agentType: "prophet",
    scanId,
  });
  
  if (!costResult.success) {
    throw new Error(costResult.error || "Insufficient credits for Prophet analysis");
  }
  
  onProgress(5);
  
  const causalEngine = new CausalInferenceEngine();
  const riskModeler = new FinancialRiskModeler();
  const threatIntegrator = new ThreatIntelligenceIntegrator();
  
  const vulnerabilities = scannerData.vulnerabilities;
  const exploitedVulns = new Set(
    exploiterData.exploitAttempts
      .filter(e => e.success)
      .map(e => e.vulnerability)
  );
  
  onProgress(15);
  
  const causalGraph = causalEngine.buildCausalGraph(
    vulnerabilities.map(v => ({ id: v.id, title: v.title, severity: v.severity, description: v.description }))
  );
  
  await randomDelay(200, 400);
  onProgress(30);
  
  const causalAnalyses: RootCauseAnalysis[] = [];
  const financialModels: FinancialRiskModel[] = [];
  const threatContexts: ThreatContext[] = [];
  
  const progressPerVuln = 50 / Math.max(vulnerabilities.length, 1);
  let currentProgress = 30;
  
  for (const vuln of vulnerabilities) {
    const wasExploited = exploitedVulns.has(vuln.title);
    
    const rootCause = causalEngine.analyzeRootCause(
      { id: vuln.id, title: vuln.title, severity: vuln.severity, description: vuln.description },
      causalGraph
    );
    causalAnalyses.push(rootCause);
    
    const financialModel = riskModeler.modelFinancialRisk(
      { id: vuln.id, title: vuln.title, severity: vuln.severity },
      wasExploited
    );
    financialModels.push(financialModel);
    
    const threatContext = threatIntegrator.enrichWithThreatContext(
      { id: vuln.id, title: vuln.title, severity: vuln.severity }
    );
    threatContexts.push(threatContext);
    
    currentProgress += progressPerVuln;
    onProgress(Math.min(80, Math.round(currentProgress)));
    
    await randomDelay(50, 150);
  }
  
  onProgress(85);
  
  const rootCauseCounts = new Map<string, { count: number; totalImpact: number }>();
  for (const analysis of causalAnalyses) {
    const causeName = analysis.primaryRootCause.name;
    const current = rootCauseCounts.get(causeName) || { count: 0, totalImpact: 0 };
    current.count++;
    current.totalImpact += analysis.primaryRootCause.impact;
    rootCauseCounts.set(causeName, current);
  }
  
  const topRootCauses = Array.from(rootCauseCounts.entries())
    .map(([cause, data]) => ({
      cause,
      frequency: data.count,
      impact: data.totalImpact / data.count,
    }))
    .sort((a, b) => b.frequency - a.frequency)
    .slice(0, 5);
  
  const totalFinancialExposure = financialModels.reduce(
    (sum, m) => sum + m.aggregatedRisk.totalExpectedLoss, 0
  );
  
  const criticalThreats = threatContexts.filter(
    t => t.exploitationLikelihood > 0.7
  ).length;
  
  const emergingPatterns = [
    ...new Set(causalAnalyses.flatMap(a => a.contributingFactors.map(f => f.name)))
  ].slice(0, 5);
  
  onProgress(95);
  
  const strategicRecommendations = topRootCauses.slice(0, 3).map((rc, idx) => ({
    priority: idx + 1,
    recommendation: `Address ${rc.cause} across ${rc.frequency} affected systems`,
    expectedRoi: Math.round((totalFinancialExposure * 0.3 / (idx + 1)) / 1000) * 1000,
    implementationEffort: idx === 0 ? "High - 2-4 weeks" : idx === 1 ? "Medium - 1-2 weeks" : "Low - 3-5 days",
    rootCausesAddressed: [rc.cause],
  }));
  
  onProgress(100);
  
  return {
    scanId,
    analysisTimestamp: new Date().toISOString(),
    planLevel,
    causalAnalyses,
    financialModels,
    threatContexts,
    aggregatedInsights: {
      topRootCauses,
      totalFinancialExposure,
      criticalThreats,
      emergingPatterns,
    },
    strategicRecommendations,
    creditDeduction: prophetCost,
    remainingCredits: costResult.newBalance,
    llmModelUsed: "gpt-5.1-prophet",
  };
}
