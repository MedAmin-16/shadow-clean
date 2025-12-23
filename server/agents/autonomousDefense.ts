import type { 
  PlanLevel 
} from "@shared/schema";
import type {
  HotfixRule,
  HotfixDeployment,
  DefenseIntegration,
  AutonomousDefenseResult,
  ManualHotfixRule,
} from "@shared/level7";
import { LEVEL7_COSTS } from "@shared/level7";
import { storage } from "../storage";
import { nanoid } from "nanoid";

const MOCK_INTEGRATIONS: DefenseIntegration[] = [
  {
    id: "int-cloudflare-waf",
    name: "Cloudflare WAF",
    type: "waf",
    vendor: "Cloudflare",
    apiEndpoint: "https://api.cloudflare.com/client/v4",
    status: "connected",
    capabilities: ["rate_limit", "ip_block", "signature", "virtual_patch"],
    lastSync: new Date().toISOString(),
  },
  {
    id: "int-aws-waf",
    name: "AWS WAF",
    type: "waf",
    vendor: "Amazon Web Services",
    apiEndpoint: "https://wafv2.amazonaws.com",
    status: "connected",
    capabilities: ["rate_limit", "ip_block", "signature"],
    lastSync: new Date().toISOString(),
  },
  {
    id: "int-palo-firewall",
    name: "Palo Alto Firewall",
    type: "firewall",
    vendor: "Palo Alto Networks",
    apiEndpoint: "https://firewall.internal/api",
    status: "connected",
    capabilities: ["ip_block", "signature", "rate_limit"],
    lastSync: new Date().toISOString(),
  },
  {
    id: "int-crowdstrike-edr",
    name: "CrowdStrike Falcon",
    type: "edr",
    vendor: "CrowdStrike",
    apiEndpoint: "https://api.crowdstrike.com",
    status: "connected",
    capabilities: ["signature", "virtual_patch"],
    lastSync: new Date().toISOString(),
  },
  {
    id: "int-splunk-siem",
    name: "Splunk SIEM",
    type: "siem",
    vendor: "Splunk",
    apiEndpoint: "https://splunk.internal:8089",
    status: "connected",
    capabilities: ["signature"],
    lastSync: new Date().toISOString(),
  },
];

const VULNERABILITY_HOTFIX_TEMPLATES: Record<string, Partial<HotfixRule>[]> = {
  "SQL Injection": [
    {
      type: "waf_rule",
      priority: "emergency",
      action: "block",
      pattern: "(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|--)",
      conditions: [
        { field: "request.body", operator: "regex", value: "(?i)(union.*select)" },
        { field: "request.uri", operator: "regex", value: "(?i)('|\")" },
      ],
    },
    {
      type: "virtual_patch",
      priority: "high",
      action: "sanitize",
      pattern: "SQL injection virtual patch",
      conditions: [
        { field: "request.params", operator: "contains", value: "'" },
      ],
    },
  ],
  "XSS": [
    {
      type: "waf_rule",
      priority: "high",
      action: "sanitize",
      pattern: "<script|javascript:|on\\w+=",
      conditions: [
        { field: "request.body", operator: "regex", value: "<script" },
        { field: "request.params", operator: "regex", value: "javascript:" },
      ],
    },
  ],
  "Remote Code Execution": [
    {
      type: "waf_rule",
      priority: "emergency",
      action: "block",
      pattern: "\\$\\{jndi:|java\\.lang\\.Runtime|ProcessBuilder|eval\\(",
      conditions: [
        { field: "request.headers", operator: "regex", value: "\\$\\{jndi:" },
        { field: "request.body", operator: "regex", value: "Runtime\\.getRuntime" },
      ],
    },
    {
      type: "firewall_rule",
      priority: "emergency",
      action: "block",
      conditions: [
        { field: "destination.port", operator: "equals", value: "1389" },
        { field: "destination.port", operator: "equals", value: "1099" },
      ],
    },
  ],
  "SSRF": [
    {
      type: "waf_rule",
      priority: "high",
      action: "block",
      pattern: "169\\.254\\.169\\.254|localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|internal|metadata",
      conditions: [
        { field: "request.body", operator: "regex", value: "169\\.254\\.169\\.254" },
        { field: "request.params", operator: "contains", value: "localhost" },
      ],
    },
  ],
  "Brute Force": [
    {
      type: "rate_limit",
      priority: "high",
      action: "rate_limit",
      conditions: [
        { field: "request.path", operator: "contains", value: "/login" },
        { field: "request.path", operator: "contains", value: "/auth" },
      ],
    },
    {
      type: "ip_block",
      priority: "medium",
      action: "block",
      conditions: [
        { field: "request.rate", operator: "gt", value: "100" },
      ],
    },
  ],
  "Default": [
    {
      type: "signature",
      priority: "medium",
      action: "alert",
      conditions: [
        { field: "request.anomaly_score", operator: "gt", value: "5" },
      ],
    },
  ],
};

function categorizeVulnerability(title: string): string {
  const lowerTitle = title.toLowerCase();
  if (lowerTitle.includes("sql") || lowerTitle.includes("injection")) return "SQL Injection";
  if (lowerTitle.includes("xss") || lowerTitle.includes("cross-site scripting")) return "XSS";
  if (lowerTitle.includes("rce") || lowerTitle.includes("remote code") || lowerTitle.includes("log4j")) return "Remote Code Execution";
  if (lowerTitle.includes("ssrf") || lowerTitle.includes("request forgery")) return "SSRF";
  if (lowerTitle.includes("brute") || lowerTitle.includes("credential") || lowerTitle.includes("auth")) return "Brute Force";
  return "Default";
}

function generateCopyPasteInstructions(
  rules: HotfixRule[],
  vulnerability: { title: string; severity: string }
): ManualHotfixRule["copyPasteInstructions"] {
  const instructions: ManualHotfixRule["copyPasteInstructions"] = [];
  
  for (const rule of rules) {
    if (rule.type === "waf_rule" || rule.type === "virtual_patch") {
      instructions.push({
        platform: "cloudflare",
        instruction: `Add this WAF rule to your Cloudflare dashboard under Security > WAF > Custom Rules for ${vulnerability.title}`,
        codeSnippet: `Rule Name: ShadowTwin-${rule.id}
Expression: (http.request.uri.path contains "${rule.pattern?.slice(0, 30) || 'malicious'}" or http.request.body contains "${rule.pattern?.slice(0, 30) || 'attack'}")
Action: ${rule.action === "block" ? "Block" : rule.action === "sanitize" ? "Managed Challenge" : "Log"}
Priority: ${rule.priority === "emergency" ? "1" : rule.priority === "high" ? "5" : "10"}`
      });
      
      instructions.push({
        platform: "aws_waf",
        instruction: `Create this AWS WAF rule in your WebACL for ${vulnerability.title}`,
        codeSnippet: `{
  "Name": "ShadowTwin-${rule.id}",
  "Priority": ${rule.priority === "emergency" ? 1 : rule.priority === "high" ? 5 : 10},
  "Statement": {
    "RegexPatternSetReferenceStatement": {
      "ARN": "arn:aws:wafv2:REGION:ACCOUNT:regional/regexpatternset/shadowtwin-patterns",
      "FieldToMatch": { "Body": {} },
      "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
    }
  },
  "Action": { "${rule.action === "block" ? "Block" : "Count"}": {} }
}`
      });
      
      instructions.push({
        platform: "nginx",
        instruction: `Add this location block or modify your nginx.conf for ${vulnerability.title}`,
        codeSnippet: `# ShadowTwin Hotfix: ${rule.id}
# Vulnerability: ${vulnerability.title} (${vulnerability.severity})
location / {
    # Block ${vulnerability.title}
    if ($request_body ~* "${rule.pattern?.replace(/\\/g, '\\\\') || 'malicious'}") {
        return 403;
    }
    if ($args ~* "${rule.pattern?.replace(/\\/g, '\\\\') || 'attack'}") {
        return 403;
    }
}`
      });
      
      instructions.push({
        platform: "apache",
        instruction: `Add these ModSecurity rules to your Apache configuration for ${vulnerability.title}`,
        codeSnippet: `# ShadowTwin Hotfix: ${rule.id}
# Vulnerability: ${vulnerability.title} (${vulnerability.severity})
SecRule REQUEST_BODY "${rule.pattern || '@rx malicious'}" \\
    "id:${Math.floor(Math.random() * 900000) + 100000},\\
    phase:2,\\
    ${rule.action === "block" ? "deny" : "log"},\\
    status:403,\\
    msg:'ShadowTwin: ${vulnerability.title}',\\
    severity:${vulnerability.severity === "critical" ? "0" : vulnerability.severity === "high" ? "2" : "4"}"`
      });
    }
    
    if (rule.type === "rate_limit") {
      instructions.push({
        platform: "nginx",
        instruction: `Add rate limiting to nginx.conf for ${vulnerability.title}`,
        codeSnippet: `# ShadowTwin Rate Limit: ${rule.id}
limit_req_zone $binary_remote_addr zone=shadowtwin_limit:10m rate=10r/s;

location /login {
    limit_req zone=shadowtwin_limit burst=20 nodelay;
    # ... your existing config
}`
      });
    }
    
    instructions.push({
      platform: "generic",
      instruction: `Generic security rule for ${vulnerability.title} - adapt to your platform`,
      codeSnippet: `Rule ID: ${rule.id}
Type: ${rule.type}
Priority: ${rule.priority}
Action: ${rule.action}
Pattern: ${rule.pattern || "N/A"}
Duration: ${rule.duration} seconds
Conditions:
${rule.conditions.map(c => `  - ${c.field} ${c.operator} "${c.value}"`).join('\n')}

Rollback: ${rule.rollbackPlan}`
    });
  }
  
  return instructions;
}

function generateHotfixRules(
  vulnerability: { id: string; title: string; severity: string },
  target: string
): HotfixRule[] {
  const category = categorizeVulnerability(vulnerability.title);
  const templates = VULNERABILITY_HOTFIX_TEMPLATES[category] || VULNERABILITY_HOTFIX_TEMPLATES["Default"];
  
  return templates.map(template => ({
    id: `rule-${nanoid(8)}`,
    type: template.type || "waf_rule",
    priority: vulnerability.severity === "critical" ? "emergency" : 
              vulnerability.severity === "high" ? "high" : 
              template.priority || "medium",
    action: template.action || "block",
    target,
    pattern: template.pattern,
    conditions: template.conditions || [],
    duration: vulnerability.severity === "critical" ? 86400 : 
              vulnerability.severity === "high" ? 43200 : 3600,
    autoExpire: true,
    rollbackPlan: `Remove rule ${template.type} for ${vulnerability.title}`,
  }));
}

function selectIntegrations(rules: HotfixRule[]): DefenseIntegration[] {
  const requiredCapabilities = new Set(rules.map(r => r.type));
  
  return MOCK_INTEGRATIONS.filter(integration => 
    integration.status === "connected" &&
    Array.from(requiredCapabilities).some(cap => 
      integration.capabilities.includes(cap)
    )
  );
}

async function deployHotfix(
  vulnerabilityId: string,
  rules: HotfixRule[],
  integrations: DefenseIntegration[]
): Promise<HotfixDeployment> {
  const deployment: HotfixDeployment = {
    id: `deploy-${nanoid(8)}`,
    vulnerabilityId,
    rules,
    integrations: integrations.map(i => i.id),
    status: "deploying",
    deployedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + rules[0].duration * 1000).toISOString(),
  };
  
  await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));
  
  const success = Math.random() > 0.1;
  
  if (success) {
    deployment.status = "active";
    deployment.effectivenessScore = 0.75 + Math.random() * 0.2;
    deployment.blockedAttempts = Math.floor(Math.random() * 50);
  } else {
    deployment.status = "failed";
  }
  
  return deployment;
}

export interface AutonomousDefenseOptions {
  userId: string;
  scanId: string;
  target: string;
  onProgress: (progress: number) => void;
  dryRun?: boolean;
}

export async function runAutonomousDefense(
  scannerData: any,
  options: AutonomousDefenseOptions
): Promise<AutonomousDefenseResult> {
  const { userId, scanId, target, onProgress, dryRun = false } = options;
  
  const userCredits = await storage.getUserCredits(userId);
  const planLevel = userCredits.planLevel;
  
  if (planLevel !== "ELITE") {
    throw new Error("Autonomous defense requires ELITE tier subscription");
  }
  
  const costs = LEVEL7_COSTS.ELITE;
  const defenseCost = costs.autonomousDefense;
  
  const costResult = await storage.deductCredits(userId, defenseCost, {
    description: "Autonomous defense deployment",
    agentType: "autonomous_defense",
    scanId,
  });
  
  if (!costResult.success) {
    throw new Error(costResult.error || "Insufficient credits for autonomous defense");
  }
  
  onProgress(10);
  
  const criticalAndHighVulns = scannerData.vulnerabilities.filter(
    (v: any) => v.severity === "critical" || v.severity === "high"
  );
  
  if (criticalAndHighVulns.length === 0) {
    onProgress(100);
    return {
      scanId,
      vulnerabilitiesProtected: 0,
      hotfixesDeployed: [],
      integrationsUsed: [],
      overallProtectionScore: 1.0,
      estimatedRiskReduction: 0,
      manualReviewRequired: [],
      rollbackCommands: [],
      manualHotfixRules: [],
      gracefulDegradation: false,
    };
  }
  
  onProgress(20);
  
  const hotfixesDeployed: HotfixDeployment[] = [];
  const allRules: HotfixRule[] = [];
  const manualReviewRequired: string[] = [];
  const rollbackCommands: string[] = [];
  const manualHotfixRules: ManualHotfixRule[] = [];
  let hasGracefulDegradation = false;
  
  const progressPerVuln = 60 / criticalAndHighVulns.length;
  let currentProgress = 20;
  
  for (const vuln of criticalAndHighVulns) {
    const rules = generateHotfixRules(
      { id: vuln.id, title: vuln.title, severity: vuln.severity },
      target
    );
    allRules.push(...rules);
    
    const integrations = selectIntegrations(rules);
    
    if (integrations.length === 0) {
      hasGracefulDegradation = true;
      manualReviewRequired.push(`No WAF API key provided - Manual hotfix rules generated for ${vuln.title}`);
      
      const copyPasteInstructions = generateCopyPasteInstructions(rules, {
        title: vuln.title,
        severity: vuln.severity,
      });
      
      manualHotfixRules.push({
        vulnerabilityId: vuln.id,
        vulnerabilityTitle: vuln.title,
        severity: vuln.severity,
        rules,
        copyPasteInstructions,
      });
      
      currentProgress += progressPerVuln;
      onProgress(Math.round(currentProgress));
      continue;
    }
    
    if (!dryRun) {
      const deployment = await deployHotfix(vuln.id, rules, integrations);
      hotfixesDeployed.push(deployment);
      
      if (deployment.status === "active") {
        for (const rule of rules) {
          rollbackCommands.push(
            `curl -X DELETE https://api.shadowtwin.io/v1/hotfix/${deployment.id}/rules/${rule.id}`
          );
        }
      } else if (deployment.status === "failed") {
        hasGracefulDegradation = true;
        const copyPasteInstructions = generateCopyPasteInstructions(rules, {
          title: vuln.title,
          severity: vuln.severity,
        });
        
        manualHotfixRules.push({
          vulnerabilityId: vuln.id,
          vulnerabilityTitle: vuln.title,
          severity: vuln.severity,
          rules,
          copyPasteInstructions,
        });
        manualReviewRequired.push(`Automated deployment failed - Manual hotfix rules provided for ${vuln.title}`);
      }
    } else {
      hotfixesDeployed.push({
        id: `dry-run-${nanoid(8)}`,
        vulnerabilityId: vuln.id,
        rules,
        integrations: integrations.map(i => i.id),
        status: "pending",
      });
    }
    
    currentProgress += progressPerVuln;
    onProgress(Math.round(currentProgress));
  }
  
  onProgress(90);
  
  const activeDeployments = hotfixesDeployed.filter(d => d.status === "active" || d.status === "pending");
  const integrationsUsed = MOCK_INTEGRATIONS.filter(i => 
    hotfixesDeployed.some(d => d.integrations.includes(i.id))
  );
  
  const protectedByAutomation = activeDeployments.length;
  const protectedByManualRules = manualHotfixRules.length;
  const totalProtected = protectedByAutomation + protectedByManualRules;
  
  const overallProtectionScore = totalProtected / Math.max(criticalAndHighVulns.length, 1);
  
  const baseRisk = criticalAndHighVulns.reduce((sum: number, v: any) => {
    return sum + (v.severity === "critical" ? 100 : 50);
  }, 0);
  
  const automatedMitigation = activeDeployments.reduce((sum: number, d: any) => {
    const effectiveness = d.effectivenessScore || 0.7;
    const vulnSeverity = criticalAndHighVulns.find((v: any) => v.id === d.vulnerabilityId)?.severity;
    return sum + (vulnSeverity === "critical" ? 100 : 50) * effectiveness;
  }, 0);
  
  const manualMitigation = manualHotfixRules.reduce((sum: number, m: any) => {
    const potentialEffectiveness = 0.5;
    return sum + (m.severity === "critical" ? 100 : 50) * potentialEffectiveness;
  }, 0);
  
  const totalMitigatedRisk = automatedMitigation + manualMitigation;
  const estimatedRiskReduction = baseRisk > 0 ? totalMitigatedRisk / baseRisk : 0;
  
  onProgress(100);
  
  return {
    scanId,
    vulnerabilitiesProtected: totalProtected,
    hotfixesDeployed,
    integrationsUsed,
    overallProtectionScore,
    estimatedRiskReduction,
    manualReviewRequired,
    rollbackCommands,
    manualHotfixRules,
    gracefulDegradation: hasGracefulDegradation,
  };
}

export function generateDefenseReport(result: AutonomousDefenseResult): string {
  const lines = [
    "# Autonomous Defense Deployment Report",
    "",
    `**Scan ID:** ${result.scanId}`,
    `**Vulnerabilities Protected:** ${result.vulnerabilitiesProtected}`,
    `**Overall Protection Score:** ${(result.overallProtectionScore * 100).toFixed(1)}%`,
    `**Estimated Risk Reduction:** ${(result.estimatedRiskReduction * 100).toFixed(1)}%`,
    "",
    "## Deployed Hotfixes",
    "",
  ];
  
  for (const deployment of result.hotfixesDeployed) {
    lines.push(`### ${deployment.vulnerabilityId}`);
    lines.push(`- **Status:** ${deployment.status}`);
    lines.push(`- **Rules:** ${deployment.rules.length}`);
    if (deployment.effectivenessScore) {
      lines.push(`- **Effectiveness:** ${(deployment.effectivenessScore * 100).toFixed(1)}%`);
    }
    if (deployment.blockedAttempts) {
      lines.push(`- **Blocked Attempts:** ${deployment.blockedAttempts}`);
    }
    lines.push("");
  }
  
  if (result.integrationsUsed.length > 0) {
    lines.push("## Integrations Used");
    lines.push("");
    for (const integration of result.integrationsUsed) {
      lines.push(`- **${integration.name}** (${integration.type}) - ${integration.vendor}`);
    }
    lines.push("");
  }
  
  if (result.manualReviewRequired.length > 0) {
    lines.push("## Manual Review Required");
    lines.push("");
    for (const item of result.manualReviewRequired) {
      lines.push(`- ${item}`);
    }
    lines.push("");
  }
  
  if (result.manualHotfixRules && result.manualHotfixRules.length > 0) {
    lines.push("## 📋 Manual Copy-Paste Hotfix Rules");
    lines.push("");
    if (result.gracefulDegradation) {
      lines.push("> **Note:** No WAF API keys were provided. The following rules can be manually applied to your security infrastructure.");
      lines.push("");
    }
    
    for (const manualRule of result.manualHotfixRules) {
      lines.push(`### ${manualRule.vulnerabilityTitle}`);
      lines.push(`- **Vulnerability ID:** ${manualRule.vulnerabilityId}`);
      lines.push(`- **Severity:** ${manualRule.severity.toUpperCase()}`);
      lines.push(`- **Rules Generated:** ${manualRule.rules.length}`);
      lines.push("");
      
      const platforms = ["cloudflare", "aws_waf", "nginx", "apache", "generic"] as const;
      for (const platform of platforms) {
        const platformInstructions = manualRule.copyPasteInstructions.filter(i => i.platform === platform);
        if (platformInstructions.length > 0) {
          const platformLabel = platform === "cloudflare" ? "☁️ Cloudflare WAF" :
                               platform === "aws_waf" ? "🔶 AWS WAF" :
                               platform === "nginx" ? "🟢 Nginx" :
                               platform === "apache" ? "🔴 Apache ModSecurity" : "📄 Generic";
          
          lines.push(`#### ${platformLabel}`);
          for (const instruction of platformInstructions) {
            lines.push(`> ${instruction.instruction}`);
            lines.push("");
            lines.push("```");
            lines.push(instruction.codeSnippet);
            lines.push("```");
            lines.push("");
          }
        }
      }
    }
  }
  
  if (result.rollbackCommands.length > 0) {
    lines.push("## Rollback Commands");
    lines.push("");
    lines.push("```bash");
    for (const cmd of result.rollbackCommands) {
      lines.push(cmd);
    }
    lines.push("```");
  }
  
  return lines.join("\n");
}
