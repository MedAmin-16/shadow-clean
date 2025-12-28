import { db } from "../../db";
import { vulnerabilitiesTable, assetsTable } from "@shared/schema";
import { eq, and } from "drizzle-orm";

export interface AttackChain {
  id: string;
  name: string;
  pattern: string;
  severity: "critical" | "high" | "medium";
  vulnerabilities: string[];
  description: string;
  impact: string;
  reasoning: string;
  exploitPath: string;
  businessImpact: string;
  estimatedLossMin: number;
  estimatedLossMax: number;
  complianceRisks: string[];
  executiveSummary: string;
}

interface VulnRecord {
  id: string;
  title: string;
  severity: string;
  category?: string;
  cveId?: string;
  description?: string;
  affectedComponent?: string;
}

const ATTACK_PATTERNS = [
  {
    id: "sensitive_info_outdated_tech",
    name: "Information Disclosure + Outdated Technology",
    pattern: ["information_disclosure", "sensitive_data_exposure", "outdated_software"],
    keywords: ["api_key", "password", "secret", "token", "config", "outdated", "deprecated", "old_version"],
    severity: "critical" as const,
    description: "Sensitive information exposed combined with outdated technology that can be exploited",
    impact: "Complete system compromise through leaked credentials targeting old vulnerabilities",
    businessImpact: "CRITICAL: Potential Data Breach / Legal Liability",
    estimatedLossMin: 500000,
    estimatedLossMax: 5000000,
    complianceRisks: ["GDPR Non-Compliance Risk", "CCPA Violation", "HIPAA Breach Notification"],
    reasoning: "When sensitive data (API keys, passwords) is exposed through information disclosure AND the system runs outdated software with known vulnerabilities, attackers can use the leaked credentials to authenticate and then exploit the outdated components.",
    executiveSummary: "Exposed credentials combined with outdated systems creates a direct path to complete data breach. This puts customer data at risk and exposes your organization to regulatory fines, legal action, and irreparable brand damage.",
  },
  {
    id: "xss_open_redirect",
    name: "XSS + Open Redirect Chain",
    pattern: ["xss", "open_redirect", "javascript"],
    keywords: ["xss", "cross.site.scripting", "open_redirect", "url_parameter", "unsanitized", "user_input"],
    severity: "high" as const,
    description: "XSS vulnerability chained with open redirect to steal credentials",
    impact: "Session hijacking and credential theft through phishing-like attacks",
    businessImpact: "HIGH: Service Disruption / Brand Damage",
    estimatedLossMin: 100000,
    estimatedLossMax: 1000000,
    complianceRisks: ["PCI-DSS Violation Risk", "SOC2 Compliance Gap"],
    reasoning: "XSS (Cross-Site Scripting) can execute malicious JavaScript, which can redirect users to a phishing site via an open redirect vulnerability, allowing attackers to steal session cookies or credentials.",
    executiveSummary: "Attackers can deceive your users into compromising their own accounts. This leads to unauthorized transactions, loss of customer trust, and potential payment card fraud penalties.",
  },
  {
    id: "subdomain_takeover_csrf",
    name: "Subdomain Takeover + CSRF",
    pattern: ["subdomain_takeover", "csrf", "dangling_dns"],
    keywords: ["subdomain", "dangling", "dns", "csrf", "cross.site.request", "forgotten", "abandoned"],
    severity: "high" as const,
    description: "Subdomain takeover enabling CSRF attacks",
    impact: "Unauthorized account modifications and data manipulation",
    businessImpact: "HIGH: Service Disruption / Brand Damage",
    estimatedLossMin: 200000,
    estimatedLossMax: 2000000,
    complianceRisks: ["GDPR Non-Compliance Risk", "SOC2 Control Failure"],
    reasoning: "A takeover of an abandoned subdomain can host CSRF attack payloads, and since it shares the same root domain, CSRF protections may be bypassed if they only check the root domain.",
    executiveSummary: "Forgotten subdomains can be weaponized to hijack user sessions and manipulate account data. Customers lose confidence in your security posture, leading to churn and reputational damage.",
  },
  {
    id: "sql_injection_auth_bypass",
    name: "SQL Injection + Authentication Bypass",
    pattern: ["sql_injection", "authentication_bypass", "database"],
    keywords: ["sql_injection", "sqli", "authentication", "bypass", "login", "database"],
    severity: "critical" as const,
    description: "SQL injection combined with weak authentication",
    impact: "Complete database access and user impersonation",
    businessImpact: "CRITICAL: Potential Data Breach / Legal Liability",
    estimatedLossMin: 1000000,
    estimatedLossMax: 10000000,
    complianceRisks: ["GDPR Non-Compliance Risk", "CCPA Violation", "HIPAA Breach Notification", "PCI-DSS Violation"],
    reasoning: "SQL injection in login forms allows bypassing authentication, or can be used to directly extract password hashes that can be cracked offline.",
    executiveSummary: "Direct database access without authentication means all customer data is exposed. This triggers mandatory breach notifications, regulatory fines, and existential damage to customer trust.",
  },
  {
    id: "rce_privilege_escalation",
    name: "Remote Code Execution + Privilege Escalation",
    pattern: ["rce", "privilege_escalation", "code_execution"],
    keywords: ["rce", "remote.code.execution", "privilege.escalation", "root", "sudo", "admin"],
    severity: "critical" as const,
    description: "RCE chained with privilege escalation for complete control",
    impact: "Full system compromise with root/admin access",
    businessImpact: "CRITICAL: Potential Data Breach / Legal Liability",
    estimatedLossMin: 2000000,
    estimatedLossMax: 50000000,
    complianceRisks: ["GDPR Non-Compliance Risk", "HIPAA Breach Notification", "Complete Audit Failure"],
    reasoning: "RCE as a low-privilege user, combined with unpatched privilege escalation vulnerabilities, allows attackers to gain root or admin access to the entire system.",
    executiveSummary: "Attackers gain complete control of your infrastructure with root access. All systems, data, and backups are compromised. Recovery can take months and costs millions. This is the worst-case scenario.",
  },
  {
    id: "lfi_rce",
    name: "Local File Inclusion + Code Execution",
    pattern: ["lfi", "rce", "file_inclusion"],
    keywords: ["lfi", "local.file.inclusion", "log_poisoning", "code.execution", "writable"],
    severity: "critical" as const,
    description: "LFI vulnerability used to achieve code execution",
    impact: "Remote code execution through file inclusion techniques",
    businessImpact: "CRITICAL: Potential Data Breach / Legal Liability",
    estimatedLossMin: 1000000,
    estimatedLossMax: 8000000,
    complianceRisks: ["GDPR Non-Compliance Risk", "SOC2 Control Failure", "ISO27001 Violation"],
    reasoning: "LFI can include application log files that contain user input, or writable directories with uploaded files, allowing attackers to poison logs with PHP code and then execute it.",
    executiveSummary: "Application server is compromised through file manipulation. Attackers can install backdoors, steal data, and maintain persistent access to your systems.",
  },
  {
    id: "ssrf_internal_access",
    name: "SSRF + Internal Service Access",
    pattern: ["ssrf", "server.side.request.forgery", "internal_network"],
    keywords: ["ssrf", "server.side.request", "internal", "localhost", "metadata", "cloud_metadata"],
    severity: "high" as const,
    description: "SSRF to access internal services and cloud metadata",
    impact: "Access to internal APIs, databases, and cloud credentials",
    businessImpact: "HIGH: Service Disruption / Brand Damage",
    estimatedLossMin: 300000,
    estimatedLossMax: 3000000,
    complianceRisks: ["GDPR Non-Compliance Risk", "AWS/Cloud Compliance Violation"],
    reasoning: "SSRF vulnerabilities allow an attacker to make requests to internal services like databases, APIs, or cloud metadata endpoints that aren't accessible from outside.",
    executiveSummary: "Attackers bypass network defenses to access internal systems and cloud credentials. This leads to lateral movement, data theft, and prolonged operational downtime.",
  },
  {
    id: "broken_auth_data_exposure",
    name: "Broken Authentication + Data Exposure",
    pattern: ["broken_authentication", "data_exposure", "weak_encryption"],
    keywords: ["weak.authentication", "hardcoded", "plaintext", "no.encryption", "credential"],
    severity: "critical" as const,
    description: "Weak authentication combined with unencrypted data storage",
    impact: "Unauthorized access and bulk data theft",
    businessImpact: "CRITICAL: Potential Data Breach / Legal Liability",
    estimatedLossMin: 750000,
    estimatedLossMax: 7500000,
    complianceRisks: ["GDPR Non-Compliance Risk", "CCPA Violation", "PCI-DSS Violation"],
    reasoning: "Weak authentication (weak passwords, session handling) combined with unencrypted or improperly encrypted data storage allows attackers to both authenticate and directly access sensitive data.",
    executiveSummary: "Unencrypted data combined with weak authentication means bulk customer data can be stolen with minimal effort. Breach notification costs and regulatory penalties are inevitable.",
  },
];

function calculateSimilarity(str1: string, str2: string): number {
  const s1 = str1.toLowerCase();
  const s2 = str2.toLowerCase();
  if (s1 === s2) return 1;
  if (s1.includes(s2) || s2.includes(s1)) return 0.8;
  
  const words1 = s1.split(/[\s_-]+/);
  const words2 = s2.split(/[\s_-]+/);
  const matching = words1.filter(w => words2.some(w2 => w2.includes(w) || w.includes(w2)));
  return matching.length / Math.max(words1.length, words2.length);
}

function matchesPattern(vulns: VulnRecord[], pattern: typeof ATTACK_PATTERNS[0]): boolean {
  const allText = vulns
    .map(v => `${v.title} ${v.category} ${v.description}`.toLowerCase())
    .join(" ");

  const matches = pattern.keywords.filter(keyword => {
    const keywordLower = keyword.replace(/\./g, " ");
    return allText.includes(keywordLower) || calculateSimilarity(allText, keywordLower) > 0.6;
  });

  return matches.length >= 2;
}

function findChains(vulns: VulnRecord[]): AttackChain[] {
  const chains: AttackChain[] = [];

  for (const pattern of ATTACK_PATTERNS) {
    const matchingVulns = vulns.filter(v => {
      const vulnText = `${v.title} ${v.category} ${v.description}`.toLowerCase();
      return pattern.keywords.some(keyword => {
        const keywordLower = keyword.replace(/\./g, " ");
        return vulnText.includes(keywordLower) || calculateSimilarity(vulnText, keywordLower) > 0.6;
      });
    });

    if (matchingVulns.length >= 2 && matchesPattern(matchingVulns, pattern)) {
      chains.push({
        id: `chain_${pattern.id}_${Date.now()}`,
        name: pattern.name,
        pattern: pattern.id,
        severity: pattern.severity,
        vulnerabilities: matchingVulns.map(v => v.id),
        description: pattern.description,
        impact: pattern.impact,
        businessImpact: pattern.businessImpact,
        estimatedLossMin: pattern.estimatedLossMin,
        estimatedLossMax: pattern.estimatedLossMax,
        complianceRisks: pattern.complianceRisks,
        reasoning: generateReasoningForChain(pattern, matchingVulns),
        executiveSummary: pattern.executiveSummary,
        exploitPath: generateExploitPath(pattern, matchingVulns),
      });
    }
  }

  return chains.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
}

function generateReasoningForChain(pattern: typeof ATTACK_PATTERNS[0], vulns: VulnRecord[]): string {
  const vulnList = vulns.map(v => `"${v.title}"`).join(", ");
  return `${pattern.reasoning} Found vulnerabilities: ${vulnList}. This combination creates a critical attack vector.`;
}

function generateExploitPath(pattern: typeof ATTACK_PATTERNS[0], vulns: VulnRecord[]): string {
  const scenarios: Record<string, string> = {
    "sensitive_info_outdated_tech":
      "1. Exploit information disclosure to leak API keys/credentials\n2. Use leaked credentials with outdated vulnerable version\n3. Exploit known CVE in outdated component\n4. Gain system access",
    "xss_open_redirect":
      "1. Craft XSS payload that executes JavaScript\n2. Use open redirect to send victim to attacker site\n3. Redirect back with stolen session cookie\n4. Impersonate victim user",
    "subdomain_takeover_csrf":
      "1. Identify abandoned subdomain\n2. Register/claim the subdomain\n3. Host CSRF attack payload\n4. Trick user into visiting attacker subdomain\n5. Modify user account or data",
    "sql_injection_auth_bypass":
      "1. Identify SQL injection in login form\n2. Bypass authentication with SQL injection\n3. Or extract password hashes\n4. Crack offline or reset passwords\n5. Gain admin access",
    "rce_privilege_escalation":
      "1. Exploit RCE vulnerability to gain shell access\n2. Run with limited user privileges\n3. Exploit unpatched privilege escalation\n4. Achieve root/admin access\n5. Install persistent backdoor",
    "lfi_rce":
      "1. Find LFI vulnerability in application\n2. Poison application logs with PHP code\n3. Use LFI to include poisoned log file\n4. Execute arbitrary code\n5. Compromise application and server",
    "ssrf_internal_access":
      "1. Find SSRF vulnerability\n2. Enumerate internal services (localhost:3306, etc)\n3. Access internal APIs and databases\n4. Access cloud metadata endpoint (169.254.169.254)\n5. Extract cloud credentials",
    "broken_auth_data_exposure":
      "1. Exploit weak authentication to access account\n2. Access unencrypted database with plaintext data\n3. Extract bulk customer data\n4. Sell data on dark web or use for fraud",
  };

  return scenarios[pattern.id] || "Multi-stage attack using vulnerability chaining";
}

export async function correlateVulnerabilities(scanId: string, userId: string): Promise<AttackChain[]> {
  try {
    const vulns = await db
      .select()
      .from(vulnerabilitiesTable)
      .where(and(eq(vulnerabilitiesTable.scanId, scanId), eq(vulnerabilitiesTable.userId, userId)));

    if (vulns.length === 0) {
      return [];
    }

    const vulnRecords: VulnRecord[] = vulns.map(v => ({
      id: v.id,
      title: v.title || "",
      severity: v.severity || "medium",
      category: v.category || "",
      cveId: v.cveId || "",
      description: v.description || "",
      affectedComponent: v.affectedComponent || "",
    }));

    return findChains(vulnRecords);
  } catch (error) {
    console.error("[AttackChainer] Error correlating vulnerabilities:", error);
    return [];
  }
}

export async function getAttackChainsForScan(scanId: string, userId: string): Promise<AttackChain[]> {
  return correlateVulnerabilities(scanId, userId);
}

export const attackChainerService = {
  correlateVulnerabilities,
  getAttackChainsForScan,
};
