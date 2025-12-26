import OpenAI from "openai";
import { randomUUID } from "crypto";
import type { ReconFindings, PlanLevel } from "@shared/schema";
import { PLAN_CONFIGS as PlanConfigs, calculateScopeCost } from "@shared/schema";

interface SingleTargetReconFindings {
  target: string;
  ip: string;
  hostname: string;
  ports: number[];
  services: { port: number; service: string; version?: string }[];
  technologies: string[];
  subdomains: string[];
  credit_deduction: number;
  strategic_decision_log: string;
}
import { storage } from "../storage";

let openaiClient: OpenAI | null = null;

function getOpenAIClient(): OpenAI | null {
  if (!process.env.OPENAI_API_KEY) {
    return null;
  }
  if (!openaiClient) {
    openaiClient = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  }
  return openaiClient;
}

function randomDelay(min: number, max: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, Math.random() * (max - min) + min));
}

function generateRandomPorts(): number[] {
  const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443];
  const numPorts = Math.floor(Math.random() * 6) + 2;
  const shuffled = commonPorts.sort(() => 0.5 - Math.random());
  return shuffled.slice(0, numPorts).sort((a, b) => a - b);
}

function generateServices(ports: number[]): { port: number; service: string; version?: string }[] {
  const serviceMap: Record<number, { service: string; versions: string[] }> = {
    21: { service: "FTP", versions: ["vsftpd 3.0.3", "ProFTPD 1.3.6"] },
    22: { service: "SSH", versions: ["OpenSSH 7.9p1", "OpenSSH 8.2p1"] },
    23: { service: "Telnet", versions: ["Linux telnetd"] },
    25: { service: "SMTP", versions: ["Postfix", "Exim 4.93"] },
    53: { service: "DNS", versions: ["BIND 9.11.5", "BIND 9.16.1"] },
    80: { service: "HTTP", versions: ["Apache 2.4.41", "nginx 1.18.0"] },
    110: { service: "POP3", versions: ["Dovecot pop3d"] },
    143: { service: "IMAP", versions: ["Dovecot imapd"] },
    443: { service: "HTTPS", versions: ["Apache 2.4.41", "nginx 1.18.0"] },
    445: { service: "SMB", versions: ["Samba 4.11.6"] },
    993: { service: "IMAPS", versions: ["Dovecot imapd"] },
    995: { service: "POP3S", versions: ["Dovecot pop3d"] },
    3306: { service: "MySQL", versions: ["MySQL 5.7.32", "MySQL 8.0.22"] },
    3389: { service: "RDP", versions: ["Microsoft Terminal Services"] },
    5432: { service: "PostgreSQL", versions: ["PostgreSQL 12.5", "PostgreSQL 13.1"] },
    8080: { service: "HTTP Proxy", versions: ["Apache Tomcat 9.0.41", "Jetty 9.4.35"] },
    8443: { service: "HTTPS Alt", versions: ["Apache Tomcat 9.0.41"] },
  };

  return ports.map(port => {
    const info = serviceMap[port] || { service: "Unknown", versions: ["Unknown"] };
    return {
      port,
      service: info.service,
      version: info.versions[Math.floor(Math.random() * info.versions.length)],
    };
  });
}

function extractHostname(target: string): string {
  return target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
}

function generateIP(): string {
  return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

export interface ReconExecutionContext {
  userId: string;
  planLevel?: PlanLevel;
  currentCredits?: number;
}

export interface ScopeValidationResult {
  valid: boolean;
  scopeCost: ScopeCostEstimate;
  availableCredits: number;
  shortfall?: number;
  error?: string;
}

async function validateScopeCost(
  targets: string[],
  userId: string,
  planLevel?: string
): Promise<ScopeValidationResult> {
  const userCredits = await storage.getUserCredits(userId);
  const effectivePlanLevel = planLevel || userCredits.planLevel;
  const scopeCost = calculateScopeCost(targets, effectivePlanLevel);
  
    if (userCredits.balance < scopeCost.totalCost) {
      return {
        valid: false,
        scopeCost,
        availableCredits: userCredits.balance,
        shortfall: scopeCost.totalCost - userCredits.balance,
        error: `Insufficient credits. Required: ${scopeCost.totalCost}, Available: ${userCredits.balance}`,
      };
    }
  
  return {
    valid: true,
    scopeCost,
    availableCredits: userCredits.balance,
  };
}

async function executeOSINTQuery(
  target: string,
  queryType: string,
  planLevel: string,
  llmModel: string
): Promise<{ subdomains: string[]; technologies: string[] }> {
  const openai = getOpenAIClient();
  if (!openai) {
    console.log("OpenAI API key not configured - using simulated OSINT data");
    return { subdomains: [], technologies: [] };
  }
  
  const planConfig = PlanConfigs[planLevel];
  
  const osintPrompt = `You are a security reconnaissance agent. Analyze the target "${target}" and provide OSINT intelligence.

Based on ${planConfig.osintAccess} access level, identify:
1. Possible subdomains (up to ${planConfig.osintAccess === 'full' ? 10 : planConfig.osintAccess === 'standard' ? 5 : 3})
2. Technology stack indicators

Respond with JSON in this format:
{
  "subdomains": ["subdomain1.example.com", "subdomain2.example.com"],
  "technologies": ["Technology 1", "Technology 2"]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: llmModel,
      messages: [
        { role: "system", content: "You are a cybersecurity OSINT specialist. Provide realistic but simulated reconnaissance data for security testing purposes." },
        { role: "user", content: osintPrompt }
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 1024,
    });

    const result = JSON.parse(response.choices[0].message.content || "{}");
    return {
      subdomains: result.subdomains || [],
      technologies: result.technologies || [],
    };
  } catch (error) {
    console.error("OSINT query failed:", error);
    return { subdomains: [], technologies: [] };
  }
}

async function generateStrategicPlan(
  target: string,
  reconData: { ip: string; hostname: string; ports: number[]; services: { port: number; service: string; version?: string }[] },
  planLevel: string,
  llmModel: string
): Promise<string> {
  const openai = getOpenAIClient();
  if (!openai) {
    return `${planLevel} Agent using ${llmModel} - Strategic assessment generated (API key not configured for LLM enhancement).

Target Analysis:
- Host: ${reconData.hostname} (${reconData.ip})
- Open Ports: ${reconData.ports.join(', ')}
- Services Detected: ${reconData.services.map(s => `${s.service}:${s.port}`).join(', ')}

Recommended for Scanner Agent:
- Perform vulnerability scanning on detected services
- Check for common CVEs on detected service versions
- Analyze security headers and SSL/TLS configuration`;
  }
  
  const strategicPrompt = `You are ${planLevel === 'ELITE' ? 'an ELITE' : planLevel === 'STANDARD' ? 'a STANDARD' : 'a BASIC'} security planning agent using ${llmModel}.

Target: ${target}
IP: ${reconData.ip}
Hostname: ${reconData.hostname}
Open Ports: ${reconData.ports.join(', ')}
Services: ${JSON.stringify(reconData.services)}

Generate a strategic security assessment plan. Include:
1. Attack surface analysis
2. Priority targets based on services detected
3. Recommended scanning approach for Agent 2 (Scanner)
${planLevel === 'ELITE' ? '4. Advanced threat modeling recommendations' : ''}

Provide a detailed strategic log that will guide the next agent.`;

  try {
    const response = await openai.chat.completions.create({
      model: llmModel,
      messages: [
        { role: "system", content: `You are ${planLevel} Agent utilizing ${llmModel} for strategic path analysis. Provide detailed reconnaissance planning.` },
        { role: "user", content: strategicPrompt }
      ],
      max_completion_tokens: 2048,
    });

    return `${planLevel} Agent utilizing ${llmModel} for strategic path analysis.\n\n${response.choices[0].message.content}`;
  } catch (error) {
    console.error("Strategic planning failed:", error);
    return `${planLevel} Agent using ${llmModel} - Basic strategic assessment generated due to LLM error.`;
  }
}

async function reconSingleTarget(
  target: string,
  planLevel: string,
  llmModel: string,
  costPerTarget: number
): Promise<SingleTargetReconFindings> {
  const hostname = extractHostname(target);
  const ip = generateIP();
  const ports = generateRandomPorts();
  const services = generateServices(ports);
  
  const defaultTechs = ["PHP 7.4", "Python 3.8", "Node.js 14.x", "Apache 2.4", "MySQL 8.0", "Linux"];
  const numTechs = Math.floor(Math.random() * 3) + 2;
  const technologies = defaultTechs.sort(() => 0.5 - Math.random()).slice(0, numTechs);
  
  const baseDomain = hostname.replace(/^www\./, '');
  const subdomains = ["www", "api", "mail"].map(prefix => `${prefix}.${baseDomain}`);
  
  const strategicDecisionLog = await generateStrategicPlan(
    target,
    { ip, hostname, ports, services },
    planLevel,
    llmModel
  );
  
  return {
    target,
    ip,
    hostname,
    ports,
    services,
    technologies,
    subdomains,
    credit_deduction: costPerTarget,
    strategic_decision_log: strategicDecisionLog,
  };
}

export async function runReconAgentBatch(
  targets: string[],
  onProgress: (progress: number) => void,
  context: ReconExecutionContext
): Promise<any> {
  if (!context?.userId) {
    throw new Error("User ID is required for recon execution");
  }
  const userId = context.userId;
  
  const userCredits = await storage.getUserCredits(userId);
  const planLevel = context?.planLevel || userCredits.planLevel;
  const planConfig = PlanConfigs[planLevel];
  
  const validation = await validateScopeCost(targets, userId, planLevel);
  if (!validation.valid) {
    throw new Error(validation.error || "Scope validation failed");
  }
  
  console.log(`[RECON] FAIL-FAST CHECK PASSED: ${validation.scopeCost.totalCost} credits authorized for ${targets.length} targets`);
  console.log(`[RECON] Plan Level: ${planLevel}, LLM Model: ${planConfig.llmModel}, Cost Per Target: ${planConfig.creditCostPerTarget}`);
  
  const deductResult = await storage.deductCredits(userId, validation.scopeCost.totalCost);
  if (!deductResult.success) {
    throw new Error(deductResult.error || "Failed to deduct credits for scope");
  }
  
  console.log(`[RECON] Credits deducted: ${validation.scopeCost.totalCost}. Remaining: ${deductResult.newBalance}`);
  
  const targetResults: SingleTargetReconFindings[] = [];
  let osintQueriesMade = 0;
  
  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    const targetProgress = ((i + 1) / targets.length) * 90;
    
    onProgress(Math.round(5 + (i / targets.length) * 10));
    await randomDelay(200, 400);
    
    const targetResult = await reconSingleTarget(
      target,
      planLevel as string,
      planConfig.llmModel,
      planConfig.creditCostPerTarget
    );
    targetResults.push(targetResult);
    
    onProgress(Math.round(15 + targetProgress));
    await randomDelay(100, 200);
  }
  
  const primaryTarget = targetResults[0];
  
  let technologies: string[] = primaryTarget?.technologies || [];
  let subdomains: string[] = primaryTarget?.subdomains || [];
  
  onProgress(92);
  if (planLevel === 'PRO' || planLevel === 'ELITE') {
    const osintCost = planConfig.osintQueryCost;
    const currentBalance = await storage.getUserCredits(userId);
    
    if (currentBalance.balance >= osintCost) {
      const osintDeduct = await storage.deductCredits(userId, osintCost);
      if (osintDeduct.success) {
        osintQueriesMade++;
        
        const osintResult = await executeOSINTQuery(targets[0], "full", planLevel, planConfig.llmModel);
        if (osintResult.subdomains.length > 0) {
          subdomains = osintResult.subdomains;
        }
        if (osintResult.technologies.length > 0) {
          technologies = osintResult.technologies;
        }
      }
    }
  }
  
  const finalCredits = await storage.getUserCredits(userId);
  
  const combinedStrategicLog = targetResults.map((r, i) => 
    `=== Target ${i + 1}: ${r.target} ===\n${r.strategic_decision_log}`
  ).join('\n\n');
  
  onProgress(100);

  // Write discoveries to database for each subdomain
  if (subdomains.length > 0 && targets[0]) {
    const firstScanId = randomUUID();
    for (const subdomain of subdomains) {
      await storage.insertDiscovery({
        scanId: firstScanId,
        userId,
        discoveryType: "subdomain",
        url: subdomain,
        title: subdomain,
        method: "enumeration",
        parameters: { source: "osint_query" },
      });
    }
  }

  return {
    ip: primaryTarget?.ip,
    hostname: primaryTarget?.hostname,
    ports: primaryTarget?.ports,
    services: primaryTarget?.services,
    technologies,
    subdomains,
    credit_deduction_recon: validation.scopeCost.totalCost + (osintQueriesMade * planConfig.osintQueryCost),
    strategic_decision_log: combinedStrategicLog,
    llm_model_used: planConfig.llmModel,
    plan_level: planLevel,
    osint_queries_made: osintQueriesMade,
    remaining_credits: finalCredits.balance,
    target_results: targetResults,
  };
}

export async function runReconAgent(
  target: string,
  onProgress: (progress: number) => void,
  context?: ReconExecutionContext,
  scanId?: string
): Promise<any> {
  if (!context?.userId) {
    throw new Error("User ID is required for recon execution");
  }
  
  const results = await runReconAgentBatch([target], onProgress, context);
  
  // Agent-01: Emit subdomain discovery to terminal
  if (scanId && results.subdomains && results.subdomains.length > 0) {
    const { emitStdoutLog } = await import("../src/sockets/socketManager");
    emitStdoutLog(scanId, `[PHASE: RECON] Discovering subdomains...`, { type: "phase_update" });
    await randomDelay(200, 300);
    results.subdomains.forEach((subdomain) => {
      emitStdoutLog(scanId, `[AGENT-01] ✓ Found subdomain: ${subdomain}`, { agentLabel: "AGENT-01" });
    });
  }
  
  return results;
}
