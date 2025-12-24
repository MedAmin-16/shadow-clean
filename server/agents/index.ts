import type { 
  Scan, 
  AgentType, 
  ReconFindings, 
  ScannerFindings, 
  ExploiterFindings, 
  ReporterOutput,
  PlanLevel,
  EnhancedScannerFindings,
  EnhancedReporterOutput,
  EnhancedVulnerability,
  ProphetAnalysis,
  Level7ExploiterFindings,
  GatedAgentId
} from "@shared/schema";
import { hasAgentAccess } from "@shared/schema";
import type { ExploiterStealthFindings } from "@shared/stealth";
import type { AutonomousDefenseResult } from "@shared/level7";
import { runReconAgent } from "./recon";
import { runScannerAgent } from "./scanner";
import { runExploiterAgent } from "./exploiter";
import { runStealthExploiterAgent } from "./stealthExploiter";
import { runReporterAgent } from "./reporter";
import { runRLExploiterAgent } from "./rlExploiter";
import { runProphetAgent } from "./prophet";
import { runAutonomousDefense, generateDefenseReport } from "./autonomousDefense";
import { storage } from "../storage";
import { generateAllReportFormats } from "../src/services/reportService";
import {
  emitExecLog,
  emitStdoutLog,
  emitAiThoughtLog,
  emitInfoLog,
  emitWarningLog,
  emitErrorLog,
} from "../src/sockets/socketManager";

export { runStealthExploiterAgent } from "./stealthExploiter";

// Level 7 ELITE tier agents
export { 
  runRLExploiterAgent, 
  runProphetAgent, 
  runAutonomousDefense,
  generateDefenseReport,
  type RLExploiterOptions,
  type ProphetOptions,
  type AutonomousDefenseOptions 
} from "./level7";

/**
 * PROFESSIONAL PENTESTING METHODOLOGY - 5-PHASE PIPELINE
 * 
 * PHASE 1: RECONNAISSANCE (Broad Search)
 *   Tools: Assetfinder, Subfinder, HTTProbe, TheHarvester
 *   Purpose: Discover all subdomains and identify live assets
 * 
 * PHASE 2: ATTACK SURFACE MAPPING (Narrowing Down)
 *   Tools: Katana, GAU, WhatWeb, Arjun, ParamSpider
 *   Purpose: Crawl URLs, identify tech stack, find hidden parameters
 * 
 * PHASE 3: VULNERABILITY ANALYSIS (Scanning)
 *   Tools: Nuclei, FFuf, TruffleHog
 *   Purpose: Scan for vulnerabilities, leaked secrets, sensitive files
 * 
 * PHASE 4: TARGETED EXPLOITATION (Deep Dive)
 *   Tools: SQLMap (Level 3/Risk 2), Dalfox, Commix
 *   Purpose: Attempt targeted exploitation of discovered vulnerabilities
 * 
 * PHASE 5: REPORTING & COMPLIANCE
 *   Purpose: Map findings to OWASP Top 10, generate executive & technical reports
 */
const FULL_AGENT_SEQUENCE: AgentType[] = ["recon", "scanner", "exploiter", "reporter"];

function getAgentSequenceForPlan(planLevel: PlanLevel): AgentType[] {
  return FULL_AGENT_SEQUENCE.filter(agent => {
    const gatedAgent = agent as GatedAgentId;
    return hasAgentAccess(planLevel, gatedAgent);
  });
}

const GLOBAL_PIPELINE_TIMEOUT_MS = 30 * 60 * 1000;
const PER_AGENT_TIMEOUT_MS = 10 * 60 * 1000;
const CONCURRENCY_LIMIT = 4; // Max 3-5 subdomains at a time to avoid RAM crash

class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TimeoutError";
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timeoutId: NodeJS.Timeout;
  const timeoutPromise = new Promise<T>((_, reject) => {
    timeoutId = setTimeout(() => reject(new TimeoutError(`${label} timed out after ${timeoutMs / 1000}s`)), timeoutMs);
  });
  
  return Promise.race([promise, timeoutPromise]).finally(() => {
    clearTimeout(timeoutId);
  });
}

/**
 * CONCURRENCY CONTROL FOR SUBDOMAIN SCANNING
 * Processes subdomains in batches to avoid RAM exhaustion
 */
async function processWithConcurrency<T>(
  items: string[],
  processor: (item: string, index: number) => Promise<T>,
  concurrencyLimit: number = CONCURRENCY_LIMIT
): Promise<T[]> {
  const results: T[] = [];
  
  for (let i = 0; i < items.length; i += concurrencyLimit) {
    const batch = items.slice(i, i + concurrencyLimit);
    const startIdx = i;
    
    const batchResults = await Promise.all(
      batch.map((item, batchIdx) => processor(item, startIdx + batchIdx))
    );
    
    results.push(...batchResults);
  }
  
  return results;
}

function getAgentProgress(agentIndex: number, agentProgress: number): number {
  const baseProgress = agentIndex * 25;
  return baseProgress + Math.round((agentProgress / 100) * 25);
}

export interface PipelineContext {
  userId?: string;
  planLevel?: PlanLevel;
}

async function runPipelineInternal(scanId: string, context?: PipelineContext): Promise<void> {
  let scan = await storage.getScan(scanId);
  if (!scan) {
    throw new Error(`Scan ${scanId} not found`);
  }

  const userCredits = await storage.getUserCredits(scan.userId);
  const userPlanLevel = (context?.planLevel || userCredits.planLevel) as PlanLevel;
  const AGENT_SEQUENCE = getAgentSequenceForPlan(userPlanLevel);
  
  console.log(`[PIPELINE] Running 5-PHASE PROFESSIONAL PENTESTING METHODOLOGY for ${userPlanLevel} plan`);
  console.log(`[PHASES] Phase 1: RECONNAISSANCE → Phase 2: ATTACK SURFACE MAPPING → Phase 3: VULNERABILITY ANALYSIS → Phase 4: TARGETED EXPLOITATION → Phase 5: REPORTING & COMPLIANCE`);
  
  // REAL-TIME LOGGING - Emit immediately to UI and console
  emitInfoLog(scanId, `Initializing 5-PHASE professional pentesting scan for target: ${scan.target}`);
  emitExecLog(scanId, `shadowtwin --methodology pentesting-5-phase --plan ${userPlanLevel} --target ${scan.target}`);
  emitStdoutLog(scanId, `[PROFESSIONAL PENTESTING] 5-Phase Methodology Initialized`);
  emitStdoutLog(scanId, `Phase 1: RECONNAISSANCE (Assetfinder, Subfinder, HTTProbe, TheHarvester)`);
  emitStdoutLog(scanId, `Phase 2: ATTACK SURFACE MAPPING (Katana, GAU, WhatWeb, Arjun, ParamSpider)`);
  emitStdoutLog(scanId, `Phase 3: VULNERABILITY ANALYSIS (Nuclei, FFuf, TruffleHog)`);
  emitStdoutLog(scanId, `Phase 4: TARGETED EXPLOITATION (SQLMap Level 3, Dalfox, Commix)`);
  emitStdoutLog(scanId, `Phase 5: REPORTING & COMPLIANCE (OWASP Top 10 Mapping)`);
  
  process.stdout.write(`[PIPELINE_INIT] ${scanId} - Methodology: 5-PHASE PROFESSIONAL PENTESTING - Target: ${scan.target} - Plan: ${userPlanLevel}\n`);
  process.stdout.write(`[PHASE_SEQUENCE] RECONNAISSANCE → ATTACK SURFACE MAPPING → VULNERABILITY ANALYSIS → TARGETED EXPLOITATION → REPORTING & COMPLIANCE\n`);
  
  if (userPlanLevel === "ELITE") {
    emitAiThoughtLog(scanId, `ELITE mode activated. 5-PHASE PROFESSIONAL PENTESTING with full agent arsenal and AI-enhanced analysis enabled.`);
    process.stdout.write(`[ELITE_MODE] 5-PHASE Professional Pentesting Methodology + Advanced AI analysis enabled\n`);
  }

  let reconData: ReconFindings | undefined;
  let scannerData: EnhancedScannerFindings | undefined;
  let exploiterData: ExploiterFindings | undefined;
  
  // RECURSIVE SWARM TRACKING: Store subdomain-organized results
  interface SubdomainScanResult {
    subdomain: string;
    scanner?: EnhancedScannerFindings;
    exploiter?: ExploiterFindings;
  }
  const subdomainResults: SubdomainScanResult[] = [];

  try {
    for (let i = 0; i < AGENT_SEQUENCE.length; i++) {
      const agentType = AGENT_SEQUENCE[i];
      
      scan = await storage.getScan(scanId);
      if (!scan) throw new Error(`Scan ${scanId} not found`);
      
      emitInfoLog(scanId, `Starting agent: ${agentType.toUpperCase()}`);
      emitExecLog(scanId, `agent-${agentType} --scanId ${scanId} --target ${scan.target}`);
      
      await storage.updateScan(scanId, {
        currentAgent: agentType,
        status: "running",
        agentResults: {
          ...scan.agentResults,
          [agentType]: {
            agentType,
            status: "running",
            startedAt: new Date().toISOString(),
            data: {},
          },
        },
      });

      const onProgress = async (progress: number) => {
        const totalProgress = getAgentProgress(i, progress);
        await storage.updateScan(scanId, { progress: totalProgress });
        // REMOVED: Fake progress logs - using pure spawn() streaming now
      };

      let result: ReconFindings | ScannerFindings | ExploiterFindings | ReporterOutput;

      try {
        switch (agentType) {
          case "recon":
            const scanUserId = scan.userId;
            const userCredits = await storage.getUserCredits(scanUserId);
            emitExecLog(scanId, `[PHASE 1: RECONNAISSANCE] Executing broad asset discovery...`);
            emitExecLog(scanId, `assetfinder --subs-only ${scan.target}`);
            emitExecLog(scanId, `subfinder -d ${scan.target} -all`);
            emitExecLog(scanId, `httpprobe -p 80,443 < subdomains.txt`);
            emitExecLog(scanId, `theHarvester -d ${scan.target} -b all`);
            emitStdoutLog(scanId, `[PHASE 1] Starting RECONNAISSANCE on ${scan.target}...`);
            
            if (userPlanLevel === "ELITE") {
              emitAiThoughtLog(scanId, `Analyzing target attack surface. Will use ${userCredits.planLevel} LLM model for strategic planning.`);
            }
            
            reconData = await withTimeout(
              runReconAgent(scan.target, onProgress, {
                userId: scanUserId,
                planLevel: context?.planLevel || userCredits.planLevel,
              }, scanId),
              PER_AGENT_TIMEOUT_MS,
              "Recon agent"
            );
            
            if (reconData) {
              emitStdoutLog(scanId, `Host: ${reconData.hostname} (${reconData.ip})`);
              emitStdoutLog(scanId, `Open ports: ${reconData.ports?.join(", ") || "None detected"}`);
              reconData.services?.forEach(s => {
                emitStdoutLog(scanId, `  ${s.port}/tcp  ${s.service}  ${s.version || ""}`);
              });
              if (userPlanLevel === "ELITE" && reconData.strategic_decision_log) {
                emitAiThoughtLog(scanId, `Strategic analysis complete. Attack vectors identified.`);
              }
            }
            result = reconData;
            break;
          
          case "scanner":
            if (!reconData) throw new Error("Recon data required for scanner");
            
            // RECURSIVE SWARM: Extract live subdomains from Phase 1
            const liveSubdomains = reconData.subdomains || [scan.target];
            const totalSubdomains = liveSubdomains.length;
            
            emitExecLog(scanId, `[RECURSIVE SWARM ACTIVATED] Phase 1 discovered ${totalSubdomains} live subdomain(s)`);
            emitStdoutLog(scanId, `[SWARM MODE] Targeting ${totalSubdomains} subdomain(s) with PHASES 2-4 (Concurrency Limit: ${CONCURRENCY_LIMIT})`);
            
            if (totalSubdomains > 1) {
              emitStdoutLog(scanId, `[SWARM] Discovered subdomains:`);
              liveSubdomains.forEach((sub, idx) => {
                emitStdoutLog(scanId, `  [${idx + 1}/${totalSubdomains}] ${sub}`);
              });
            }
            
            // Process subdomains with concurrency control
            subdomainResults.length = 0;
            const subdomainProcessingResults = await processWithConcurrency(
              liveSubdomains,
              async (subdomain: string, index: number) => {
                emitExecLog(scanId, `[SWARM] [${index + 1}/${totalSubdomains}] Processing: ${subdomain}`);
                emitStdoutLog(scanId, `[PHASE 2-3] Scanning subdomain [${index + 1}/${totalSubdomains}]: ${subdomain}`);
                
                try {
                  const subdomainScannerData = await withTimeout(
                    runScannerAgent(subdomain, reconData, {
                      userId: scan.userId,
                      scanId: scanId,
                      onProgress,
                      planLevel: userPlanLevel,
                    }),
                    PER_AGENT_TIMEOUT_MS,
                    `Scanner agent [${subdomain}]`
                  );
                  
                  emitStdoutLog(scanId, `[PHASE 2-3] Subdomain ${subdomain}: ${subdomainScannerData?.vulnerabilities?.length || 0} vulnerabilities`);
                  
                  return {
                    subdomain,
                    scanner: subdomainScannerData,
                  } as SubdomainScanResult;
                } catch (err) {
                  emitStdoutLog(scanId, `[ERROR] Scanner failed for ${subdomain}: ${err instanceof Error ? err.message : "Unknown error"}`);
                  return { subdomain, scanner: undefined } as SubdomainScanResult;
                }
              },
              CONCURRENCY_LIMIT
            );
            
            subdomainResults.push(...subdomainProcessingResults);
            
            // Aggregate scanner data from all subdomains
            const aggregatedVulnerabilities = subdomainResults
              .flatMap(r => r.scanner?.vulnerabilities || [])
              .map(v => ({ ...v, subdomain: v.service || scan.target }));
            
            scannerData = {
              vulnerabilities: aggregatedVulnerabilities,
              apiEndpoints: subdomainResults.flatMap(r => r.scanner?.apiEndpoints || []),
              technologies: [...new Set(subdomainResults.flatMap(r => r.scanner?.technologies || []))],
              totalFindings: aggregatedVulnerabilities.length,
              criticalCount: aggregatedVulnerabilities.filter(v => v.severity === "critical").length,
              highCount: aggregatedVulnerabilities.filter(v => v.severity === "high").length,
              decisionLog: [`Scanned ${totalSubdomains} subdomains with ${CONCURRENCY_LIMIT}-concurrent limit`],
              agentResults: {},
            };
            
            emitStdoutLog(scanId, `[SWARM PHASE 2-3 COMPLETE] Total vulnerabilities across all subdomains: ${scannerData.totalFindings}`);
            result = scannerData;
            break;
          
          case "exploiter":
            if (!scannerData || subdomainResults.length === 0) throw new Error("Scanner data and subdomain results required for exploiter");
            const exploiterPlanLevel = context?.planLevel || (await storage.getUserCredits(scan.userId)).planLevel;
            
            emitExecLog(scanId, `[PHASE 4: RECURSIVE SWARM EXPLOITATION] Running on ${subdomainResults.length} subdomains...`);
            emitStdoutLog(scanId, `[PHASE 4] Starting TARGETED EXPLOITATION on all discovered subdomains...`);
            
            // Process exploitation for each subdomain with concurrency control
            const exploitationResults = await processWithConcurrency(
              subdomainResults,
              async (result: SubdomainScanResult, index: number) => {
                emitStdoutLog(scanId, `[PHASE 4] Exploiting vulnerabilities in [${index + 1}/${subdomainResults.length}]: ${result.subdomain}`);
                
                try {
                  const useStealthMode = 'waf_ids_detected' in (result.scanner || {}) && (result.scanner as any)?.waf_ids_detected;
                  
                  let exploitResult: ExploiterFindings;
                  if (useStealthMode && (exploiterPlanLevel === "ELITE" || exploiterPlanLevel === "STANDARD")) {
                    const stealthResult = await withTimeout(
                      runStealthExploiterAgent(result.subdomain, result.scanner!, {
                        userId: scan.userId,
                        scanId: scanId,
                        stealthLevel: exploiterPlanLevel === "ELITE" ? "aggressive" : "cautious",
                        adaptiveMode: true,
                        onProgress,
                      }),
                      PER_AGENT_TIMEOUT_MS,
                      `Stealth exploiter [${result.subdomain}]`
                    );
                    exploitResult = {
                      exploitAttempts: stealthResult.exploitAttempts.map(e => ({
                        vulnerability: e.vulnerabilityTitle,
                        success: e.success,
                        technique: e.technique,
                        evidence: e.evidence,
                      })),
                      accessGained: stealthResult.accessGained,
                      riskLevel: stealthResult.riskLevel,
                    };
                  } else {
                    exploitResult = await withTimeout(
                      runExploiterAgent(result.subdomain, result.scanner!, onProgress),
                      PER_AGENT_TIMEOUT_MS,
                      `Exploiter [${result.subdomain}]`
                    );
                  }
                  
                  const successCount = exploitResult.exploitAttempts?.filter(e => e.success).length || 0;
                  emitStdoutLog(scanId, `[PHASE 4] Subdomain ${result.subdomain}: ${successCount} successful exploits`);
                  
                  return { ...result, exploiter: exploitResult } as SubdomainScanResult & { exploiter: ExploiterFindings };
                } catch (err) {
                  emitStdoutLog(scanId, `[ERROR] Exploitation failed for ${result.subdomain}: ${err instanceof Error ? err.message : "Unknown error"}`);
                  return { ...result, exploiter: undefined } as SubdomainScanResult;
                }
              },
              CONCURRENCY_LIMIT
            );
            
            // Update subdomain results with exploiter data
            exploitationResults.forEach((result, idx) => {
              const existing = subdomainResults.find(r => r.subdomain === result.subdomain);
              if (existing && result.exploiter) {
                existing.exploiter = result.exploiter;
              }
            });
            
            // Aggregate exploiter data
            const aggregatedExploits = subdomainResults
              .flatMap(r => r.exploiter?.exploitAttempts || []);
            
            exploiterData = {
              exploitAttempts: aggregatedExploits,
              accessGained: subdomainResults.some(r => r.exploiter?.accessGained) ? "Multiple subdomains compromised" : undefined,
              riskLevel: subdomainResults.some(r => r.exploiter?.riskLevel === "critical") ? "critical" : 
                         subdomainResults.some(r => r.exploiter?.riskLevel === "high") ? "high" : "medium",
            };
            
            emitStdoutLog(scanId, `[SWARM PHASE 4 COMPLETE] Total successful exploits across all subdomains: ${aggregatedExploits.filter(e => e.success).length}`);
            result = exploiterData;
            break;
          
          case "reporter":
            if (!reconData || !scannerData || !exploiterData) {
              throw new Error("All previous agent data required for reporter");
            }
            emitExecLog(scanId, `[PHASE 5: REPORTING & COMPLIANCE] Mapping findings to OWASP Top 10...`);
            emitExecLog(scanId, `report-gen --methodology pentesting-5-phase --owasp-mapping --format pdf,json --template executive,technical`);
            emitStdoutLog(scanId, `[PHASE 5] Compiling OWASP Top 10 compliance report...`);
            emitStdoutLog(scanId, `[PHASE 5] Generating Executive Summary for managers`);
            emitStdoutLog(scanId, `[PHASE 5] Generating Technical Remediation guide for developers`);
            
            if (userPlanLevel === "ELITE") {
              emitAiThoughtLog(scanId, `Generating comprehensive executive and technical reports with AI-enhanced recommendations.`);
            }
            
            const reporterResult = await withTimeout(
              runReporterAgent(
                scan.target, 
                reconData, 
                scannerData, 
                exploiterData, 
                onProgress,
                {
                  userId: scan.userId,
                  scanId: scanId,
                  planLevel: context?.planLevel,
                  onProgress,
                }
              ),
              PER_AGENT_TIMEOUT_MS,
              "Reporter agent"
            );
            result = reporterResult;
            
            emitStdoutLog(scanId, `Report generated successfully. Security Score: ${reporterResult.securityScore}/100`);
            
            if ('planLevel' in reporterResult && (reporterResult.planLevel === "ELITE" || reporterResult.planLevel === "STANDARD")) {
              try {
                const reportFormats = await generateAllReportFormats(
                  scanId,
                  reporterResult as EnhancedReporterOutput,
                  scan.target,
                  scannerData as unknown as Record<string, unknown>,
                  exploiterData as unknown as Record<string, unknown>
                );
                
                if (reportFormats.executivePdf) {
                  (result as EnhancedReporterOutput).executivePdfPath = reportFormats.executivePdf;
                }
                if (reportFormats.technicalPdf) {
                  (result as EnhancedReporterOutput).technicalPdfPath = reportFormats.technicalPdf;
                }
                if (reportFormats.jsonExport) {
                  (result as EnhancedReporterOutput).rawDataExportPath = reportFormats.jsonExport;
                }
                if (reportFormats.csvExport) {
                  (result as EnhancedReporterOutput).csvExportPath = reportFormats.csvExport;
                }
              } catch (pdfError) {
                console.log("[PIPELINE] PDF generation failed, continuing without PDFs:", pdfError);
              }
            }
            break;
          
          default:
            throw new Error(`Unknown agent type: ${agentType}`);
        }

        // Fetch latest scan state before updating to preserve all agent results
        const currentScan = await storage.getScan(scanId);
        if (!currentScan) throw new Error(`Scan ${scanId} not found`);
        
        await storage.updateScan(scanId, {
          agentResults: {
            ...currentScan.agentResults,
            [agentType]: {
              agentType,
              status: "complete",
              startedAt: currentScan.agentResults?.[agentType]?.startedAt,
              completedAt: new Date().toISOString(),
              data: result,
            },
          },
        });
        
      } catch (agentError) {
        // Mark specific agent as failed but continue to mark overall scan as failed
        const errorMessage = agentError instanceof Error ? agentError.message : "Unknown error";
        const currentScan = await storage.getScan(scanId);
        
        if (currentScan) {
          await storage.updateScan(scanId, {
            agentResults: {
              ...currentScan.agentResults,
              [agentType]: {
                agentType,
                status: "failed",
                startedAt: currentScan.agentResults?.[agentType]?.startedAt,
                completedAt: new Date().toISOString(),
                error: errorMessage,
                data: {},
              },
            },
          });
        }
        
        throw agentError;
      }
    }

    // Run Level 7 ELITE agents after standard pipeline
    const elitePlanLevel = context?.planLevel || (await storage.getUserCredits(scan.userId)).planLevel;
    
    if (elitePlanLevel === "ELITE" && scannerData && exploiterData) {
      try {
        console.log("[PIPELINE] Running Level 7 ELITE agents...");
        
        // Run RL Exploiter Agent (enhanced exploitation with reinforcement learning)
        const rlProgressCallback = async (progress: number) => {
          await storage.updateScan(scanId, { progress: 80 + Math.round(progress * 0.05) });
        };
        
        const level7Scan = await storage.getScan(scanId);
        if (level7Scan) {
          await storage.updateScan(scanId, {
            currentAgent: "rl_exploiter",
            agentResults: {
              ...level7Scan.agentResults,
              rl_exploiter: {
                agentType: "rl_exploiter",
                status: "running",
                startedAt: new Date().toISOString(),
                data: {},
              },
            },
          });
        }
        
        const rlExploiterResult = await withTimeout(
          runRLExploiterAgent(scan.target, scannerData, {
            userId: scan.userId,
            scanId: scanId,
            onProgress: rlProgressCallback,
          }),
          PER_AGENT_TIMEOUT_MS,
          "RL Exploiter agent"
        );
        
        const afterRlScan = await storage.getScan(scanId);
        if (afterRlScan) {
          await storage.updateScan(scanId, {
            agentResults: {
              ...afterRlScan.agentResults,
              rl_exploiter: {
                agentType: "rl_exploiter",
                status: "complete",
                startedAt: afterRlScan.agentResults?.["rl_exploiter"]?.startedAt,
                completedAt: new Date().toISOString(),
                data: rlExploiterResult,
              },
            },
          });
        }
        
        console.log("[PIPELINE] RL Exploiter complete. Updating reporter with PoC evidence...");
        
        // Update reporter output with RL Exploiter PoC evidence
        try {
          const scanForReporterUpdate = await storage.getScan(scanId);
          if (scanForReporterUpdate?.agentResults?.reporter?.data) {
            const existingReporterData = scanForReporterUpdate.agentResults.reporter.data as EnhancedReporterOutput;
            if (existingReporterData.planLevel === "ELITE") {
              // Import the PoC extraction functions
              const { extractLevel7PoCEvidence, generateRLExploiterSummary } = await import("./reporter");
              
              // Extract Level 7 PoC evidence from RL Exploiter results
              const level7PoCEvidence = extractLevel7PoCEvidence(rlExploiterResult);
              const rlExploiterSummary = generateRLExploiterSummary(rlExploiterResult);
              
              // Update reporter output with Level 7 PoC evidence
              const updatedReporterData: EnhancedReporterOutput = {
                ...existingReporterData,
                level7PoCEvidence,
                rlExploiterSummary,
              };
              
              await storage.updateScan(scanId, {
                agentResults: {
                  ...scanForReporterUpdate.agentResults,
                  reporter: {
                    ...scanForReporterUpdate.agentResults.reporter,
                    data: updatedReporterData,
                  },
                },
              });
              
              console.log(`[PIPELINE] Reporter updated with ${level7PoCEvidence.length} PoC entries (${rlExploiterSummary.successfulExploits} successful exploits)`);
              
              // Regenerate PDF reports to include Level 7 PoC evidence
              try {
                const reportFormats = await generateAllReportFormats(
                  scanId,
                  updatedReporterData,
                  scan.target,
                  scannerData as unknown as Record<string, unknown>,
                  exploiterData as unknown as Record<string, unknown>
                );
                
                const finalReporterData = { ...updatedReporterData };
                if (reportFormats.executivePdf) {
                  finalReporterData.executivePdfPath = reportFormats.executivePdf;
                }
                if (reportFormats.technicalPdf) {
                  finalReporterData.technicalPdfPath = reportFormats.technicalPdf;
                }
                if (reportFormats.jsonExport) {
                  finalReporterData.rawDataExportPath = reportFormats.jsonExport;
                }
                if (reportFormats.csvExport) {
                  finalReporterData.csvExportPath = reportFormats.csvExport;
                }
                
                // Update with regenerated export paths
                const scanWithNewPaths = await storage.getScan(scanId);
                if (scanWithNewPaths) {
                  await storage.updateScan(scanId, {
                    agentResults: {
                      ...scanWithNewPaths.agentResults,
                      reporter: {
                        ...scanWithNewPaths.agentResults.reporter!,
                        data: finalReporterData,
                      },
                    },
                  });
                }
                console.log("[PIPELINE] PDFs regenerated with Level 7 PoC evidence");
              } catch (pdfRegenError) {
                console.log("[PIPELINE] Failed to regenerate PDFs with Level 7 PoC:", pdfRegenError);
              }
            }
          }
        } catch (pocUpdateError) {
          console.log("[PIPELINE] Failed to update reporter with PoC evidence:", pocUpdateError);
        }
        
        console.log("[PIPELINE] Running Prophet analysis...");
        
        // Run Prophet Agent (causal inference and financial modeling)
        const prophetProgressCallback = async (progress: number) => {
          await storage.updateScan(scanId, { progress: 85 + Math.round(progress * 0.05) });
        };
        
        const prophetScan = await storage.getScan(scanId);
        if (prophetScan) {
          await storage.updateScan(scanId, {
            currentAgent: "prophet",
            agentResults: {
              ...prophetScan.agentResults,
              prophet: {
                agentType: "prophet",
                status: "running",
                startedAt: new Date().toISOString(),
                data: {},
              },
            },
          });
        }
        
        const prophetResult = await withTimeout(
          runProphetAgent(scannerData, exploiterData, {
            userId: scan.userId,
            scanId: scanId,
            onProgress: prophetProgressCallback,
          }),
          PER_AGENT_TIMEOUT_MS,
          "Prophet agent"
        );
        
        const afterProphetScan = await storage.getScan(scanId);
        if (afterProphetScan) {
          await storage.updateScan(scanId, {
            agentResults: {
              ...afterProphetScan.agentResults,
              prophet: {
                agentType: "prophet",
                status: "complete",
                startedAt: afterProphetScan.agentResults?.["prophet"]?.startedAt,
                completedAt: new Date().toISOString(),
                data: prophetResult,
              },
            },
          });
        }
        
        console.log("[PIPELINE] Prophet complete. Running Autonomous Defense...");
        
        // Run Autonomous Defense (WAF/Firewall hotfix integration)
        const defenseProgressCallback = async (progress: number) => {
          await storage.updateScan(scanId, { progress: 90 + Math.round(progress * 0.1) });
        };
        
        const defenseScan = await storage.getScan(scanId);
        if (defenseScan) {
          await storage.updateScan(scanId, {
            currentAgent: "autonomous_defense",
            agentResults: {
              ...defenseScan.agentResults,
              autonomous_defense: {
                agentType: "autonomous_defense",
                status: "running",
                startedAt: new Date().toISOString(),
                data: {},
              },
            },
          });
        }
        
        const defenseResult = await withTimeout(
          runAutonomousDefense(scannerData, {
            userId: scan.userId,
            scanId: scanId,
            target: scan.target,
            onProgress: defenseProgressCallback,
          }),
          PER_AGENT_TIMEOUT_MS,
          "Autonomous Defense agent"
        );
        
        const afterDefenseScan = await storage.getScan(scanId);
        if (afterDefenseScan) {
          await storage.updateScan(scanId, {
            agentResults: {
              ...afterDefenseScan.agentResults,
              autonomous_defense: {
                agentType: "autonomous_defense",
                status: "complete",
                startedAt: afterDefenseScan.agentResults?.["autonomous_defense"]?.startedAt,
                completedAt: new Date().toISOString(),
                data: defenseResult,
              },
            },
          });
        }
        
        console.log("[PIPELINE] Autonomous Defense complete. Regenerating PDFs with Agent 7 Executive Summary...");
        
        try {
          const scanForFinalPdf = await storage.getScan(scanId);
          if (scanForFinalPdf?.agentResults?.reporter?.data) {
            const reporterDataForPdf = scanForFinalPdf.agentResults.reporter.data as EnhancedReporterOutput;
            
            const finalReportFormats = await generateAllReportFormats(
              scanId,
              reporterDataForPdf,
              scan.target,
              scannerData as unknown as Record<string, unknown>,
              exploiterData as unknown as Record<string, unknown>,
              defenseResult
            );
            
            const updatedReporterWithPaths = { ...reporterDataForPdf };
            if (finalReportFormats.executivePdf) {
              updatedReporterWithPaths.executivePdfPath = finalReportFormats.executivePdf;
            }
            if (finalReportFormats.technicalPdf) {
              updatedReporterWithPaths.technicalPdfPath = finalReportFormats.technicalPdf;
            }
            if (finalReportFormats.jsonExport) {
              updatedReporterWithPaths.rawDataExportPath = finalReportFormats.jsonExport;
            }
            if (finalReportFormats.csvExport) {
              updatedReporterWithPaths.csvExportPath = finalReportFormats.csvExport;
            }
            
            const scanForPathUpdate = await storage.getScan(scanId);
            if (scanForPathUpdate) {
              await storage.updateScan(scanId, {
                agentResults: {
                  ...scanForPathUpdate.agentResults,
                  reporter: {
                    ...scanForPathUpdate.agentResults.reporter!,
                    data: updatedReporterWithPaths,
                  },
                },
              });
            }
            console.log("[PIPELINE] PDFs regenerated with Agent 7 Orchestrator Executive Summary");
          }
        } catch (finalPdfError) {
          console.log("[PIPELINE] Failed to regenerate final PDFs with Agent 7 data:", finalPdfError);
        }
        
        console.log("[PIPELINE] Level 7 ELITE agents completed successfully.");
        
      } catch (eliteError) {
        console.log("[PIPELINE] Level 7 ELITE agents failed, continuing with standard results:", eliteError);
        // Level 7 failures are non-fatal - the standard pipeline results are still valid
      }
    }

    // Fetch final state and mark complete
    const finalScan = await storage.getScan(scanId);
    await storage.updateScan(scanId, {
      status: "complete",
      currentAgent: null,
      progress: 100,
      completedAt: new Date().toISOString(),
      agentResults: finalScan?.agentResults,
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
    
    // Preserve agent results when marking scan as failed
    const failedScan = await storage.getScan(scanId);
    await storage.updateScan(scanId, {
      status: "failed",
      error: errorMessage,
      completedAt: new Date().toISOString(),
      agentResults: failedScan?.agentResults,
    });
    
    throw error;
  }
}

export async function runAgentPipeline(scanId: string, context?: PipelineContext): Promise<void> {
  return withTimeout(
    runPipelineInternal(scanId, context),
    GLOBAL_PIPELINE_TIMEOUT_MS,
    "Agent pipeline"
  );
}
