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

const FULL_AGENT_SEQUENCE: AgentType[] = ["recon", "scanner", "exploiter", "reporter"];

function getAgentSequenceForPlan(planLevel: PlanLevel): AgentType[] {
  return FULL_AGENT_SEQUENCE.filter(agent => {
    const gatedAgent = agent as GatedAgentId;
    return hasAgentAccess(planLevel, gatedAgent);
  });
}

const GLOBAL_PIPELINE_TIMEOUT_MS = 30 * 60 * 1000;
const PER_AGENT_TIMEOUT_MS = 10 * 60 * 1000;

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
  
  console.log(`[PIPELINE] Running agents for ${userPlanLevel} plan: ${AGENT_SEQUENCE.join(", ")}`);
  
  // REAL-TIME LOGGING - Emit immediately to UI and console
  emitInfoLog(scanId, `Initializing ${userPlanLevel} scan pipeline for target: ${scan.target}`);
  emitExecLog(scanId, `shadowtwin --plan ${userPlanLevel} --target ${scan.target}`);
  emitStdoutLog(scanId, `[REAL-TIME]: Pipeline initialized`);
  emitStdoutLog(scanId, `[REAL-TIME]: Agent sequence: ${AGENT_SEQUENCE.join(" -> ")}`);
  
  process.stdout.write(`[PIPELINE_INIT] ${scanId} - Target: ${scan.target} - Plan: ${userPlanLevel}\n`);
  process.stdout.write(`[AGENTS_SEQUENCE] ${AGENT_SEQUENCE.join(" -> ")}\n`);
  
  if (userPlanLevel === "ELITE") {
    emitAiThoughtLog(scanId, `ELITE mode activated. Full agent pipeline with AI-enhanced analysis enabled.`);
    process.stdout.write(`[ELITE_MODE] Advanced AI analysis enabled\n`);
  }

  let reconData: ReconFindings | undefined;
  let scannerData: EnhancedScannerFindings | undefined;
  let exploiterData: ExploiterFindings | undefined;

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
            emitExecLog(scanId, `nmap -sV -T4 -Pn ${scan.target}`);
            emitStdoutLog(scanId, `Starting reconnaissance on ${scan.target}...`);
            
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
            emitExecLog(scanId, `nikto -h ${scan.target} -Format xml`);
            emitExecLog(scanId, `gobuster dir -u ${scan.target} -w /usr/share/wordlists/common.txt`);
            emitStdoutLog(scanId, `Starting vulnerability assessment...`);
            
            if (userPlanLevel === "ELITE") {
              emitAiThoughtLog(scanId, `Initiating deep vulnerability scan with OWASP methodology. Checking for SQLi, XSS, IDOR patterns.`);
            }
            
            scannerData = await withTimeout(
              runScannerAgent(scan.target, reconData, {
                userId: scan.userId,
                scanId: scanId,
                onProgress,
                planLevel: userPlanLevel,
              }),
              PER_AGENT_TIMEOUT_MS,
              "Scanner agent"
            );
            
            if (scannerData && scannerData.vulnerabilities) {
              emitStdoutLog(scanId, `Vulnerabilities discovered: ${scannerData.vulnerabilities.length}`);
              scannerData.vulnerabilities.forEach((v: EnhancedVulnerability) => {
                emitStdoutLog(scanId, `  [${v.severity.toUpperCase()}] ${v.title}`);
              });
              if (userPlanLevel === "ELITE") {
                const criticalCount = scannerData.vulnerabilities.filter((v: EnhancedVulnerability) => v.severity === "critical").length;
                if (criticalCount > 0) {
                  emitAiThoughtLog(scanId, `CRITICAL: Found ${criticalCount} critical vulnerabilities. Recommending immediate remediation.`);
                }
              }
            }
            result = scannerData;
            break;
          
          case "exploiter":
            if (!scannerData) throw new Error("Scanner data required for exploiter");
            const exploiterPlanLevel = context?.planLevel || (await storage.getUserCredits(scan.userId)).planLevel;
            const useStealthMode = 'waf_ids_detected' in scannerData && scannerData.waf_ids_detected;
            
            emitExecLog(scanId, `metasploit -q -x "use exploit/multi/handler"`);
            emitStdoutLog(scanId, `Initializing exploitation framework...`);
            
            if (userPlanLevel === "ELITE") {
              emitAiThoughtLog(scanId, `Preparing exploit payloads for ${scannerData.vulnerabilities?.length || 0} vulnerabilities. Using ${useStealthMode ? "stealth" : "standard"} mode.`);
            }
            
            if (useStealthMode && (exploiterPlanLevel === "ELITE" || exploiterPlanLevel === "STANDARD")) {
              emitInfoLog(scanId, `WAF/IDS detected - switching to stealth mode`);
              const stealthResult = await withTimeout(
                runStealthExploiterAgent(scan.target, scannerData, {
                  userId: scan.userId,
                  scanId: scanId,
                  stealthLevel: exploiterPlanLevel === "ELITE" ? "aggressive" : "cautious",
                  adaptiveMode: true,
                  onProgress,
                }),
                PER_AGENT_TIMEOUT_MS,
                "Stealth exploiter agent"
              );
              exploiterData = {
                exploitAttempts: stealthResult.exploitAttempts.map(e => ({
                  vulnerability: e.vulnerabilityTitle,
                  success: e.success,
                  technique: e.technique,
                  evidence: e.evidence,
                })),
                accessGained: stealthResult.accessGained,
                riskLevel: stealthResult.riskLevel,
              };
              result = exploiterData;
            } else {
              exploiterData = await withTimeout(
                runExploiterAgent(scan.target, scannerData, onProgress),
                PER_AGENT_TIMEOUT_MS,
                "Exploiter agent"
              );
              result = exploiterData;
            }
            
            if (exploiterData) {
              const successfulExploits = exploiterData.exploitAttempts?.filter(e => e.success).length || 0;
              emitStdoutLog(scanId, `Exploitation complete: ${successfulExploits} successful, Risk: ${exploiterData.riskLevel}`);
              if (userPlanLevel === "ELITE" && exploiterData.accessGained) {
                emitAiThoughtLog(scanId, `Access gained: ${exploiterData.accessGained}. Documenting attack chain for report.`);
              }
            }
            break;
          
          case "reporter":
            if (!reconData || !scannerData || !exploiterData) {
              throw new Error("All previous agent data required for reporter");
            }
            emitExecLog(scanId, `report-gen --format pdf,json --template security-audit`);
            emitStdoutLog(scanId, `Compiling security assessment report...`);
            
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
