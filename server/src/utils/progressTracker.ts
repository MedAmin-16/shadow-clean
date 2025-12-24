import { emitStdoutLog } from "../sockets/socketManager";

export interface ProgressState {
  scanId: string;
  toolName: string;
  totalTargets: number;
  processedTargets: number;
  currentPhase: string;
  lastActivityTime: number;
  lastProgressReport: number;
  heartbeatInterval?: NodeJS.Timeout;
}

const progressMap = new Map<string, ProgressState>();
const spinnerFrames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
let spinnerIndex = 0;

export function initializeProgress(scanId: string, toolName: string, totalTargets: number, phase: string): ProgressState {
  const state: ProgressState = {
    scanId,
    toolName,
    totalTargets,
    processedTargets: 0,
    currentPhase: phase,
    lastActivityTime: Date.now(),
    lastProgressReport: Date.now(),
  };

  progressMap.set(scanId, state);
  startHeartbeat(scanId, toolName);
  return state;
}

function startHeartbeat(scanId: string, toolName: string): void {
  const state = progressMap.get(scanId);
  if (!state) return;

  state.heartbeatInterval = setInterval(() => {
    const now = Date.now();
    // If no activity for 10 seconds, emit heartbeat
    if (now - state.lastActivityTime > 10000) {
      const spinner = spinnerFrames[spinnerIndex % spinnerFrames.length];
      spinnerIndex++;
      
      emitStdoutLog(scanId, `${spinner} [STILL SCANNING...] ${toolName} is processing targets... No findings yet, but still working.`, {
        agentLabel: toolName,
        type: "info",
      });
      state.lastActivityTime = now;
    }
  }, 10000); // Check every 10 seconds
}

export function updateProgress(scanId: string, processed: number, lastFoundTarget?: string): void {
  const state = progressMap.get(scanId);
  if (!state) return;

  state.processedTargets = processed;
  state.lastActivityTime = Date.now();

  // Report progress every 10% or when significant progress made
  const progressPercent = Math.round((processed / state.totalTargets) * 100);
  const lastReportPercent = Math.round((state.processedTargets - 1) / state.totalTargets) * 100;

  if (progressPercent % 10 === 0 && progressPercent !== lastReportPercent) {
    const now = Date.now();
    if (now - state.lastProgressReport > 5000) { // Don't report more than every 5 seconds
      reportProgress(scanId, state);
      state.lastProgressReport = now;
    }
  }
}

function reportProgress(scanId: string, state: ProgressState): void {
  const progressPercent = Math.round((state.processedTargets / state.totalTargets) * 100);
  const barLength = 20;
  const filledLength = Math.round((progressPercent / 100) * barLength);
  const bar = "█".repeat(filledLength) + "░".repeat(barLength - filledLength);

  const message = `[PROGRESS] ${state.currentPhase}: ${progressPercent}% [${bar}] (${state.processedTargets}/${state.totalTargets} targets)`;
  emitStdoutLog(scanId, message, {
    agentLabel: state.toolName,
    type: "progress",
  });
}

export function incrementProgress(scanId: string, amount: number = 1): void {
  const state = progressMap.get(scanId);
  if (!state) return;

  state.processedTargets += amount;
  state.lastActivityTime = Date.now();
  updateProgress(scanId, state.processedTargets);
}

export function completeProgress(scanId: string): void {
  const state = progressMap.get(scanId);
  if (!state) return;

  if (state.heartbeatInterval) {
    clearInterval(state.heartbeatInterval);
  }

  // Final progress report
  reportProgress(scanId, state);
  progressMap.delete(scanId);
}

export function getProgress(scanId: string): ProgressState | undefined {
  return progressMap.get(scanId);
}

export function parseToolOutput(output: string, toolName: string): number {
  if (toolName === "httpx" || toolName === "katana") {
    // Count lines (URLs) in output
    return output.split("\n").filter((line) => line.trim() && line.includes("http")).length;
  } else if (toolName === "nuclei") {
    // Count JSON results
    return output.split("\n").filter((line) => line.startsWith("{")).length;
  }
  return 0;
}
