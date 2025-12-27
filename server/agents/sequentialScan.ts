import { spawn, execSync } from "child_process";
import { writeFileSync, unlinkSync, mkdirSync, existsSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { emitStdoutLog, emitExecLog, emitErrorLog } from "../src/sockets/socketManager";

import { db } from "../db";
import { type DbScan as Scan, scansTable as scans } from "@shared/schema";
import { eq } from "drizzle-orm";

// Track active processes per scan
const activeProcesses = new Map<string, any>();

export function killScanProcess(scanId: string) {
  const child = activeProcesses.get(scanId);
  if (child) {
    try {
      // Use SIGKILL for immediate termination of the process tree
      child.kill("SIGKILL");
      activeProcesses.delete(scanId);
      return true;
    } catch (error) {
      console.error(`[KILL-PROCESS] Failed to kill process for scan ${scanId}:`, error);
    }
  }
  return false;
}

/**
 * Kill all hanging tool processes before starting a new scan
 */
function cleanupHangingProcesses() {
  try {
    const tools = ["nuclei", "katana", "dalfox", "assetfinder", "httpx", "gau", "sqlmap", "commix"];
    tools.forEach(tool => {
      try {
        execSync(`pkill -9 ${tool}`, { stdio: "ignore" });
      } catch (e) {
        // Process might not exist, ignore
      }
    });
  } catch (err) {
    console.error("[CLEANUP] Global process cleanup failed:", err);
  }
}

async function updateScanProgress(scanId: string, progress: number, currentAgent?: string) {
  try {
    const updateData: any = { progress: Math.min(progress, 99) };
    if (currentAgent) updateData.currentAgent = currentAgent;
    await db.update(scans).set(updateData).where(eq(scans.id, scanId));
    
    // Broadcast progress via socket
    const { emitScanProgress, emitToScan } = await import("../src/sockets/socketManager");
    emitScanProgress(scanId, updateData.progress, currentAgent);
    
    // Force UI state update for all subscribers
    emitToScan(scanId, "scan:progress", {
      scanId,
      progress: updateData.progress,
      currentAgent: currentAgent
    });
  } catch (error) {
    console.error(`[PROGRESS-UPDATE] Failed to update progress for ${scanId}:`, error);
  }
}

/**
 * Capture a screenshot of a vulnerable URL
 */
async function captureScreenshot(scanId: string, url: string, vulnerabilityId: string): Promise<string | null> {
  const screenshotDir = join(process.cwd(), "public", "screenshots");
  if (!existsSync(screenshotDir)) {
    mkdirSync(screenshotDir, { recursive: true });
  }

  const filename = `screenshot-${scanId}-${vulnerabilityId}.png`;
  const filepath = join(screenshotDir, filename);
  const publicPath = `/screenshots/${filename}`;

  try {
    emitStdoutLog(scanId, `[SYSTEM] 📸 Triggering screenshot for: ${url}`, { agentLabel: "SCREENSHOT", type: "info" });
    
    // Using npx playwright as it handles local installation if needed
    const cmd = `npx playwright screenshot --wait-for-timeout 3000 "${url}" "${filepath}"`;
    execSync(cmd, { timeout: 15000 });
    
    emitStdoutLog(scanId, `[SYSTEM] ✅ Screenshot captured: ${publicPath}`, { agentLabel: "SCREENSHOT", type: "success" });
    return publicPath;
  } catch (error) {
    emitStdoutLog(scanId, `[SYSTEM] ⚠️ Screenshot Unavailable for ${url}`, { agentLabel: "SCREENSHOT", type: "warning" });
    return null;
  }
}
import {
  createBanner,
  logPhaseInfo,
  logToolExecution,
  logFinding,
  logSuccess,
  logWarning,
  logError,
  logDiscovery,
  createFinalReport,
  createProgressLine,
  icons,
  colors,
} from "../src/utils/terminalFormatter";
import { filterToolOutput } from "../src/utils/toolOutputFilter";

interface ScanData {
  target: string;
  scanId: string;
  subdomains: string[];
  urls: string[]; // Global list of all URLs from all subdomains
  vulnerabilities: any[];
  errors: string[];
  subdomainMetadata: Map<string, { urlCount: number; vulnerabilityCount: number }>;
}

/**
 * Filter and format tool output for cleaner terminal display
 */
function formatToolOutput(line: string, agentLabel: string): { text: string; type: "info" | "error" | "stdout" | "finding" } {
  const lowerLine = line.toLowerCase();
  
  // GAU config warning filter
  if (line.includes("config file") && line.includes(".gau.toml") && line.includes("not found")) {
    return { text: "", type: "info" }; 
  }

  // Smart Information Filtering
  if (
    line.includes("[INF]") || 
    line.includes("[Information]") || 
    lowerLine.includes("installing...") ||
    lowerLine.includes("loading") ||
    lowerLine.includes("updating") ||
    line.includes("[stats]") ||
    line.includes("%")
  ) {
    return { text: line, type: "info" };
  }

  // Default to stdout for most tool output unless it's clearly an error
  if (lowerLine.includes("error") || lowerLine.includes("failed") || lowerLine.includes("fatal")) {
    // Only treat as error if it's not a known false positive or info line
    if (!lowerLine.includes("info") && !lowerLine.includes("debug") && !lowerLine.includes("warning")) {
      return { text: line, type: "error" };
    }
  }

  return { text: line, type: "stdout" };
}

/**
 * Execute a command with spawn() and return output
 */
function executeCommand(
  scanId: string,
  command: string,
  args: string[],
  phaseName: string
): Promise<string> {
  return new Promise((resolve) => {
    const output: string[] = [];
    const errorOutput: string[] = [];

    emitExecLog(scanId, `[${phaseName}] $ ${command} ${args.join(" ")}`);

    // Skip stdbuf for dalfox (GLIBC compatibility issue), use direct spawn
    let spawnCmd = command;
    let spawnArgs = args;
    
    if (!command.includes("dalfox")) {
      spawnCmd = "stdbuf";
      spawnArgs = ["-oL", "-eL", command, ...args];
    }

    const child = spawn(spawnCmd, spawnArgs, { 
      shell: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: { 
        ...process.env, 
        PATH: `${process.env.PATH}:/home/runner/workspace/bin`,
        PYTHONUNBUFFERED: "1"
      }
    });

    activeProcesses.set(scanId, child);

    let lastOutputTime = Date.now();
    // NUCLEI GRACE PERIOD: 5 minutes (300s) for Nuclei, 60s for others
    const silenceTimeout = phaseName.includes("NUCLEI") ? 300000 : 60000;
    
    const silenceCheck = setInterval(() => {
      if (child.killed) {
        clearInterval(silenceCheck);
        return;
      }
      if (Date.now() - lastOutputTime > silenceTimeout) {
        emitStdoutLog(scanId, `[SYSTEM] Tool silent for >${silenceTimeout/1000}s. Auto-forwarding results to prevent hang.`, { agentLabel: phaseName, type: "warning" });
        child.kill("SIGKILL");
        clearInterval(silenceCheck);
      }
    }, 10000);

    child.stdout?.on("data", (data: Buffer) => {
      lastOutputTime = Date.now();
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        output.push(line);
        const filtered = formatToolOutput(line, phaseName);
        if (filtered.text) {
          emitStdoutLog(scanId, filtered.text, { agentLabel: phaseName, type: filtered.type });
        }
      });
    });

    child.stderr?.on("data", (data: Buffer) => {
      lastOutputTime = Date.now();
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        const filtered = formatToolOutput(line, phaseName);
        if (filtered.text) {
          emitStdoutLog(scanId, filtered.text, { agentLabel: phaseName, type: filtered.type });
        }
        errorOutput.push(line);
      });
    });

    child.on("close", (code: number) => {
      clearInterval(silenceCheck);
      activeProcesses.delete(scanId);
      if (code !== 0 && code !== null) {
        emitStdoutLog(scanId, `[${phaseName}] ⚠️ Command exited with code ${code}`, { agentLabel: phaseName, type: "warning" });
      }
      resolve(output.join("\n"));
    });

    child.on("error", (err: any) => {
      clearInterval(silenceCheck);
      emitErrorLog(scanId, `[${phaseName}] Process spawn error: ${err.message} (Code: ${err.code})`);
      emitStdoutLog(scanId, `[SYSTEM] Process error - ${err.code || 'UNKNOWN'}: ${err.message}`, { agentLabel: phaseName, type: "error" });
      resolve("");
    });
  });
}

/**
 * Execute a command with REAL-TIME streaming output (no buffering)
 */
function executeCommandWithStreaming(
  scanId: string,
  command: string,
  args: string[],
  phaseName: string
): Promise<string> {
  // Merged logic into executeCommand for consistency
  return executeCommand(scanId, command, args, phaseName);
}

/**
 * ASSETFINDER DISCOVERY ENGINE
 */
function executeAssetfinderWithDiscovery(
  scanId: string,
  targetDomain: string
): Promise<string[]> {
  return new Promise((resolve) => {
    const discoveredSubdomains = new Set<string>();
    let lastDiscoveryTime = Date.now();
    const timeoutMs = 30000;
    let timeoutHandle: NodeJS.Timeout | null = null;
    let processKilled = false;

    emitExecLog(scanId, `[ASSETFINDER] $ /home/runner/workspace/bin/assetfinder -subs-only ${targetDomain}`);
    emitStdoutLog(scanId, `[DEBUG] Assetfinder starting subdomain discovery on ${targetDomain}...`, { agentLabel: "ASSETFINDER", type: "info" });

    const child = spawn("/home/runner/workspace/bin/assetfinder", ["-subs-only", targetDomain], { 
      shell: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, PATH: `${process.env.PATH}:/home/runner/workspace/bin` }
    });

    const setIdleTimeout = () => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      timeoutHandle = setTimeout(() => {
        if (!processKilled && discoveredSubdomains.size > 0) {
          emitStdoutLog(scanId, `[DEBUG] Assetfinder idle for 30s. Killing to proceed...`, { agentLabel: "ASSETFINDER", type: "warning" });
          processKilled = true;
          child.kill("SIGTERM");
        }
      }, timeoutMs);
    };

    setIdleTimeout();

    child.stdout?.on("data", (data: Buffer) => {
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim() && !l.startsWith("[") && !l.startsWith("{"));
      lines.forEach(line => {
        const subdomain = line.trim();
        if (subdomain && !discoveredSubdomains.has(subdomain)) {
          discoveredSubdomains.add(subdomain);
          lastDiscoveryTime = Date.now();
          emitStdoutLog(scanId, `🔍 [DISCOVERY] Found: ${subdomain}`, { agentLabel: "ASSETFINDER", type: "success" });
          setIdleTimeout();
        }
      });
    });

    child.on("close", (code: number) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      resolve(Array.from(discoveredSubdomains));
    });

    child.on("error", (err: Error) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      resolve(Array.from(discoveredSubdomains));
    });
  });
}

/**
 * PHASE 1: Subdomain Discovery
 */
async function phase1SubdomainDiscovery(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-1: RECONNAISSANCE");
  logPhaseInfo("PHASE-1", "Starting global subdomain discovery...", icons.discovery);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-1" });

  try {
    let targetDomain = scanData.target.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    
    // DYNAMIC RESOURCE ALLOCATION: Skip heavy reconnaissance for single URLs
    const isSingleUrl = scanData.target.includes("testphp") || scanData.target.includes("localhost") || !scanData.target.includes(".");
    if (isSingleUrl) {
      emitStdoutLog(scanData.scanId, `[SYSTEM] ⚡ Single URL detected. Skipping Phase 1 Recon, jumping to Phase 2 in 5s...`, { agentLabel: "PHASE-1", type: "info" });
      await new Promise(resolve => setTimeout(resolve, 5000));
      scanData.subdomains = [targetDomain];
      return;
    }

    let discoveredSubs = await executeAssetfinderWithDiscovery(scanData.scanId, targetDomain);

    if (discoveredSubs.length === 0) {
      discoveredSubs = [targetDomain];
    }

    logDiscovery("PHASE-1", discoveredSubs.length, "subdomains");

    if (discoveredSubs.length > 0) {
      await updateScanProgress(scanData.scanId, 10, "httpx");
      const httpxInputFile = `${tmpdir()}/httpx-input-${scanData.scanId}.txt`;
      writeFileSync(httpxInputFile, discoveredSubs.map(sub => sub.startsWith("http") ? sub : `https://${sub}`).join("\n"));
      
      const httpxOutput = await executeCommandWithStreaming(
        scanData.scanId,
        "/home/runner/workspace/bin/httpx",
        ["-l", httpxInputFile, "-status-code", "-follow-redirects", "-t", "10", "-rate-limit", "10", "-timeout", "5"],
        "HTTPX"
      );

      const liveSubdomains = httpxOutput && httpxOutput.trim() 
        ? httpxOutput.split("\n").filter(line => line.trim().includes("http")).map(line => {
            try { return new URL(line.trim()).hostname; } catch { return line.trim().split(" ")[0]; }
          })
        : discoveredSubs;
      
      scanData.subdomains = Array.from(new Set(liveSubdomains));
      try { unlinkSync(httpxInputFile); } catch {}
    }
  } catch (error) {
    throw error;
  }
}

/**
 * PHASE 2: Global URL Crawling
 */
async function phase2GlobalUrlCrawling(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-2: ATTACK SURFACE MAPPING");
  logPhaseInfo("PHASE-2", `Crawling ${scanData.subdomains.length} subdomains...`, icons.speed);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-2" });
  await updateScanProgress(scanData.scanId, 20, "katana");

  try {
    const subdomainsFile = `${tmpdir()}/subdomains-${scanData.scanId}.txt`;
    writeFileSync(subdomainsFile, scanData.subdomains.map(sub => sub.startsWith("http") ? sub : `https://${sub}`).join("\n"));

    logToolExecution("PHASE-2", "katana", ["-list", subdomainsFile, "-c", "3", "-d", "3", "-ps"]);
    let katanaOutput = "";
    try {
      katanaOutput = await executeCommand(
        scanData.scanId,
        "/home/runner/workspace/bin/katana",
        ["-list", subdomainsFile, "-c", "3", "-d", "3", "-ps", "-jc", "-delay", "5", "-system-chromium", "--no-sandbox"],
        "KATANA-HEADLESS"
      );
    } catch (e) {
      emitStdoutLog(scanData.scanId, `[PHASE 2] Katana headless failed, falling back to standard...`, { agentLabel: "KATANA", type: "warning" });
      katanaOutput = await executeCommand(
        scanData.scanId,
        "/home/runner/workspace/bin/katana",
        ["-list", subdomainsFile, "-c", "3", "-d", "3", "-ps", "-jc", "-delay", "5"],
        "KATANA-STANDARD"
      );
    }

    let allUrls = katanaOutput.split("\n").filter(line => line.trim().startsWith("http")).slice(0, 500);

    if (allUrls.length === 0) {
      const gauOutput = await executeCommand(scanData.scanId, "/home/runner/workspace/bin/gau", ["--subs", scanData.target.replace(/^https?:\/\//i, '').replace(/\/+$/, '')], "GAU-PASSIVE");
      allUrls = gauOutput.split("\n").filter(line => line.trim().startsWith("http")).slice(0, 500);
    }

    scanData.urls = allUrls;
    try { unlinkSync(subdomainsFile); } catch {}
  } catch (error) {
    throw error;
  }
}

/**
 * PHASE 3: Global Vuln Scanning
 */
async function phase3GlobalVulnScanning(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-3: VULNERABILITY ANALYSIS");
  logPhaseInfo("PHASE-3", "Starting global CVE vulnerability scan...", icons.shield);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-3" });
  await updateScanProgress(scanData.scanId, 50, "nuclei");

  try {
    const subdomainsFile = `${tmpdir()}/subdomains-nuclei-${scanData.scanId}.txt`;
    writeFileSync(subdomainsFile, scanData.subdomains.map(sub => sub.startsWith("http") ? sub : `https://${sub}`).join("\n"));

    // HARDCODED TURBO FLAGS - USER SPECIFIED EXACT SEQUENCE (SILENT ONLY, NO -v)
    const nucleiArgs = [
      "-u", scanData.target,
      "-c", "100",
      "-rate-limit", "200",
      "-bs", "50",
      "-timeout", "3",
      "-ni",
      "-stats",
      "-stats-interval", "10",
      "-silent"
    ];
    
    const nucleiCmdDebug = `/home/runner/workspace/bin/nuclei ${nucleiArgs.join(" ")}`;
    console.log("[FINAL_NUCLEI_TURBO] EXECUTING EXACT COMMAND:");
    console.log(nucleiCmdDebug);
    console.log("[FINAL_NUCLEI_TURBO] CRITICAL_CHECK: -ni flag is PRESENT (No Interactsh)");
    console.log("[FINAL_NUCLEI_TURBO] CRITICAL_CHECK: shell will be FALSE");
    
    emitStdoutLog(scanData.scanId, `[NUCLEI-TURBO] Command: ${nucleiCmdDebug}`, { agentLabel: "NUCLEI-TURBO" });
    
    logToolExecution("PHASE-3", "nuclei", nucleiArgs);
    await executeCommandWithStreaming(
      scanData.scanId,
      "/home/runner/workspace/bin/nuclei",
      nucleiArgs,
      "NUCLEI-TURBO"
    );
    try { unlinkSync(subdomainsFile); } catch {}
  } catch (error) {
    throw error;
  }
}

/**
 * PHASE 4: Global XSS Testing
 */
async function phase4GlobalXssTesting(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-4: TARGETED EXPLOITATION");
  logPhaseInfo("PHASE-4", "Starting global XSS injection testing...", icons.injection);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-4" });
  await updateScanProgress(scanData.scanId, 80, "dalfox");

  if (scanData.urls.length > 0) {
    const urlsFile = `${tmpdir()}/xss-urls-${scanData.scanId}.txt`;
    writeFileSync(urlsFile, scanData.urls.join("\n"));
    
    // OPTIMIZED DALFOX: --worker 50, --timeout 3, --skip-bypassing
    const dalfoxArgs = ["file", urlsFile, "--mass", "--silence-force", "--worker", "50", "--timeout", "3", "--skip-bypassing"];
    logToolExecution("PHASE-4", "dalfox", dalfoxArgs);
    await executeCommandWithStreaming(
      scanData.scanId,
      "/home/runner/workspace/bin/dalfox",
      dalfoxArgs,
      "DALFOX-GLOBAL"
    );
    try { unlinkSync(urlsFile); } catch {}
  } else {
    emitStdoutLog(scanData.scanId, "[WARNING] No URLs collected for XSS testing, skipping PHASE-4", { agentLabel: "PHASE-4", type: "warning" });
  }
}

/**
 * PHASE 5: SQL Injection Testing
 */
async function phase5SqlInjectionTesting(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-5: SQL INJECTION ANALYSIS");
  logPhaseInfo("PHASE-5", "Starting SQL injection testing...", icons.injection);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-5" });
  await updateScanProgress(scanData.scanId, 90, "sqlmap");

  if (scanData.urls.length === 0) {
    emitStdoutLog(scanData.scanId, "[WARNING] No URLs collected for SQLMap, skipping PHASE-5", { agentLabel: "PHASE-5", type: "warning" });
    return;
  }

  // Filter URLs with parameters (containing ?)
  const parameterizedUrls = scanData.urls.filter(url => url.includes("?"));
  
  if (parameterizedUrls.length === 0) {
    emitStdoutLog(scanData.scanId, "[INFO] No parameterized URLs found. SQLMap requires parameters to test.", { agentLabel: "PHASE-5", type: "info" });
    return;
  }

  const urlsFile = `${tmpdir()}/sqlmap-urls-${scanData.scanId}.txt`;
  writeFileSync(urlsFile, parameterizedUrls.join("\n"));
  
  // Use -m flag instead of -l to avoid STDIN issues with multiple URLs
  const sqlmapArgs = ["--batch", "--flush-session", "--random-agent", "--level", "3", "--risk", "2", "-m", urlsFile, "--threads=10", "--timeout=5"];
  logToolExecution("PHASE-5", "sqlmap", sqlmapArgs);
  await executeCommandWithStreaming(
    scanData.scanId,
    "sqlmap",
    sqlmapArgs,
    "SQLMAP-GLOBAL"
  );
  try { unlinkSync(urlsFile); } catch {}
}

/**
 * PHASE 6: Command Injection Testing
 */
async function phase6CommandInjectionTesting(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-6: COMMAND INJECTION ANALYSIS");
  logPhaseInfo("PHASE-6", "Starting command injection testing...", icons.injection);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-6" });
  await updateScanProgress(scanData.scanId, 95, "commix");

  if (scanData.urls.length === 0) {
    emitStdoutLog(scanData.scanId, "[WARNING] No URLs collected for Commix, skipping PHASE-6", { agentLabel: "PHASE-6", type: "warning" });
    return;
  }

  const urlsFile = `${tmpdir()}/commix-urls-${scanData.scanId}.txt`;
  writeFileSync(urlsFile, scanData.urls.join("\n"));
  
  // Check if commix is available as a command or script
  let commixCmd = "commix";
  let commixArgs = ["-l", urlsFile, "--batch"];
  
  try {
    // Try to locate commix.py if binary fails
    const commixPath = "/home/runner/workspace/commix/commix.py";
    if (existsSync(commixPath)) {
      commixCmd = "python3";
      commixArgs = [commixPath, "-l", urlsFile, "--batch"];
    }
  } catch (e) {}

  logToolExecution("PHASE-6", commixCmd, commixArgs);
  await executeCommandWithStreaming(
    scanData.scanId,
    commixCmd,
    commixArgs,
    "COMMIX-GLOBAL"
  );
  try { unlinkSync(urlsFile); } catch {}
}

export async function runSequentialScan(scanId: string, target: string) {
  cleanupHangingProcesses();
  
  const scanData: ScanData = {
    target,
    scanId,
    subdomains: [],
    urls: [],
    vulnerabilities: [],
    errors: [],
    subdomainMetadata: new Map()
  };

  try {
    await phase1SubdomainDiscovery(scanData);
    await phase2GlobalUrlCrawling(scanData);
    await phase3GlobalVulnScanning(scanData);
    
    // Start XSS and SQLi in parallel for speed
    emitStdoutLog(scanData.scanId, "[SYSTEM] ⚡ Parallel Execution: Launching Phase 4 (XSS) and Phase 5 (SQLi) simultaneously", { agentLabel: "SYSTEM", type: "info" });
    await Promise.all([
      phase4GlobalXssTesting(scanData),
      phase5SqlInjectionTesting(scanData)
    ]);
    
    await phase6CommandInjectionTesting(scanData);

    await db.update(scans).set({ status: "complete", progress: 100, completedAt: new Date() }).where(eq(scans.id, scanId));
    emitStdoutLog(scanId, "[\u2713] SCAN ARCHIVE FINALIZED", { agentLabel: "SYSTEM", type: "success" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Scan failed";
    await db.update(scans).set({ status: "failed", error: errorMsg, completedAt: new Date() }).where(eq(scans.id, scanId));
    emitErrorLog(scanId, `Scan failed: ${errorMsg}`);
  }
}
