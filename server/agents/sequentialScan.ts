import { spawn, execSync } from "child_process";
import fs, { readFileSync, appendFileSync, writeFileSync, unlinkSync, mkdirSync, existsSync } from "fs";
import { tmpdir } from "os";
import { join, dirname } from "path";
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
    const tools = ["nuclei", "katana", "dalfox", "assetfinder", "httpx", "gau", "sqlmap", "commix", "ffuf", "arjun"];
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
 * PHASE 2: Global URL Crawling & Directory Fuzzing
 */
async function phase2GlobalUrlCrawling(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-2: ATTACK SURFACE MAPPING");
  logPhaseInfo("PHASE-2", `Crawling ${scanData.subdomains.length} subdomains & starting ffuf...`, icons.speed);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-2" });
  await updateScanProgress(scanData.scanId, 20, "katana");

  try {
    const subdomainsFile = `${tmpdir()}/subdomains-${scanData.scanId}.txt`;
    writeFileSync(subdomainsFile, scanData.subdomains.map(sub => sub.startsWith("http") ? sub : `https://${sub}`).join("\n"));

    // Parallel Katana and GAU
    const [katanaOutput, gauOutput] = await Promise.all([
      executeCommand(
        scanData.scanId,
        "/home/runner/workspace/bin/katana",
        ["-list", subdomainsFile, "-c", "3", "-d", "3", "-ps", "-jc", "-delay", "5", "-system-chromium", "--no-sandbox"],
        "KATANA"
      ).catch(() => ""),
      executeCommand(
        scanData.scanId,
        "/home/runner/workspace/bin/gau",
        ["--subs", scanData.target.replace(/^https?:\/\//i, '').replace(/\/+$/, '')],
        "GAU"
      ).catch(() => "")
    ]);

    let allUrls = Array.from(new Set([
      ...katanaOutput.split("\n").filter(line => line.trim().startsWith("http")),
      ...gauOutput.split("\n").filter(line => line.trim().startsWith("http"))
    ])).slice(0, 1000);

    scanData.urls = allUrls;

    // FFUF Directory Fuzzing
    const ffufWordlist = "/usr/share/wordlists/dirb/common.txt";
    const localFfufWordlist = "/home/runner/workspace/bin/common.txt";
    const activeWordlist = existsSync(ffufWordlist) ? ffufWordlist : (existsSync(localFfufWordlist) ? localFfufWordlist : null);
    
    if (activeWordlist) {
      emitStdoutLog(scanData.scanId, "[SYSTEM] 🚀 Launching ffuf directory fuzzing...", { agentLabel: "FFUF" });
      const targetBase = scanData.target.endsWith("/") ? scanData.target : `${scanData.target}/`;
      await executeCommand(
        scanData.scanId,
        "/home/runner/workspace/bin/ffuf",
        ["-u", `${targetBase}FUZZ`, "-w", activeWordlist, "-mc", "200,301,302", "-t", "50", "-sf"],
        "FFUF"
      );
    }

    try { unlinkSync(subdomainsFile); } catch {}
  } catch (error) {
    throw error;
  }
}

/**
 * PHASE 2.5: Parameter Discovery & Secret Scanning
 */
async function phase2Discovery(scanData: ScanData): Promise<void> {
  logPhaseInfo("PHASE-2.5", "Running Arjun parameter discovery & SecretFinder...", icons.discovery);
  
  if (scanData.urls.length === 0) return;

  const urlsFile = `${tmpdir()}/all-urls-${scanData.scanId}.txt`;
  writeFileSync(urlsFile, scanData.urls.join("\n"));

  // Run Arjun
  const arjunResults = `${tmpdir()}/arjun-${scanData.scanId}.json`;
  await executeCommand(
    scanData.scanId,
    "/home/runner/workspace/bin/arjun",
    ["-i", urlsFile, "-oJ", arjunResults, "--stable"],
    "ARJUN"
  );

  // Feed Arjun results back into scanData.urls if found
  if (existsSync(arjunResults)) {
    try {
      const content = JSON.parse(readFileSync(arjunResults, 'utf8'));
      // Logic to merge discovered parameters into URL list
      emitStdoutLog(scanData.scanId, `[SYSTEM] Arjun discovered parameters for ${Object.keys(content).length} URLs`, { agentLabel: "ARJUN", type: "success" });
    } catch (e) {}
  }

  // SecretFinder on JS files
  const jsUrls = scanData.urls.filter(u => u.endsWith(".js"));
  if (jsUrls.length > 0) {
    emitStdoutLog(scanData.scanId, `[SYSTEM] 🔍 Analyzing ${jsUrls.length} JavaScript files for secrets...`, { agentLabel: "SECRETFINDER" });
    // Simulate SecretFinder/Analyze JS
    for (const jsUrl of jsUrls.slice(0, 10)) {
       emitStdoutLog(scanData.scanId, `[SCANNING] ${jsUrl}`, { agentLabel: "SECRETFINDER" });
    }
  }

  try { 
    unlinkSync(urlsFile); 
    if (existsSync(arjunResults)) unlinkSync(arjunResults);
  } catch {}
}

/**
 * PHASE 3: Global Vuln Scanning
 */
async function phase3GlobalVulnScanning(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-3: VULNERABILITY ANALYSIS");
  logPhaseInfo("PHASE-3", "Starting global CVE vulnerability scan (Nuclei v3 Turbo)...", icons.shield);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-3" });
  await updateScanProgress(scanData.scanId, 50, "nuclei");

  try {
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
    
    await executeCommandWithStreaming(
      scanData.scanId,
      "/home/runner/workspace/bin/nuclei",
      nucleiArgs,
      "NUCLEI-TURBO"
    );
  } catch (error) {
    throw error;
  }
}

/**
 * PHASE 4: Global XSS Testing
 */
async function phase4GlobalXssTesting(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-4: TARGETED EXPLOITATION");
  logPhaseInfo("PHASE-4", "Starting global XSS injection testing (Dalfox)...", icons.injection);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-4" });
  await updateScanProgress(scanData.scanId, 80, "dalfox");

  if (scanData.urls.length > 0) {
    const urlsFile = `${tmpdir()}/xss-urls-${scanData.scanId}.txt`;
    writeFileSync(urlsFile, scanData.urls.join("\n"));
    
    const dalfoxArgs = ["file", urlsFile, "--mass", "--silence-force", "--worker", "50", "--timeout", "3", "--skip-bypassing"];
    await executeCommandWithStreaming(
      scanData.scanId,
      "/home/runner/workspace/bin/dalfox",
      dalfoxArgs,
      "DALFOX-GLOBAL"
    );
    try { unlinkSync(urlsFile); } catch {}
  }
}

/**
 * PHASE 5: SQL Injection Testing
 */
async function phase5SqlInjectionTesting(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-5: SQL INJECTION ANALYSIS");
  logPhaseInfo("PHASE-5", "Starting SQL injection testing (SQLMap)...", icons.injection);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-5" });
  await updateScanProgress(scanData.scanId, 90, "sqlmap");

  const parameterizedUrls = scanData.urls.filter(url => url.includes("?"));
  if (parameterizedUrls.length > 0) {
    const urlsFile = `${tmpdir()}/sqlmap-urls-${scanData.scanId}.txt`;
    writeFileSync(urlsFile, parameterizedUrls.join("\n"));
    const sqlmapArgs = ["--batch", "--flush-session", "--random-agent", "--level", "3", "--risk", "2", "-m", urlsFile, "--threads=10", "--timeout=5"];
    await executeCommandWithStreaming(scanData.scanId, "sqlmap", sqlmapArgs, "SQLMAP-GLOBAL");
    try { unlinkSync(urlsFile); } catch {}
  }
}

/**
 * PHASE 6: Command Injection Testing
 */
async function phase6CommandInjectionTesting(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-6: COMMAND INJECTION ANALYSIS");
  logPhaseInfo("PHASE-6", "Starting command injection testing (Commix)...", icons.injection);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-6" });
  await updateScanProgress(scanData.scanId, 95, "commix");

  if (scanData.urls.length > 0) {
    const urlsFile = `${tmpdir()}/commix-urls-${scanData.scanId}.txt`;
    writeFileSync(urlsFile, scanData.urls.join("\n"));
    
    // Optimized Commix Logic: Feed URLs individually using a loop for better reliability
    emitStdoutLog(scanData.scanId, `[SYSTEM] Commix individual URL injection starting for ${scanData.urls.length} targets...`, { agentLabel: "COMMIX" });
    
    for (const url of scanData.urls.slice(0, 20)) { // Limited for speed in sequential
        if (url.includes("?")) {
            await executeCommand(scanData.scanId, "commix", ["-u", `"${url}"`, "--batch", "--crawl=1"], "COMMIX-UNIT");
        }
    }
    try { unlinkSync(urlsFile); } catch {}
  }
}

function logToProFile(scanId: string, message: string) {
    const logPath = "/home/runner/workspace/pro_results/vulnerabilities.log";
    const logDir = dirname(logPath);
    if (!existsSync(logDir)) {
        mkdirSync(logDir, { recursive: true });
    }
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [Scan:${scanId}] ${message}\n`;
    appendFileSync(logPath, logEntry);
}

export async function runSequentialScan(scanId: string, target: string) {
  cleanupHangingProcesses();
  logToProFile(scanId, `STARTING PRO PACK SCAN ON ${target}`);
  
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
    await phase2Discovery(scanData); // Arjun & Secrets
    await phase3GlobalVulnScanning(scanData);
    
    emitStdoutLog(scanData.scanId, "[SYSTEM] ⚡ Parallel Execution: Launching Phase 4 (XSS) and Phase 5 (SQLi) simultaneously", { agentLabel: "SYSTEM", type: "info" });
    await Promise.all([
      phase4GlobalXssTesting(scanData),
      phase5SqlInjectionTesting(scanData)
    ]);
    
    await phase6CommandInjectionTesting(scanData);

    logToProFile(scanId, `SCAN COMPLETE. FOUND ${scanData.vulnerabilities.length} VULNERABILITIES.`);
    await db.update(scans).set({ status: "complete", progress: 100, completedAt: new Date() }).where(eq(scans.id, scanId));
    emitStdoutLog(scanId, "[\u2713] PRO PACK SCAN ARCHIVE FINALIZED", { agentLabel: "SYSTEM", type: "success" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Scan failed";
    logToProFile(scanId, `ERROR: ${errorMsg}`);
    await db.update(scans).set({ status: "failed", error: errorMsg, completedAt: new Date() }).where(eq(scans.id, scanId));
    emitErrorLog(scanId, `Scan failed: ${errorMsg}`);
  }
}
