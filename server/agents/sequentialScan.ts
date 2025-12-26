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

    const child = spawn(command, args, { 
      shell: true,
      detached: false,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, PATH: `${process.env.PATH}:/home/runner/workspace/bin` }
    });

    activeProcesses.set(scanId, child);

    let lastOutputTime = Date.now();
    const silenceTimeout = 60000; // 60 seconds
    const silenceCheck = setInterval(() => {
      if (child.killed) {
        clearInterval(silenceCheck);
        return;
      }
      if (Date.now() - lastOutputTime > silenceTimeout) {
        emitStdoutLog(scanId, `[SYSTEM] Tool silent for >60s. Auto-forwarding results to prevent hang.`, { agentLabel: phaseName, type: "warning" });
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
      });
    });

    child.stderr?.on("data", (data: Buffer) => {
      lastOutputTime = Date.now();
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        emitStdoutLog(scanId, `[${phaseName}] [ERROR] ${line}`, { agentLabel: phaseName, type: "error" });
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
  return new Promise((resolve) => {
    const output: string[] = [];
    const errorOutput: string[] = [];

    emitExecLog(scanId, `[${phaseName}] $ ${command} ${args.join(" ")}`);

    const child = spawn(command, args, { 
      shell: true,
      detached: false,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, PATH: `${process.env.PATH}:/home/runner/workspace/bin` }
    });

    activeProcesses.set(scanId, child);

    let lastOutputTime = Date.now();
    const silenceTimeout = 60000; // 60 seconds
    const silenceCheck = setInterval(() => {
      if (child.killed) {
        clearInterval(silenceCheck);
        return;
      }
      if (Date.now() - lastOutputTime > silenceTimeout) {
        emitStdoutLog(scanId, `[SYSTEM] Tool silent for >60s. Auto-forwarding results to prevent hang.`, { agentLabel: phaseName, type: "warning" });
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
        
        if (line.includes("[INF]")) {
          emitStdoutLog(scanId, line, { agentLabel: phaseName, type: "info" });
        } else if (line.includes("[WRN]")) {
          emitStdoutLog(scanId, line, { agentLabel: phaseName, type: "warning" });
        } else if (line.match(/\[.*\]\s\[.*\]\s\[(critical|high|medium|low|info)\]/i)) {
          emitStdoutLog(scanId, `🚨 **[CRITICAL HIT]** ${line}`, { agentLabel: phaseName, type: "finding" });
          const urlMatch = line.match(/https?:\/\/[^\s]+/);
          if (urlMatch) {
            const vulnUrl = urlMatch[0];
            captureScreenshot(scanId, vulnUrl, `nuclei-hit-${Date.now()}`);
          }
        } else {
          if (!line.includes("[INF]") && !line.includes("[WRN]") && (line.includes("http://") || line.includes("https://"))) {
            emitStdoutLog(scanId, `[${phaseName}] ✓ ${line}`, { agentLabel: phaseName, type: "success" });
          } else {
            emitStdoutLog(scanId, line, { agentLabel: phaseName, type: "stdout" });
          }
        }
      });
    });

    child.stderr?.on("data", (data: Buffer) => {
      lastOutputTime = Date.now();
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        if (line.includes("[INF]")) {
          emitStdoutLog(scanId, line, { agentLabel: phaseName, type: "info" });
        } else if (line.includes("[WRN]")) {
          emitStdoutLog(scanId, line, { agentLabel: phaseName, type: "warning" });
        } else {
          emitStdoutLog(scanId, `[${phaseName}] [ERROR] ${line}`, { agentLabel: phaseName, type: "error" });
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

    logToolExecution("PHASE-3", "nuclei", ["-list", subdomainsFile, "-header", "User-Agent: googlebot"]);
    await executeCommandWithStreaming(
      scanData.scanId,
      "/home/runner/workspace/bin/nuclei",
      ["-list", subdomainsFile, "-header", "'User-Agent: googlebot'", "-severity", "critical,high", "-rate-limit", "10", "-timeout", "10", "-c", "3", "-include-tags", "cve2020,cve2021,cve2022,cve2023,cve2024,cve2025"],
      "NUCLEI-GLOBAL"
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
    
    logToolExecution("PHASE-4", "dalfox", ["file", urlsFile, "--mass"]);
    await executeCommandWithStreaming(
      scanData.scanId,
      "/home/runner/workspace/bin/dalfox",
      ["file", urlsFile, "--mass", "--silence-force"],
      "DALFOX-GLOBAL"
    );
    try { unlinkSync(urlsFile); } catch {}
  }
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
    await phase4GlobalXssTesting(scanData);

    await db.update(scans).set({ status: "complete", progress: 100, completedAt: new Date() }).where(eq(scans.id, scanId));
    emitStdoutLog(scanId, "[\u2713] SCAN ARCHIVE FINALIZED", { agentLabel: "SYSTEM", type: "success" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Scan failed";
    await db.update(scans).set({ status: "failed", error: errorMsg, completedAt: new Date() }).where(eq(scans.id, scanId));
    emitErrorLog(scanId, `Scan failed: ${errorMsg}`);
  }
}
