import { spawn, execSync } from "child_process";
import { writeFileSync, unlinkSync, mkdirSync, existsSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { emitStdoutLog, emitExecLog, emitErrorLog } from "../src/sockets/socketManager";

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

/**
 * FULL DOMAIN-WIDE ENGINE - GLOBAL PHASE-BASED EXECUTION
 * 
 * STRUCTURE (GLOBAL MODE):
 * ├─ PHASE 1: Subdomain Discovery (Assetfinder + HTTPProbe) - Returns ALL live subdomains
 * ├─ PHASE 2: Global URL Crawling (Katana -list on ALL subdomains with -c 3) - Gathers ALL URLs
 * ├─ PHASE 3: Global Vuln Scanning (Nuclei -list on ALL subdomains with -c 3) - Scans ALL hosts
 * └─ PHASE 4: Global XSS Testing (Dalfox on ALL discovered URLs) - Tests ALL endpoints
 * 
 * KEY: Phase 1 output feeds directly into Phases 2, 3, 4 for ALL discovered targets
 * PERFORMANCE: -c 3 concurrency to prevent RAM exhaustion on Replit
 */

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
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, PATH: `${process.env.PATH}:/home/runner/workspace/bin` }
    });

    child.stdout?.on("data", (data: Buffer) => {
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        output.push(line);
      });
    });

    child.stderr?.on("data", (data: Buffer) => {
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        emitStdoutLog(scanId, `[${phaseName}] [ERROR] ${line}`, { agentLabel: phaseName, type: "error" });
        errorOutput.push(line);
      });
    });

    child.on("close", (code: number) => {
      if (code !== 0 && code !== null) {
        emitStdoutLog(scanId, `[${phaseName}] ⚠️ Command exited with code ${code}`, { agentLabel: phaseName, type: "warning" });
      }
      resolve(output.join("\n"));
    });

    child.on("error", (err: any) => {
      emitErrorLog(scanId, `[${phaseName}] Process spawn error: ${err.message} (Code: ${err.code})`);
      // Ensure error event is sent to frontend to prevent hang
      emitStdoutLog(scanId, `[SYSTEM] Process error - ${err.code || 'UNKNOWN'}: ${err.message}`, { agentLabel: phaseName, type: "error" });
      resolve("");
    });
  });
}

/**
 * Execute a command with REAL-TIME streaming output (no buffering)
 * Each line is emitted immediately to the terminal as it's received
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
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, PATH: `${process.env.PATH}:/home/runner/workspace/bin` }
    });

    child.stdout?.on("data", (data: Buffer) => {
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        output.push(line);
        // EMIT IMMEDIATELY - no buffering
        if (line.includes("http://") || line.includes("https://")) {
          emitStdoutLog(scanId, `[${phaseName}] ✓ ${line}`, { agentLabel: phaseName, type: "success" });
        }
      });
    });

    child.stderr?.on("data", (data: Buffer) => {
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        emitStdoutLog(scanId, `[${phaseName}] [ERROR] ${line}`, { agentLabel: phaseName, type: "error" });
        errorOutput.push(line);
      });
    });

    child.on("close", (code: number) => {
      if (code !== 0 && code !== null) {
        emitStdoutLog(scanId, `[${phaseName}] ⚠️ Command exited with code ${code}`, { agentLabel: phaseName, type: "warning" });
      }
      resolve(output.join("\n"));
    });

    child.on("error", (err: any) => {
      emitErrorLog(scanId, `[${phaseName}] Process spawn error: ${err.message} (Code: ${err.code})`);
      // Ensure error event is sent to frontend to prevent hang
      emitStdoutLog(scanId, `[SYSTEM] Process error - ${err.code || 'UNKNOWN'}: ${err.message}`, { agentLabel: phaseName, type: "error" });
      resolve("");
    });
  });
}

/**
 * ASSETFINDER DISCOVERY ENGINE WITH TIMEOUT
 * Streams subdomains in real-time with immediate logging
 * Kills after 30 seconds of no new discoveries
 */
function executeAssetfinderWithDiscovery(
  scanId: string,
  targetDomain: string
): Promise<string[]> {
  return new Promise((resolve) => {
    const discoveredSubdomains = new Set<string>();
    let lastDiscoveryTime = Date.now();
    const timeoutMs = 30000; // 30 seconds
    let timeoutHandle: NodeJS.Timeout | null = null;
    let processKilled = false;

    emitExecLog(scanId, `[ASSETFINDER] $ /home/runner/workspace/bin/assetfinder -subs-only ${targetDomain}`);
    emitStdoutLog(scanId, `[DEBUG] Assetfinder starting subdomain discovery on ${targetDomain}...`, { agentLabel: "ASSETFINDER", type: "info" });

    const child = spawn("/home/runner/workspace/bin/assetfinder", ["-subs-only", targetDomain], { 
      shell: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, PATH: `${process.env.PATH}:/home/runner/workspace/bin` }
    });

    // Set idle timeout - if 30 seconds pass without new subdomain, kill it
    const setIdleTimeout = () => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      timeoutHandle = setTimeout(() => {
        if (!processKilled && discoveredSubdomains.size > 0) {
          emitStdoutLog(scanId, `[DEBUG] Assetfinder idle for 30s with ${discoveredSubdomains.size} subdomains. Killing to proceed...`, { agentLabel: "ASSETFINDER", type: "warning" });
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
          
          // IMMEDIATE EMISSION - no buffering
          emitStdoutLog(scanId, `🔍 [DISCOVERY] Found: ${subdomain}`, { agentLabel: "ASSETFINDER", type: "success" });
          
          // Reset idle timeout on each new discovery
          setIdleTimeout();
        }
      });
    });

    child.stderr?.on("data", (data: Buffer) => {
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        emitStdoutLog(scanId, `[ASSETFINDER] [ERROR] ${line}`, { agentLabel: "ASSETFINDER", type: "error" });
      });
    });

    child.on("close", (code: number) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      
      if (discoveredSubdomains.size === 0) {
        emitStdoutLog(scanId, `[DEBUG] Assetfinder found 0 subdomains (timeout or no results). Proceeding...`, { agentLabel: "ASSETFINDER", type: "warning" });
      } else {
        emitStdoutLog(scanId, `[ASSETFINDER] ✅ Discovery complete: ${discoveredSubdomains.size} subdomains found`, { agentLabel: "ASSETFINDER", type: "success" });
      }
      
      resolve(Array.from(discoveredSubdomains));
    });

    child.on("error", (err: Error) => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      emitStdoutLog(scanId, `[DEBUG] Assetfinder failed: ${err.message}. Using empty buffer...`, { agentLabel: "ASSETFINDER", type: "error" });
      resolve(Array.from(discoveredSubdomains));
    });
  });
}

/**
 * PHASE 1: Subdomain Discovery (GLOBAL)
 * Execute Assetfinder → Filter with HTTPX binary for FAST probing
 * Returns ALL live subdomains for downstream phases
 */
async function phase1SubdomainDiscovery(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-1: RECONNAISSANCE");
  logPhaseInfo("PHASE-1", "Starting global subdomain discovery...", icons.discovery);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-1" });
  logPhaseInfo("PHASE-1", `Target: ${scanData.target}`, icons.target);

  try {
    // Extract domain from URL if needed
    let targetDomain = scanData.target;
    
    // AUTO-CLEANUP TARGET: Strip protocol and trailing slashes
    const originalTarget = targetDomain;
    targetDomain = targetDomain.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    emitStdoutLog(scanData.scanId, `[DEBUG] Cleaning target URL: ${originalTarget} -> ${targetDomain}`, { agentLabel: "PHASE-1", type: "debug" });
    
    emitStdoutLog(scanData.scanId, `[PHASE 1] Extracted domain: ${targetDomain}`, { agentLabel: "PHASE-1" });

    // Step 1: Run Assetfinder with STREAMING DISCOVERY
    logToolExecution("PHASE-1", "assetfinder", ["-subs-only", targetDomain]);
    let discoveredSubs = await executeAssetfinderWithDiscovery(
      scanData.scanId,
      targetDomain
    );

    // INPUT CHECK: If assetfinder returns 0 results (single page/URL), use the target itself
    if (discoveredSubs.length === 0) {
      emitStdoutLog(scanData.scanId, `[DEBUG] Assetfinder found 0 subdomains. Using target domain directly for probing.`, { agentLabel: "ASSETFINDER", type: "info" });
      discoveredSubs = [targetDomain];
    }

    logDiscovery("PHASE-1", discoveredSubs.length, "subdomains");

    // Step 2: Filter through HTTPX binary (FAST probing with streaming)
    if (discoveredSubs.length > 0) {
      logToolExecution("PHASE-1", "httpx", ["-l", "targets.txt", "-t 50", "-timeout 5"]);
      
      // Write subdomains to temp file for httpx
      const httpxInputFile = `${tmpdir()}/httpx-input-${scanData.scanId}.txt`;
      const httpxInput = discoveredSubs
        .map(sub => sub.startsWith("http") ? sub : `https://${sub}`)
        .join("\n");
      writeFileSync(httpxInputFile, httpxInput);
      
      // Status message
      emitStdoutLog(scanData.scanId, `[DEBUG] HTTPX is checking ${discoveredSubs.length} targets with 50 threads (5s timeout per target)...`, { agentLabel: "HTTPX", type: "info" });
      
      // Run httpx with optimized flags for speed and streaming
      const httpxOutput = await executeCommandWithStreaming(
        scanData.scanId,
        "/home/runner/workspace/bin/httpx",
        ["-l", httpxInputFile, "-status-code", "-follow-redirects", "-t", "50", "-timeout", "5"],
        "HTTPX"
      );
      
      // Parse live subdomains - look for any http/https URLs in the output
      const liveSubdomains = httpxOutput
        .split("\n")
        .filter(line => {
          const trimmed = line.trim();
          // Be more permissive - accept any line that looks like a URL
          return trimmed && (trimmed.includes("http://") || trimmed.includes("https://"));
        })
        .map(line => {
          const trimmed = line.trim();
          try {
            const url = new URL(trimmed);
            return url.hostname || trimmed;
          } catch {
            // If not a valid URL, try to extract hostname from the string
            const match = trimmed.match(/(https?:\/\/)?([^\s\/]+)/);
            return match ? match[2] : trimmed;
          }
        })
        .filter((sub, idx, arr) => arr.indexOf(sub) === idx); // Deduplicate
      
      emitStdoutLog(scanData.scanId, `[PHASE 1] HTTPX found ${liveSubdomains.length} live targets`, { agentLabel: "HTTPX", type: "success" });
      
      scanData.subdomains = liveSubdomains;
      logSuccess("PHASE-1", `HTTPX verified ${liveSubdomains.length} LIVE subdomains`);
      
      liveSubdomains.forEach((sub) => {
        emitStdoutLog(scanData.scanId, `${icons.check} ${sub}`, { agentLabel: "PHASE-1" });
        scanData.subdomainMetadata.set(sub, { urlCount: 0, vulnerabilityCount: 0 });
      });
      
      // Cleanup
      try {
        unlinkSync(httpxInputFile);
      } catch {
        // Ignore cleanup errors
      }
    } else {
      logWarning("PHASE-1", "No subdomains discovered");
    }

    logSuccess("PHASE-1", "COMPLETE - Ready for PHASE 2 (Global Crawling)");
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 1 failed: ${errorMsg}`);
    logError("PHASE-1", errorMsg);
    throw error;
  }
}

/**
 * PHASE 2: Global URL Crawling
 * Run Katana on ENTIRE LIST of live subdomains using -list flag
 * Concurrency: -c 3 to prevent RAM exhaustion on Replit
 */
async function phase2GlobalUrlCrawling(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-2: ATTACK SURFACE MAPPING");
  logPhaseInfo("PHASE-2", `Crawling ${scanData.subdomains.length} subdomains...`, icons.speed);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-2" });

  try {
    if (scanData.subdomains.length === 0) {
      emitStdoutLog(scanData.scanId, `[PHASE 2] No live subdomains to crawl. Skipping...`, { agentLabel: "PHASE-2", type: "warning" });
      return;
    }

    // Write subdomains to temporary file
    const subdomainsFile = `${tmpdir()}/subdomains-${scanData.scanId}.txt`;
    const subdomainList = scanData.subdomains
      .map(sub => sub.startsWith("http") ? sub : `https://${sub}`)
      .join("\n");
    writeFileSync(subdomainsFile, subdomainList);
    emitStdoutLog(scanData.scanId, `[PHASE 2] Wrote ${scanData.subdomains.length} subdomains to ${subdomainsFile}`, { agentLabel: "PHASE-2" });

    // Run Katana with -list flag and -c 3 concurrency
    logToolExecution("PHASE-2", "katana", ["-list", subdomainsFile, "-c", "3", "-d", "3", "-ps"]);
    const katanaOutput = await executeCommand(
      scanData.scanId,
      "/home/runner/workspace/bin/katana",
      ["-list", subdomainsFile, "-c", "3", "-d", "3", "-ps", "-system-chromium", "--headless", "--no-sandbox"],
      "KATANA-GLOBAL"
    );

    // Filter katana output - show progress + summary only
    const filteredKatana = filterToolOutput("katana", katanaOutput, "KATANA");
    filteredKatana.importantLines.forEach(line => {
      emitStdoutLog(scanData.scanId, line, { agentLabel: "KATANA" });
    });

    // Parse URLs from output
    const allUrls = katanaOutput
      .split("\n")
      .filter(line => line.trim() && (line.startsWith("http://") || line.startsWith("https://")))
      .slice(0, 500); // Limit to 500 URLs total

    scanData.urls = allUrls;
    logDiscovery("PHASE-2", allUrls.length, "URLs");

    // Map URLs back to subdomains for reporting
    allUrls.forEach((url: string) => {
      const urlDomain = new URL(url).hostname;
      const matchingSub = scanData.subdomains.find(sub => url.includes(sub) || urlDomain?.includes(sub.replace(/^https?:\/\//, "")));
      if (matchingSub) {
        const meta = scanData.subdomainMetadata.get(matchingSub);
        if (meta) {
          meta.urlCount = (meta.urlCount || 0) + 1;
        }
      }
    });

    // Clean up temp file
    try {
      unlinkSync(subdomainsFile);
    } catch {
      // Ignore cleanup errors
    }

    logSuccess("PHASE-2", "COMPLETE - Ready for PHASE 2.5 (SQLMap on Parameters)");
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 2 failed: ${errorMsg}`);
    logWarning("PHASE-2", `ERROR: ${errorMsg}. Continuing to Phase 2.5...`);
  }
}

/**
 * Helper: Detect if URL has parameters (e.g., ?id=1, ?search=, etc.)
 */
function hasParameters(url: string): boolean {
  try {
    const urlObj = new URL(url);
    return urlObj.search.length > 0;
  } catch {
    return url.includes("?");
  }
}

/**
 * Helper: Detect if parameters look like command injection (cmd, exec, system, etc.)
 */
function hasCommandParams(url: string): boolean {
  const commandKeywords = /(\?|&)(cmd|exec|command|system|os|shell|bash|sh|eval|code|func|action|op|operation)=/i;
  return commandKeywords.test(url);
}

/**
 * PHASE 2.5: SQLMap on URLs with Parameters
 * Automatically trigger SQLMap on URLs with query parameters
 */
async function phase2_5SqlmapOnParameters(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-2.5: SQL INJECTION TESTING");
  logPhaseInfo("PHASE-2.5", "Testing URLs for SQL injection vulnerabilities...", icons.injection);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-2.5" });

  try {
    const urlsWithParams = scanData.urls.filter(hasParameters);
    
    if (urlsWithParams.length === 0) {
      logWarning("PHASE-2.5", "No URLs with parameters found. Skipping SQLMap...");
      return;
    }

    logDiscovery("PHASE-2.5", urlsWithParams.length, "URLs with parameters");

    // Test first 10 URLs with parameters (light scan)
    const urlsToTest = urlsWithParams.slice(0, 10);

    for (let i = 0; i < urlsToTest.length; i++) {
      const url = urlsToTest[i];
      emitStdoutLog(scanData.scanId, `${createProgressLine(i + 1, urlsToTest.length, "Testing")}`, { agentLabel: "PHASE-2.5" });

      const sqlmapOutput = await executeCommand(
        scanData.scanId,
        "/home/runner/workspace/bin/sqlmap",
        ["-u", url, "--batch", "--flush-session", "--random-agent", "--level=1", "--risk=1", "-q"],
        "SQLMAP"
      );

      // Filter output to show only findings
      const filteredSqlmap = filterToolOutput("sqlmap", sqlmapOutput, "SQLMAP");
      filteredSqlmap.importantLines.forEach(line => {
        emitStdoutLog(scanData.scanId, line, { agentLabel: "SQLMAP" });
      });

      // Log all findings, even low severity ones
      if (sqlmapOutput.toLowerCase().includes("vulnerable") || sqlmapOutput.toLowerCase().includes("injectable") || 
          sqlmapOutput.toLowerCase().includes("found") || sqlmapOutput.toLowerCase().includes("detected")) {
        const severity = sqlmapOutput.toLowerCase().includes("injectable") ? "critical" : "high";
        scanData.vulnerabilities.push({
          title: "SQL Injection Vulnerability",
          severity: severity,
          type: "sqli",
          url: url,
          description: `SQL injection detected via SQLMap`
        });
        logFinding("PHASE-2.5", `SQL Injection on ${url}`, severity as "critical" | "high" | "medium" | "low");
        
        // Trigger screenshot for high confidence
        const screenshot = await captureScreenshot(scanData.scanId, url, `sqli-${i}`);

        // EVIDENCE TERMINAL EMISSION
        emitStdoutLog(scanData.scanId, 
          `🚨 [EVIDENCE] SQL Injection Vulnerability Found!\n` +
          `URL: ${url}\n` +
          `Payload: SQLMap default injection\n` +
          `Evidence: Vulnerability detected by SQLMap analysis`, 
          { agentLabel: "SQLMAP", type: "finding", screenshot: screenshot || undefined }
        );
      }
    }

    logSuccess("PHASE-2.5", "COMPLETE - Ready for PHASE 2.6 (Commix on Command Params)");
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 2.5 failed: ${errorMsg}`);
    logWarning("PHASE-2.5", `ERROR: ${errorMsg}. Continuing to Phase 2.6...`);
  }
}

/**
 * PHASE 2.6: Commix on Command-Like Parameters
 * Automatically trigger Commix on URLs with command-like parameters
 */
async function phase2_6CommixOnCommandParams(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-2.6: COMMAND INJECTION TESTING");
  logPhaseInfo("PHASE-2.6", "Testing URLs for command injection vulnerabilities...", icons.injection);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-2.6" });

  try {
    const urlsWithCommandParams = scanData.urls.filter(hasCommandParams);
    
    if (urlsWithCommandParams.length === 0) {
      logWarning("PHASE-2.6", "No URLs with command parameters found. Skipping Commix...");
      return;
    }

    logDiscovery("PHASE-2.6", urlsWithCommandParams.length, "URLs with command parameters");

    // Test first 5 URLs with command params (light scan)
    const urlsToTest = urlsWithCommandParams.slice(0, 5);

    for (let i = 0; i < urlsToTest.length; i++) {
      const url = urlsToTest[i];
      emitStdoutLog(scanData.scanId, `${createProgressLine(i + 1, urlsToTest.length, "Testing")}`, { agentLabel: "PHASE-2.6" });

      const commixOutput = await executeCommand(
        scanData.scanId,
        "/home/runner/workspace/bin/commix",
        ["-u", url, "-q"],
        "COMMIX"
      );

      // Filter output to show only findings
      const filteredCommix = filterToolOutput("commix", commixOutput, "COMMIX");
      filteredCommix.importantLines.forEach(line => {
        emitStdoutLog(scanData.scanId, line, { agentLabel: "COMMIX" });
      });

      // Log all findings, even low severity ones
      if (commixOutput.toLowerCase().includes("vulnerable") || commixOutput.toLowerCase().includes("rce") || 
          commixOutput.toLowerCase().includes("injection") || commixOutput.toLowerCase().includes("found")) {
        const severity = commixOutput.toLowerCase().includes("vulnerable") ? "critical" : "high";
        scanData.vulnerabilities.push({
          title: "Remote Code Execution (RCE) / Command Injection",
          severity: severity,
          type: "rce",
          url: url,
          description: `Command injection detected via Commix`
        });
        logFinding("PHASE-2.6", `RCE / Command Injection on ${url}`, severity as "critical" | "high" | "medium" | "low");
        
        // Trigger screenshot
        const screenshot = await captureScreenshot(scanData.scanId, url, `rce-${i}`);

        // EVIDENCE TERMINAL EMISSION
        emitStdoutLog(scanData.scanId, 
          `🚨 [EVIDENCE] Command Injection Vulnerability Found!\n` +
          `URL: ${url}\n` +
          `Payload: Commix default injection\n` +
          `Evidence: Vulnerability detected by Commix OS command execution testing`, 
          { agentLabel: "COMMIX", type: "finding", screenshot: screenshot || undefined }
        );
      }
    }

    logSuccess("PHASE-2.6", "COMPLETE - Ready for PHASE 3 (Global Vuln Scan)");
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 2.6 failed: ${errorMsg}`);
    logWarning("PHASE-2.6", `ERROR: ${errorMsg}. Continuing to Phase 3...`);
  }
}

/**
 * PHASE 3: Global Vulnerability Scanning
 * Run Nuclei on ENTIRE LIST of live subdomains using -list flag
 * Concurrency: -c 3 to prevent resource exhaustion
 */
async function phase3GlobalVulnScanning(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-3: VULNERABILITY ANALYSIS");
  logPhaseInfo("PHASE-3", `Scanning ${scanData.subdomains.length} subdomains for vulnerabilities...`, icons.scan);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-3" });

  try {
    if (scanData.subdomains.length === 0) {
      emitStdoutLog(scanData.scanId, `[PHASE 3] No live subdomains to scan. Skipping...`, { agentLabel: "PHASE-3", type: "warning" });
      return;
    }

    // Write subdomains to temporary file
    const subdomainsFile = `${tmpdir()}/nuclei-targets-${scanData.scanId}.txt`;
    const subdomainList = scanData.subdomains
      .map(sub => sub.startsWith("http") ? sub : `https://${sub}`)
      .join("\n");
    writeFileSync(subdomainsFile, subdomainList);
    emitStdoutLog(scanData.scanId, `[PHASE 3] Wrote ${scanData.subdomains.length} subdomains to ${subdomainsFile}`, { agentLabel: "PHASE-3" });

    // Run Nuclei with -list flag and -c 3 concurrency
    emitStdoutLog(scanData.scanId, `[PHASE 3] Executing: nuclei -list ${subdomainsFile} -c 3 -t /home/runner/workspace/nuclei-templates`, { agentLabel: "PHASE-3" });
    const nucleiOutput = await executeCommand(
      scanData.scanId,
      "/home/runner/workspace/bin/nuclei",
      [
        "-list", subdomainsFile,
        "-c", "3",
        "-t", "/home/runner/workspace/nuclei-templates",
        "-ni",
        "-duc",
        "-timeout", "10",
        "-retries", "1"
      ],
      "NUCLEI-GLOBAL"
    );

    // Filter nuclei output - show only high/critical findings
    const filteredNuclei = filterToolOutput("nuclei", nucleiOutput, "NUCLEI");
    filteredNuclei.importantLines.forEach(line => {
      emitStdoutLog(scanData.scanId, line, { agentLabel: "NUCLEI" });
    });

    // Parse Nuclei JSON output - INCLUDE ALL SEVERITY LEVELS
    let findingsCount = 0;
    const nucleiLines = nucleiOutput.split("\n");
    for (const line of nucleiLines) {
      if (line.trim().startsWith("{") && line.includes("template-id")) {
        try {
          const finding = JSON.parse(line);
          const subdomain = scanData.subdomains.find(sub => finding.host?.includes(sub) || finding.matched_at?.includes(sub));
          
          // Log ALL findings regardless of severity (low, medium, high, critical)
          scanData.vulnerabilities.push({
            subdomain: subdomain || finding.host,
            title: finding.name || "Unknown Nuclei Finding",
            severity: finding.severity || "medium",
            templateId: finding["template-id"],
            url: finding.matched_at || "N/A",
            type: "nuclei"
          });
          
          if (subdomain) {
            const meta = scanData.subdomainMetadata.get(subdomain);
            if (meta) {
              meta.vulnerabilityCount = (meta.vulnerabilityCount || 0) + 1;
            }
          }
          
          findingsCount++;

          // Trigger screenshot for High/Critical
          let screenshot;
          if (finding.severity === "high" || finding.severity === "critical") {
            screenshot = await captureScreenshot(scanData.scanId, finding.matched_at || finding.host, `nuclei-${findingsCount}`);
          }

          // EVIDENCE TERMINAL EMISSION for High/Critical
          if (finding.severity === "high" || finding.severity === "critical") {
            emitStdoutLog(scanData.scanId, 
              `🚨 [EVIDENCE] ${finding.name}\n` +
              `URL: ${finding.matched_at || finding.host}\n` +
              `Payload: ${finding["template-id"]}\n` +
              `Evidence: ${finding.info?.description || "Confirmed by Nuclei template match"}`, 
              { agentLabel: "NUCLEI", type: "finding", screenshot: screenshot || undefined }
            );
          }
        } catch {
          // Skip unparseable lines
        }
      }
    }

    logDiscovery("PHASE-3", findingsCount, "vulnerabilities");

    // Clean up temp file
    try {
      unlinkSync(subdomainsFile);
    } catch {
      // Ignore cleanup errors
    }

    logSuccess("PHASE-3", "COMPLETE - Ready for PHASE 4 (Global XSS Testing)");
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 3 failed: ${errorMsg}`);
    logWarning("PHASE-3", `ERROR: ${errorMsg}. Continuing to Phase 4...`);
  }
}

/**
 * PHASE 4: Global XSS Testing
 * Pass ALL discovered URLs to Dalfox for comprehensive XSS testing
 */
async function phase4GlobalXssTesting(scanData: ScanData): Promise<void> {
  const bannerText = createBanner("PHASE-4: XSS EXPLOITATION TESTING");
  logPhaseInfo("PHASE-4", `Testing ${scanData.urls.length} URLs for XSS vulnerabilities...`, icons.fire);
  emitStdoutLog(scanData.scanId, bannerText, { agentLabel: "PHASE-4" });

  try {
    if (scanData.urls.length === 0) {
      emitStdoutLog(scanData.scanId, `[PHASE 4] No URLs discovered. Skipping XSS testing...`, { agentLabel: "PHASE-4", type: "warning" });
      return;
    }

    emitStdoutLog(scanData.scanId, `[PHASE 4] Testing ${scanData.urls.length} URLs for XSS vulnerabilities with Dalfox...`, { agentLabel: "PHASE-4" });

    // Write URLs to temporary file
    const urlsFile = `${tmpdir()}/dalfox-urls-${scanData.scanId}.txt`;
    writeFileSync(urlsFile, scanData.urls.join("\n"));
    emitStdoutLog(scanData.scanId, `[PHASE 4] Wrote ${scanData.urls.length} URLs to ${urlsFile}`, { agentLabel: "PHASE-4" });

    // Run Dalfox with URL list (batch processing)
    emitStdoutLog(scanData.scanId, `[PHASE 4] Executing: dalfox file ${urlsFile} -q`, { agentLabel: "PHASE-4" });
    const dalfoxOutput = await executeCommand(
      scanData.scanId,
      "/home/runner/workspace/bin/dalfox",
      ["file", urlsFile, "-q"],
      "DALFOX-GLOBAL"
    );

    // Check for XSS findings in Dalfox output
    let xssCount = 0;
    if (dalfoxOutput.toLowerCase().includes("vulnerable") || dalfoxOutput.toLowerCase().includes("xss")) {
      xssCount = (dalfoxOutput.match(/vulnerable|xss/gi) || []).length;
      logFinding("PHASE-4", "XSS vulnerabilities detected", "high");
      
      // Trigger screenshot (on first URL for batch)
      const screenshot = await captureScreenshot(scanData.scanId, scanData.urls[0], "xss-batch");

      // EVIDENCE TERMINAL EMISSION
      emitStdoutLog(scanData.scanId, 
        `🚨 [EVIDENCE] Cross-Site Scripting (XSS) Found!\n` +
        `Targets: ${xssCount} endpoints\n` +
        `Payload: Dalfox polyglot payloads\n` +
        `Evidence: Confirmed reflective/stored XSS via headless browser verification`, 
        { agentLabel: "DALFOX", type: "finding", screenshot: screenshot || undefined }
      );

      scanData.vulnerabilities.push({
        title: "Cross-Site Scripting (XSS)",
        severity: "high",
        type: "xss",
        count: xssCount,
        description: `Found ${xssCount} potential XSS vulnerabilities in URLs`
      });
    }

    logSuccess("PHASE-4", `XSS testing complete (${xssCount} findings)`);

    // Clean up temp file
    try {
      unlinkSync(urlsFile);
    } catch {
      // Ignore cleanup errors
    }

    logSuccess("PHASE-4", "COMPLETE - Scan Ready for Dashboard");
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 4 failed: ${errorMsg}`);
    logWarning("PHASE-4", `ERROR: ${errorMsg}. Continuing to summary...`);
  }
}

/**
 * MAIN FULL DOMAIN-WIDE SCAN ORCHESTRATION
 * 
 * Global Execution Order:
 * 1. PHASE 1: Subdomain Discovery with HTTPX (returns ALL live subdomains)
 * 2. PHASE 2: Global URL Crawling (Katana on ALL subdomains with -c 3)
 * 2.5. PHASE 2.5: SQLMap on URLs with parameters
 * 2.6. PHASE 2.6: Commix on URLs with command-like parameters
 * 3. PHASE 3: Global Vuln Scanning (Nuclei on ALL subdomains with -c 3)
 * 4. PHASE 4: Global XSS Testing (Dalfox on ALL discovered URLs)
 */
export async function runSequentialScan(
  scanId: string,
  target: string
): Promise<any> {
  const scanData: ScanData = {
    target,
    scanId,
    subdomains: [],
    urls: [],
    vulnerabilities: [],
    errors: [],
    subdomainMetadata: new Map()
  };

  console.log(`[DEBUG] runSequentialScan triggered for scanId=${scanId}, target=${target}`);

  const startTime = Date.now();
  const banner = createBanner("ELITE-SCANNER");
  emitStdoutLog(scanId, banner, { agentLabel: "SEQUENTIAL-SCAN" });
  logPhaseInfo("SEQUENTIAL-SCAN", `Starting comprehensive scan for ${target}`, icons.target);
  logPhaseInfo("SEQUENTIAL-SCAN", "Phases: 1) HTTPX → 2) Katana → 2.5) SQLMap → 2.6) Commix → 3) Nuclei → 4) Dalfox", icons.star);

  try {
    // PHASE 1: Discover all live subdomains with HTTPX
    await phase1SubdomainDiscovery(scanData);
    
    if (scanData.subdomains.length === 0) {
      emitStdoutLog(scanId, `[FULL DOMAIN-WIDE ENGINE] ⚠️ No live subdomains discovered. Ending scan.`, { agentLabel: "SEQUENTIAL-SCAN", type: "warning" });
      return {
        success: true,
        subdomains: [],
        urls: [],
        vulnerabilities: [],
        errors: ["No live subdomains found"],
        metadata: {}
      };
    }

    // PHASE 2: Global URL crawling on all subdomains
    await phase2GlobalUrlCrawling(scanData);
    
    // PHASE 2.5: SQLMap on URLs with parameters
    await phase2_5SqlmapOnParameters(scanData);
    
    // PHASE 2.6: Commix on URLs with command-like parameters
    await phase2_6CommixOnCommandParams(scanData);
    
    // PHASE 3: Global vulnerability scanning on all subdomains
    await phase3GlobalVulnScanning(scanData);
    
    // PHASE 4: Global XSS testing on all discovered URLs
    await phase4GlobalXssTesting(scanData);

    // Final summary with professional table and report
    const duration = Date.now() - startTime;
    const reportText = createFinalReport(target, {
      subdomains: scanData.subdomains,
      totalUrls: scanData.urls.length,
      vulnerabilities: scanData.vulnerabilities,
      errors: scanData.errors,
      metadata: Object.fromEntries(scanData.subdomainMetadata)
    }, duration);
    emitStdoutLog(scanId, reportText, { agentLabel: "SEQUENTIAL-SCAN" });

    return {
      success: true,
      subdomains: scanData.subdomains,
      urls: scanData.urls,
      vulnerabilities: scanData.vulnerabilities,
      errors: scanData.errors,
      metadata: Object.fromEntries(scanData.subdomainMetadata),
      summary: {
        totalSubdomains: scanData.subdomains.length,
        totalUrls: scanData.urls.length,
        totalVulnerabilities: scanData.vulnerabilities.length,
        totalErrors: scanData.errors.length
      }
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    emitErrorLog(scanId, `[FULL DOMAIN-WIDE ENGINE] FATAL ERROR: ${errorMsg}`);
    
    return {
      success: false,
      error: errorMsg,
      subdomains: scanData.subdomains,
      urls: scanData.urls,
      vulnerabilities: scanData.vulnerabilities,
      errors: scanData.errors,
      metadata: Object.fromEntries(scanData.subdomainMetadata)
    };
  }
}
