import { spawn } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { emitStdoutLog, emitExecLog, emitErrorLog } from "../src/sockets/socketManager";

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
      stdio: ["pipe", "pipe", "pipe"]
    });

    child.stdout?.on("data", (data: Buffer) => {
      const text = data.toString();
      const lines = text.split("\n").filter(l => l.trim());
      lines.forEach(line => {
        emitStdoutLog(scanId, `[${phaseName}] ${line}`, { agentLabel: phaseName });
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

    child.on("error", (err: Error) => {
      emitErrorLog(scanId, `[${phaseName}] Process error: ${err.message}`);
      resolve("");
    });
  });
}

/**
 * PHASE 1: Subdomain Discovery (GLOBAL)
 * Execute Assetfinder → Filter with HTTPX binary for FAST probing
 * Returns ALL live subdomains for downstream phases
 */
async function phase1SubdomainDiscovery(scanData: ScanData): Promise<void> {
  emitStdoutLog(scanData.scanId, `\n${'═'.repeat(80)}`, { agentLabel: "PHASE-1" });
  emitStdoutLog(scanData.scanId, `[PHASE 1] GLOBAL SUBDOMAIN DISCOVERY - STARTING`, { agentLabel: "PHASE-1" });
  emitStdoutLog(scanData.scanId, `[PHASE 1] Target: ${scanData.target}`, { agentLabel: "PHASE-1" });
  emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-1" });

  try {
    // Extract domain from URL if needed
    let targetDomain = scanData.target;
    try {
      const url = new URL(scanData.target.startsWith('http') ? scanData.target : `https://${scanData.target}`);
      targetDomain = url.hostname;
    } catch {
      targetDomain = scanData.target.split('/')[0];
    }
    
    emitStdoutLog(scanData.scanId, `[PHASE 1] Extracted domain: ${targetDomain}`, { agentLabel: "PHASE-1" });

    // Step 1: Run Assetfinder with absolute path
    emitStdoutLog(scanData.scanId, `[PHASE 1] Running assetfinder...`, { agentLabel: "PHASE-1" });
    const assetfinderOutput = await executeCommand(
      scanData.scanId,
      "/home/runner/workspace/bin/assetfinder",
      ["-subs-only", targetDomain],
      "ASSETFINDER"
    );

    const discoveredSubs = assetfinderOutput
      .split("\n")
      .filter(line => line.trim() && !line.startsWith("[") && !line.startsWith("{"))
      .map(line => line.trim());

    emitStdoutLog(scanData.scanId, `[PHASE 1] Discovered ${discoveredSubs.length} subdomains`, { agentLabel: "PHASE-1" });

    // Step 2: Filter through HTTPX binary (FAST probing)
    if (discoveredSubs.length > 0) {
      emitStdoutLog(scanData.scanId, `[PHASE 1] Probing ${discoveredSubs.length} subdomain(s) with HTTPX (fast)...`, { agentLabel: "PHASE-1" });
      
      // Write subdomains to temp file for httpx
      const httpxInputFile = `${tmpdir()}/httpx-input-${scanData.scanId}.txt`;
      const httpxInput = discoveredSubs
        .map(sub => sub.startsWith("http") ? sub : `https://${sub}`)
        .join("\n");
      writeFileSync(httpxInputFile, httpxInput);
      
      // Run httpx with -l flag
      const httpxOutput = await executeCommand(
        scanData.scanId,
        "/home/runner/workspace/bin/httpx",
        ["-l", httpxInputFile, "-status-code", "-follow-redirects"],
        "HTTPX"
      );
      
      const liveSubdomains = httpxOutput
        .split("\n")
        .filter(line => line.trim() && (line.includes("http://") || line.includes("https://")))
        .map(line => {
          try {
            const url = new URL(line);
            return url.hostname || line;
          } catch {
            return line;
          }
        })
        .filter((sub, idx, arr) => arr.indexOf(sub) === idx); // Deduplicate
      
      scanData.subdomains = liveSubdomains;
      emitStdoutLog(scanData.scanId, `[PHASE 1] ✅ HTTPX verified ${liveSubdomains.length} LIVE subdomains`, { agentLabel: "PHASE-1", type: "success" });
      
      liveSubdomains.forEach((sub, idx) => {
        emitStdoutLog(scanData.scanId, `  [${idx + 1}/${liveSubdomains.length}] ${sub}`, { agentLabel: "PHASE-1" });
        scanData.subdomainMetadata.set(sub, { urlCount: 0, vulnerabilityCount: 0 });
      });
      
      // Cleanup
      try {
        unlinkSync(httpxInputFile);
      } catch {
        // Ignore cleanup errors
      }
    } else {
      emitStdoutLog(scanData.scanId, `[PHASE 1] ⚠️ No subdomains discovered`, { agentLabel: "PHASE-1", type: "warning" });
    }

    emitStdoutLog(scanData.scanId, `\n[PHASE 1] ✅ COMPLETE - Ready for PHASE 2 (Global Crawling)`, { agentLabel: "PHASE-1", type: "success" });
    emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-1" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 1 failed: ${errorMsg}`);
    emitErrorLog(scanData.scanId, `[PHASE 1] FAILED: ${errorMsg}`);
    throw error;
  }
}

/**
 * PHASE 2: Global URL Crawling
 * Run Katana on ENTIRE LIST of live subdomains using -list flag
 * Concurrency: -c 3 to prevent RAM exhaustion on Replit
 */
async function phase2GlobalUrlCrawling(scanData: ScanData): Promise<void> {
  emitStdoutLog(scanData.scanId, `\n${'═'.repeat(80)}`, { agentLabel: "PHASE-2" });
  emitStdoutLog(scanData.scanId, `[PHASE 2] GLOBAL URL CRAWLING (${scanData.subdomains.length} subdomains)`, { agentLabel: "PHASE-2" });
  emitStdoutLog(scanData.scanId, `[PHASE 2] Running Katana with -c 3 concurrency on all subdomains...`, { agentLabel: "PHASE-2" });
  emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-2" });

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
    emitStdoutLog(scanData.scanId, `[PHASE 2] Executing: katana -list ${subdomainsFile} -c 3 -d 3 -ps`, { agentLabel: "PHASE-2" });
    const katanaOutput = await executeCommand(
      scanData.scanId,
      "/home/runner/workspace/bin/katana",
      ["-list", subdomainsFile, "-c", "3", "-d", "3", "-ps", "-system-chromium", "--headless", "--no-sandbox"],
      "KATANA-GLOBAL"
    );

    // Parse URLs from output
    const allUrls = katanaOutput
      .split("\n")
      .filter(line => line.trim() && (line.startsWith("http://") || line.startsWith("https://")))
      .slice(0, 500); // Limit to 500 URLs total

    scanData.urls = allUrls;
    emitStdoutLog(scanData.scanId, `[PHASE 2] ✅ Katana discovered ${allUrls.length} total URLs from all subdomains`, { agentLabel: "PHASE-2", type: "success" });

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

    emitStdoutLog(scanData.scanId, `\n[PHASE 2] ✅ COMPLETE - Ready for PHASE 2.5 (SQLMap on Parameters)`, { agentLabel: "PHASE-2", type: "success" });
    emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-2" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 2 failed: ${errorMsg}`);
    emitStdoutLog(scanData.scanId, `[PHASE 2] ⚠️ ERROR: ${errorMsg}. Continuing to Phase 2.5...`, { agentLabel: "PHASE-2", type: "error" });
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
  emitStdoutLog(scanData.scanId, `\n${'═'.repeat(80)}`, { agentLabel: "PHASE-2.5" });
  emitStdoutLog(scanData.scanId, `[PHASE 2.5] SQLMAP ON PARAMETERS`, { agentLabel: "PHASE-2.5" });
  emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-2.5" });

  try {
    const urlsWithParams = scanData.urls.filter(hasParameters);
    
    if (urlsWithParams.length === 0) {
      emitStdoutLog(scanData.scanId, `[PHASE 2.5] No URLs with parameters found. Skipping SQLMap...`, { agentLabel: "PHASE-2.5", type: "info" });
      return;
    }

    emitStdoutLog(scanData.scanId, `[PHASE 2.5] Found ${urlsWithParams.length} URLs with parameters. Running SQLMap...`, { agentLabel: "PHASE-2.5" });

    // Test first 10 URLs with parameters (light scan)
    const urlsToTest = urlsWithParams.slice(0, 10);

    for (let i = 0; i < urlsToTest.length; i++) {
      const url = urlsToTest[i];
      emitStdoutLog(scanData.scanId, `[PHASE 2.5] Testing [${i + 1}/${urlsToTest.length}] ${url}`, { agentLabel: "PHASE-2.5" });

      const sqlmapOutput = await executeCommand(
        scanData.scanId,
        "sqlmap",
        ["-u", url, "--batch", "--flush-session", "--random-agent", "--level=1", "--risk=1", "-q"],
        "SQLMAP"
      );

      if (sqlmapOutput.toLowerCase().includes("vulnerable") || sqlmapOutput.toLowerCase().includes("injectable")) {
        scanData.vulnerabilities.push({
          title: "SQL Injection Vulnerability",
          severity: "critical",
          type: "sqli",
          url: url,
          description: `SQL injection detected via SQLMap`
        });
        emitStdoutLog(scanData.scanId, `[PHASE 2.5] 🚨 SQL INJECTION FOUND on ${url}`, { agentLabel: "PHASE-2.5", type: "finding" });
      }
    }

    emitStdoutLog(scanData.scanId, `\n[PHASE 2.5] ✅ COMPLETE - Ready for PHASE 2.6 (Commix on Command Params)`, { agentLabel: "PHASE-2.5", type: "success" });
    emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-2.5" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 2.5 failed: ${errorMsg}`);
    emitStdoutLog(scanData.scanId, `[PHASE 2.5] ⚠️ ERROR: ${errorMsg}. Continuing to Phase 2.6...`, { agentLabel: "PHASE-2.5", type: "error" });
  }
}

/**
 * PHASE 2.6: Commix on Command-Like Parameters
 * Automatically trigger Commix on URLs with command-like parameters
 */
async function phase2_6CommixOnCommandParams(scanData: ScanData): Promise<void> {
  emitStdoutLog(scanData.scanId, `\n${'═'.repeat(80)}`, { agentLabel: "PHASE-2.6" });
  emitStdoutLog(scanData.scanId, `[PHASE 2.6] COMMIX ON COMMAND PARAMETERS`, { agentLabel: "PHASE-2.6" });
  emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-2.6" });

  try {
    const urlsWithCommandParams = scanData.urls.filter(hasCommandParams);
    
    if (urlsWithCommandParams.length === 0) {
      emitStdoutLog(scanData.scanId, `[PHASE 2.6] No URLs with command parameters found. Skipping Commix...`, { agentLabel: "PHASE-2.6", type: "info" });
      return;
    }

    emitStdoutLog(scanData.scanId, `[PHASE 2.6] Found ${urlsWithCommandParams.length} URLs with command parameters. Running Commix...`, { agentLabel: "PHASE-2.6" });

    // Test first 5 URLs with command params (light scan)
    const urlsToTest = urlsWithCommandParams.slice(0, 5);

    for (let i = 0; i < urlsToTest.length; i++) {
      const url = urlsToTest[i];
      emitStdoutLog(scanData.scanId, `[PHASE 2.6] Testing [${i + 1}/${urlsToTest.length}] ${url}`, { agentLabel: "PHASE-2.6" });

      const commixOutput = await executeCommand(
        scanData.scanId,
        "python3",
        ["-m", "commix", "-u", url, "-q"],
        "COMMIX"
      );

      if (commixOutput.toLowerCase().includes("vulnerable") || commixOutput.toLowerCase().includes("rce") || commixOutput.toLowerCase().includes("injection")) {
        scanData.vulnerabilities.push({
          title: "Remote Code Execution (RCE) / Command Injection",
          severity: "critical",
          type: "rce",
          url: url,
          description: `Command injection detected via Commix`
        });
        emitStdoutLog(scanData.scanId, `[PHASE 2.6] 🚨 RCE FOUND on ${url}`, { agentLabel: "PHASE-2.6", type: "finding" });
      }
    }

    emitStdoutLog(scanData.scanId, `\n[PHASE 2.6] ✅ COMPLETE - Ready for PHASE 3 (Global Vuln Scan)`, { agentLabel: "PHASE-2.6", type: "success" });
    emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-2.6" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 2.6 failed: ${errorMsg}`);
    emitStdoutLog(scanData.scanId, `[PHASE 2.6] ⚠️ ERROR: ${errorMsg}. Continuing to Phase 3...`, { agentLabel: "PHASE-2.6", type: "error" });
  }
}

/**
 * PHASE 3: Global Vulnerability Scanning
 * Run Nuclei on ENTIRE LIST of live subdomains using -list flag
 * Concurrency: -c 3 to prevent resource exhaustion
 */
async function phase3GlobalVulnScanning(scanData: ScanData): Promise<void> {
  emitStdoutLog(scanData.scanId, `\n${'═'.repeat(80)}`, { agentLabel: "PHASE-3" });
  emitStdoutLog(scanData.scanId, `[PHASE 3] GLOBAL VULNERABILITY SCANNING (${scanData.subdomains.length} subdomains)`, { agentLabel: "PHASE-3" });
  emitStdoutLog(scanData.scanId, `[PHASE 3] Running Nuclei with -c 3 concurrency on all subdomains...`, { agentLabel: "PHASE-3" });
  emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-3" });

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

    // Parse Nuclei JSON output
    let findingsCount = 0;
    nucleiOutput.split("\n").forEach(line => {
      if (line.trim().startsWith("{") && line.includes("template-id")) {
        try {
          const finding = JSON.parse(line);
          const subdomain = scanData.subdomains.find(sub => finding.host?.includes(sub) || finding.matched_at?.includes(sub));
          
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
          emitStdoutLog(scanData.scanId, `[PHASE 3] 🔍 Finding: ${finding.name} (${finding.severity})`, { agentLabel: "PHASE-3" });
        } catch {
          // Skip unparseable lines
        }
      }
    });

    emitStdoutLog(scanData.scanId, `[PHASE 3] ✅ Nuclei found ${findingsCount} vulnerabilities across all subdomains`, { agentLabel: "PHASE-3", type: "success" });

    // Clean up temp file
    try {
      unlinkSync(subdomainsFile);
    } catch {
      // Ignore cleanup errors
    }

    emitStdoutLog(scanData.scanId, `\n[PHASE 3] ✅ COMPLETE - Ready for PHASE 4 (Global XSS Testing)`, { agentLabel: "PHASE-3", type: "success" });
    emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-3" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 3 failed: ${errorMsg}`);
    emitStdoutLog(scanData.scanId, `[PHASE 3] ⚠️ ERROR: ${errorMsg}. Continuing to Phase 4...`, { agentLabel: "PHASE-3", type: "error" });
  }
}

/**
 * PHASE 4: Global XSS Testing
 * Pass ALL discovered URLs to Dalfox for comprehensive XSS testing
 */
async function phase4GlobalXssTesting(scanData: ScanData): Promise<void> {
  emitStdoutLog(scanData.scanId, `\n${'═'.repeat(80)}`, { agentLabel: "PHASE-4" });
  emitStdoutLog(scanData.scanId, `[PHASE 4] GLOBAL XSS TESTING (${scanData.urls.length} URLs)`, { agentLabel: "PHASE-4" });
  emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-4" });

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
      emitStdoutLog(scanData.scanId, `[PHASE 4] 🚨 XSS vulnerabilities detected!`, { agentLabel: "PHASE-4", type: "finding" });
      
      scanData.vulnerabilities.push({
        title: "Cross-Site Scripting (XSS)",
        severity: "high",
        type: "xss",
        count: xssCount,
        description: `Found ${xssCount} potential XSS vulnerabilities in URLs`
      });
    }

    emitStdoutLog(scanData.scanId, `[PHASE 4] ✅ XSS testing complete (${xssCount} findings)`, { agentLabel: "PHASE-4", type: "success" });

    // Clean up temp file
    try {
      unlinkSync(urlsFile);
    } catch {
      // Ignore cleanup errors
    }

    emitStdoutLog(scanData.scanId, `\n[PHASE 4] ✅ COMPLETE - Scan Ready for Dashboard`, { agentLabel: "PHASE-4", type: "success" });
    emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-4" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 4 failed: ${errorMsg}`);
    emitStdoutLog(scanData.scanId, `[PHASE 4] ⚠️ ERROR: ${errorMsg}. Continuing to summary...`, { agentLabel: "PHASE-4", type: "error" });
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

  emitStdoutLog(scanId, `\n${'█'.repeat(80)}`, { agentLabel: "SEQUENTIAL-SCAN" });
  emitStdoutLog(scanId, `[FULL DOMAIN-WIDE ENGINE] Starting comprehensive scan for ${target}`, { agentLabel: "SEQUENTIAL-SCAN" });
  emitStdoutLog(scanId, `[FULL DOMAIN-WIDE ENGINE] Phases: 1) HTTPX Discovery → 2) Crawling → 2.5) SQLMap → 2.6) Commix → 3) Nuclei → 4) Dalfox`, { agentLabel: "SEQUENTIAL-SCAN" });
  emitStdoutLog(scanId, `${'█'.repeat(80)}\n`, { agentLabel: "SEQUENTIAL-SCAN" });

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

    // Final summary with per-subdomain breakdown
    emitStdoutLog(scanId, `\n${'█'.repeat(80)}`, { agentLabel: "SEQUENTIAL-SCAN" });
    emitStdoutLog(scanId, `[FULL DOMAIN-WIDE ENGINE] ✅ SCAN COMPLETE`, { agentLabel: "SEQUENTIAL-SCAN", type: "success" });
    emitStdoutLog(scanId, `${'█'.repeat(80)}`, { agentLabel: "SEQUENTIAL-SCAN" });
    
    emitStdoutLog(scanId, `\n[SUMMARY] Global Results:`, { agentLabel: "SEQUENTIAL-SCAN" });
    emitStdoutLog(scanId, `  • Live Subdomains: ${scanData.subdomains.length}`, { agentLabel: "SEQUENTIAL-SCAN" });
    emitStdoutLog(scanId, `  • Total URLs Discovered: ${scanData.urls.length}`, { agentLabel: "SEQUENTIAL-SCAN" });
    emitStdoutLog(scanId, `  • Vulnerabilities Found: ${scanData.vulnerabilities.length}`, { agentLabel: "SEQUENTIAL-SCAN" });
    emitStdoutLog(scanId, `  • Errors: ${scanData.errors.length}`, { agentLabel: "SEQUENTIAL-SCAN" });
    
    emitStdoutLog(scanId, `\n[PER-SUBDOMAIN BREAKDOWN]:`, { agentLabel: "SEQUENTIAL-SCAN" });
    scanData.subdomains.forEach(sub => {
      const meta = scanData.subdomainMetadata.get(sub);
      const vulnCount = scanData.vulnerabilities.filter(v => v.subdomain === sub).length;
      emitStdoutLog(scanId, `  • ${sub}: ${meta?.urlCount || 0} URLs | ${vulnCount} vulnerabilities`, { agentLabel: "SEQUENTIAL-SCAN" });
    });
    
    emitStdoutLog(scanId, `\n${'█'.repeat(80)}\n`, { agentLabel: "SEQUENTIAL-SCAN" });

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
