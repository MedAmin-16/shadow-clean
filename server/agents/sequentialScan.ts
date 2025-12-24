import { spawn } from "child_process";
import { emitStdoutLog, emitExecLog, emitErrorLog } from "../src/sockets/socketManager";

/**
 * SEQUENTIAL SCAN ORCHESTRATION - PHASE-BASED EXECUTION
 * 
 * STRUCTURE:
 * ├─ PHASE 1: Subdomain Discovery (Subfinder/Assetfinder → HTTProbe)
 * └─ FOR EACH SUBDOMAIN (Sequential, one at a time):
 *    ├─ PHASE 2: URL Gathering (Katana + GAU)
 *    ├─ PHASE 3: Vulnerability Scanning (Nuclei)
 *    └─ PHASE 4: Targeted Exploitation (SQLMap/Dalfox/Commix)
 * 
 * NO CONCURRENCY. NO PARALLEL EXECUTION. HARD BLOCKS BETWEEN PHASES.
 */

interface ScanData {
  target: string;
  scanId: string;
  subdomains: string[];
  urls: Map<string, string[]>; // subdomain -> urls
  vulnerabilities: any[];
  errors: string[];
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
 * PHASE 1: Subdomain Discovery
 * Execute Subfinder/Assetfinder → Filter through HTTProbe
 */
async function phase1SubdomainDiscovery(scanData: ScanData): Promise<void> {
  emitStdoutLog(scanData.scanId, `\n${'═'.repeat(80)}`, { agentLabel: "PHASE-1" });
  emitStdoutLog(scanData.scanId, `[PHASE 1] SUBDOMAIN DISCOVERY - STARTING`, { agentLabel: "PHASE-1" });
  emitStdoutLog(scanData.scanId, `[PHASE 1] Target: ${scanData.target}`, { agentLabel: "PHASE-1" });
  emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-1" });

  try {
    // Extract domain from URL if needed - assetfinder requires DOMAIN only, not full URL
    let targetDomain = scanData.target;
    try {
      const url = new URL(scanData.target.startsWith('http') ? scanData.target : `https://${scanData.target}`);
      targetDomain = url.hostname;
    } catch {
      // If URL parsing fails, use target as-is (likely already a domain)
      targetDomain = scanData.target.split('/')[0];
    }
    
    emitStdoutLog(scanData.scanId, `[PHASE 1] Extracted domain for assetfinder: ${targetDomain}`, { agentLabel: "PHASE-1" });

    // Step 1: Run Assetfinder
    emitStdoutLog(scanData.scanId, `[PHASE 1 - Assetfinder] Discovering subdomains...`, { agentLabel: "PHASE-1" });
    const assetfinderOutput = await executeCommand(
      scanData.scanId,
      "/home/runner/workspace/bin/assetfinder",
      ["-subs-only", targetDomain],
      "ASSETFINDER"
    );

    const assetfinderSubs = assetfinderOutput
      .split("\n")
      .filter(line => line.trim() && !line.startsWith("[") && !line.startsWith("{"))
      .map(line => line.trim());

    emitStdoutLog(scanData.scanId, `[PHASE 1] Assetfinder found ${assetfinderSubs.length} subdomains`, { agentLabel: "PHASE-1" });

    // Step 2: Filter through HTTProbe
    if (assetfinderSubs.length > 0) {
      emitStdoutLog(scanData.scanId, `[PHASE 1 - HTTProbe] Filtering live subdomains...`, { agentLabel: "PHASE-1" });
      
      const httpprobeInput = assetfinderSubs.join("\n");
      const httpprobeOutput = await executeCommand(
        scanData.scanId,
        "bash",
        ["-c", `echo "${httpprobeInput}" | /home/runner/workspace/bin/httpprobe -c 50 -p 80,443 -t 5000`],
        "HTTPPROBE"
      );

      const liveSubdomains = httpprobeOutput
        .split("\n")
        .filter(line => line.trim() && (line.includes("http://") || line.includes("https://")))
        .map(line => {
          // Extract domain from URL
          try {
            const url = new URL(line);
            return url.hostname;
          } catch {
            return line.split("//")[1]?.split("/")[0] || line;
          }
        })
        .filter((sub, idx, arr) => arr.indexOf(sub) === idx); // Deduplicate

      scanData.subdomains = liveSubdomains;
      emitStdoutLog(scanData.scanId, `[PHASE 1] HTTProbe verified ${liveSubdomains.length} live subdomain(s)`, { agentLabel: "PHASE-1" });
      
      liveSubdomains.forEach((sub, idx) => {
        emitStdoutLog(scanData.scanId, `  [${idx + 1}/${liveSubdomains.length}] ${sub}`, { agentLabel: "PHASE-1" });
      });
    }

    // Phase 1 Complete
    emitStdoutLog(scanData.scanId, `\n[PHASE 1] ✅ COMPLETE - ${scanData.subdomains.length} subdomain(s) discovered`, { agentLabel: "PHASE-1" });
    emitStdoutLog(scanData.scanId, `[PHASE 1] Hard block: Phase 2 will now begin...`, { agentLabel: "PHASE-1" });
    emitStdoutLog(scanData.scanId, `${'═'.repeat(80)}\n`, { agentLabel: "PHASE-1" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 1 failed: ${errorMsg}`);
    emitErrorLog(scanData.scanId, `[PHASE 1] FAILED: ${errorMsg}`);
    throw error;
  }
}

/**
 * PHASE 2: URL Gathering (Katana + GAU)
 */
async function phase2UrlGathering(scanData: ScanData, subdomain: string, index: number): Promise<void> {
  const totalSubs = scanData.subdomains.length;
  emitStdoutLog(scanData.scanId, `\n${'─'.repeat(80)}`, { agentLabel: "PHASE-2" });
  emitStdoutLog(scanData.scanId, `[PHASE 2] URL GATHERING [${index + 1}/${totalSubs}] - ${subdomain}`, { agentLabel: "PHASE-2" });
  emitStdoutLog(scanData.scanId, `${'─'.repeat(80)}\n`, { agentLabel: "PHASE-2" });

  try {
    const urls: string[] = [];

    // Step 1: Katana crawling
    emitStdoutLog(scanData.scanId, `[PHASE 2 - Katana] Crawling ${subdomain}...`, { agentLabel: "PHASE-2" });
    const target = subdomain.startsWith("http") ? subdomain : `https://${subdomain}`;
    
    const katanaOutput = await executeCommand(
      scanData.scanId,
      "/home/runner/workspace/bin/katana",
      ["-d", "3", "-ps", "-system-chromium", "--headless", "--no-sandbox", "-u", target],
      "KATANA"
    );

    const katanaUrls = katanaOutput
      .split("\n")
      .filter(line => line.trim() && (line.startsWith("http://") || line.startsWith("https://")))
      .slice(0, 100); // Limit to 100 URLs

    urls.push(...katanaUrls);
    emitStdoutLog(scanData.scanId, `[PHASE 2] Katana found ${katanaUrls.length} URL(s)`, { agentLabel: "PHASE-2" });

    // Step 2: GAU (Wayback Machine)
    emitStdoutLog(scanData.scanId, `[PHASE 2 - WaybackURLs] Mining Wayback Machine for ${subdomain}...`, { agentLabel: "PHASE-2" });
    
    const waybackOutput = await executeCommand(
      scanData.scanId,
      "bash",
      ["-c", `echo "${subdomain}" | /home/runner/workspace/bin/waybackurls 2>/dev/null || true`],
      "WAYBACKURLS"
    );

    const waybackUrls = waybackOutput
      .split("\n")
      .filter(line => line.trim() && (line.startsWith("http://") || line.startsWith("https://")))
      .slice(0, 100); // Limit to 100 URLs

    urls.push(...waybackUrls);
    emitStdoutLog(scanData.scanId, `[PHASE 2] Wayback URLs found ${waybackUrls.length} URL(s)`, { agentLabel: "PHASE-2" });

    // Deduplicate and store
    const uniqueUrls = [...new Set(urls)];
    scanData.urls.set(subdomain, uniqueUrls);

    emitStdoutLog(scanData.scanId, `[PHASE 2] ✅ COMPLETE for ${subdomain} - ${uniqueUrls.length} unique URL(s)`, { agentLabel: "PHASE-2" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 2 failed for ${subdomain}: ${errorMsg}`);
    emitStdoutLog(scanData.scanId, `[PHASE 2] ⚠️ ERROR for ${subdomain}: ${errorMsg}. Continuing...`, { agentLabel: "PHASE-2", type: "error" });
  }
}

/**
 * PHASE 3: Vulnerability Scanning (Nuclei)
 */
async function phase3NucleiScanning(scanData: ScanData, subdomain: string, index: number): Promise<void> {
  const totalSubs = scanData.subdomains.length;
  emitStdoutLog(scanData.scanId, `\n${'─'.repeat(80)}`, { agentLabel: "PHASE-3" });
  emitStdoutLog(scanData.scanId, `[PHASE 3] VULNERABILITY SCANNING [${index + 1}/${totalSubs}] - ${subdomain}`, { agentLabel: "PHASE-3" });
  emitStdoutLog(scanData.scanId, `${'─'.repeat(80)}\n`, { agentLabel: "PHASE-3" });

  try {
    const target = subdomain.startsWith("http") ? subdomain : `https://${subdomain}`;

    emitStdoutLog(scanData.scanId, `[PHASE 3 - Nuclei] Scanning ${target}...`, { agentLabel: "PHASE-3" });

    const nucleiOutput = await executeCommand(
      scanData.scanId,
      "/home/runner/workspace/bin/nuclei",
      [
        "-u", target,
        "-t", "/home/runner/workspace/nuclei-templates",
        "-ni",
        "-duc",
        "-stats",
        "-timeout", "10",
        "-retries", "2"
      ],
      "NUCLEI"
    );

    // Parse Nuclei JSON output
    const nucleiFindings: any[] = [];
    nucleiOutput.split("\n").forEach(line => {
      if (line.trim().startsWith("{") && line.includes("template-id")) {
        try {
          const finding = JSON.parse(line);
          nucleiFindings.push({
            subdomain,
            title: finding.name || "Unknown",
            severity: finding.severity || "medium",
            templateId: finding["template-id"],
            url: finding.matched_at || target
          });
        } catch {
          // Skip unparseable lines
        }
      }
    });

    scanData.vulnerabilities.push(...nucleiFindings);
    emitStdoutLog(scanData.scanId, `[PHASE 3] ✅ COMPLETE for ${subdomain} - ${nucleiFindings.length} finding(s)`, { agentLabel: "PHASE-3" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 3 failed for ${subdomain}: ${errorMsg}`);
    emitStdoutLog(scanData.scanId, `[PHASE 3] ⚠️ ERROR for ${subdomain}: ${errorMsg}. Continuing...`, { agentLabel: "PHASE-3", type: "error" });
  }
}

/**
 * PHASE 4: Targeted Exploitation (SQLMap/Dalfox/Commix)
 */
async function phase4Exploitation(scanData: ScanData, subdomain: string, index: number): Promise<void> {
  const totalSubs = scanData.subdomains.length;
  emitStdoutLog(scanData.scanId, `\n${'─'.repeat(80)}`, { agentLabel: "PHASE-4" });
  emitStdoutLog(scanData.scanId, `[PHASE 4] TARGETED EXPLOITATION [${index + 1}/${totalSubs}] - ${subdomain}`, { agentLabel: "PHASE-4" });
  emitStdoutLog(scanData.scanId, `${'─'.repeat(80)}\n`, { agentLabel: "PHASE-4" });

  try {
    const urls = scanData.urls.get(subdomain) || [];
    
    if (urls.length === 0) {
      emitStdoutLog(scanData.scanId, `[PHASE 4] No URLs found for ${subdomain}. Skipping exploitation.`, { agentLabel: "PHASE-4" });
      return;
    }

    const targetUrl = urls[0]; // Test first URL
    emitStdoutLog(scanData.scanId, `[PHASE 4] Testing ${targetUrl}...`, { agentLabel: "PHASE-4" });

    // Step 1: SQLMap for SQL Injection
    emitStdoutLog(scanData.scanId, `[PHASE 4 - SQLMap] Testing for SQL injection...`, { agentLabel: "PHASE-4" });
    const sqlmapOutput = await executeCommand(
      scanData.scanId,
      "sqlmap",
      ["-u", targetUrl, "--batch", "--flush-session", "--random-agent", "--level=3", "--risk=2", "-q"],
      "SQLMAP"
    );

    if (sqlmapOutput.toLowerCase().includes("vulnerable") || sqlmapOutput.toLowerCase().includes("injectable")) {
      scanData.vulnerabilities.push({
        subdomain,
        title: "SQL Injection Vulnerability",
        severity: "critical",
        type: "sqli",
        url: targetUrl
      });
      emitStdoutLog(scanData.scanId, `[PHASE 4] 🚨 SQL Injection FOUND on ${targetUrl}`, { agentLabel: "PHASE-4", type: "finding" });
    }

    // Step 2: Dalfox for XSS
    emitStdoutLog(scanData.scanId, `[PHASE 4 - Dalfox] Testing for XSS...`, { agentLabel: "PHASE-4" });
    const dalfoxOutput = await executeCommand(
      scanData.scanId,
      "/home/runner/workspace/bin/dalfox",
      ["url", targetUrl, "-q"],
      "DALFOX"
    );

    if (dalfoxOutput.toLowerCase().includes("vulnerable") || dalfoxOutput.toLowerCase().includes("xss")) {
      scanData.vulnerabilities.push({
        subdomain,
        title: "Cross-Site Scripting (XSS)",
        severity: "high",
        type: "xss",
        url: targetUrl
      });
      emitStdoutLog(scanData.scanId, `[PHASE 4] ⚠️ XSS FOUND on ${targetUrl}`, { agentLabel: "PHASE-4", type: "finding" });
    }

    // Step 3: Commix for Command Injection
    emitStdoutLog(scanData.scanId, `[PHASE 4 - Commix] Testing for command injection...`, { agentLabel: "PHASE-4" });
    const commixOutput = await executeCommand(
      scanData.scanId,
      "python3",
      ["-m", "commix", "-u", targetUrl, "-q"],
      "COMMIX"
    );

    if (commixOutput.toLowerCase().includes("vulnerable") || commixOutput.toLowerCase().includes("rce")) {
      scanData.vulnerabilities.push({
        subdomain,
        title: "Remote Code Execution (RCE)",
        severity: "critical",
        type: "rce",
        url: targetUrl
      });
      emitStdoutLog(scanData.scanId, `[PHASE 4] 🚨 RCE FOUND on ${targetUrl}`, { agentLabel: "PHASE-4", type: "finding" });
    }

    emitStdoutLog(scanData.scanId, `[PHASE 4] ✅ COMPLETE for ${subdomain}`, { agentLabel: "PHASE-4" });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    scanData.errors.push(`Phase 4 failed for ${subdomain}: ${errorMsg}`);
    emitStdoutLog(scanData.scanId, `[PHASE 4] ⚠️ ERROR for ${subdomain}: ${errorMsg}. Continuing...`, { agentLabel: "PHASE-4", type: "error" });
  }
}

/**
 * MAIN SEQUENTIAL SCAN ORCHESTRATION
 * 
 * Execution Order:
 * 1. PHASE 1: Subdomain Discovery (once)
 * 2. FOR EACH subdomain (sequential):
 *    - PHASE 2: URL Gathering
 *    - PHASE 3: Nuclei Scanning
 *    - PHASE 4: Exploitation
 */
export async function runSequentialScan(
  scanId: string,
  target: string
): Promise<any> {
  const scanData: ScanData = {
    target,
    scanId,
    subdomains: [],
    urls: new Map(),
    vulnerabilities: [],
    errors: []
  };

  // DEBUG: Log that function was triggered
  console.log(`[DEBUG] runSequentialScan triggered for scanId=${scanId}, target=${target}`);

  emitStdoutLog(scanId, `\n${'█'.repeat(80)}`, { agentLabel: "SEQUENTIAL-SCAN" });
  emitStdoutLog(scanId, `[SEQUENTIAL SCAN] Starting scan for ${target}`, { agentLabel: "SEQUENTIAL-SCAN" });
  emitStdoutLog(scanId, `[SEQUENTIAL SCAN] Hard block enforcement: Each phase completes fully before next begins`, { agentLabel: "SEQUENTIAL-SCAN" });
  emitStdoutLog(scanId, `${'█'.repeat(80)}\n`, { agentLabel: "SEQUENTIAL-SCAN" });

  try {
    // PHASE 1: One-time subdomain discovery
    await phase1SubdomainDiscovery(scanData);

    // Main loop: Process each subdomain sequentially through phases 2-4
    for (let idx = 0; idx < scanData.subdomains.length; idx++) {
      const subdomain = scanData.subdomains[idx];
      
      emitStdoutLog(scanId, `\n[SUBDOMAIN BLOCK ${idx + 1}/${scanData.subdomains.length}] Processing: ${subdomain}`, { agentLabel: "LOOP-CONTROLLER" });
      
      // PHASE 2: URL Gathering
      await phase2UrlGathering(scanData, subdomain, idx);
      
      // PHASE 3: Vulnerability Scanning
      await phase3NucleiScanning(scanData, subdomain, idx);
      
      // PHASE 4: Exploitation
      await phase4Exploitation(scanData, subdomain, idx);
      
      emitStdoutLog(scanId, `\n[SUBDOMAIN BLOCK ${idx + 1}/${scanData.subdomains.length}] ✅ Complete for ${subdomain}`, { agentLabel: "LOOP-CONTROLLER" });
    }

    // Final summary
    emitStdoutLog(scanId, `\n${'█'.repeat(80)}`, { agentLabel: "SEQUENTIAL-SCAN" });
    emitStdoutLog(scanId, `[SEQUENTIAL SCAN] ✅ COMPLETE`, { agentLabel: "SEQUENTIAL-SCAN" });
    emitStdoutLog(scanId, `[SUMMARY] Subdomains: ${scanData.subdomains.length} | Vulnerabilities: ${scanData.vulnerabilities.length} | Errors: ${scanData.errors.length}`, { agentLabel: "SEQUENTIAL-SCAN" });
    emitStdoutLog(scanId, `${'█'.repeat(80)}\n`, { agentLabel: "SEQUENTIAL-SCAN" });

    return {
      success: true,
      subdomains: scanData.subdomains,
      vulnerabilities: scanData.vulnerabilities,
      errors: scanData.errors,
      urlsMap: Object.fromEntries(scanData.urls)
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    emitErrorLog(scanId, `[SEQUENTIAL SCAN] FATAL ERROR: ${errorMsg}`);
    
    return {
      success: false,
      error: errorMsg,
      subdomains: scanData.subdomains,
      vulnerabilities: scanData.vulnerabilities,
      errors: scanData.errors
    };
  }
}
