import { spawn } from "child_process";
import { db, pool } from "../../db";
import path from "path";
import fs from "fs";

// Absolute paths to all tools - use workspace bin directory
const TOOLS = {
  NUCLEI: "/home/runner/workspace/bin/nuclei",
  SUBFINDER: "/home/runner/workspace/bin/subfinder",
  HTTPX: "/home/runner/workspace/bin/httpx",
  KATANA: "/home/runner/workspace/bin/katana",
  WAYBACKURLS: "/home/runner/workspace/bin/waybackurls",
  GAU: "/home/runner/workspace/bin/gau",
  SUBJS: "/home/runner/workspace/bin/subjs",
  SQLMAP: "/home/runner/workspace/bin/sqlmap",
};

export interface SecretScanResult {
  url: string;
  secretType: string;
  value: string;
  confidence: string;
  template: string;
  jsFileUrl?: string;
  severity?: string;
}

export class SecretScanService {
  /**
   * Stream output in real-time to callback with timeout
   * @param silenceStderr - if true, don't forward stderr (for tools with verbose logos)
   */
  private streamOutput(
    process: any,
    onOutput: (line: string) => void,
    onError?: (error: string) => void,
    timeoutMs: number = 1800000,
    silenceStderr: boolean = false
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      let timedOut = false;
      const timeout = setTimeout(() => {
        timedOut = true;
        onError ? onError(`Process timeout after ${timeoutMs}ms`) : onOutput(`[TIMEOUT] Process exceeded ${timeoutMs}ms limit`);
        process.kill("SIGKILL");
      }, timeoutMs);

      if (process.stdout) {
        process.stdout.on("data", (data: Buffer) => {
          const lines = data.toString().split("\n").filter((l: string) => l.trim());
          lines.forEach((line: string) => {
            onOutput(`[STREAM] ${line}`);
          });
        });
      }

      if (process.stderr && !silenceStderr) {
        process.stderr.on("data", (data: Buffer) => {
          const lines = data.toString().split("\n").filter((l: string) => l.trim());
          lines.forEach((line: string) => {
            if (onError) onError(line);
            else onOutput(`[ERROR] ${line}`);
          });
        });
      }

      process.on("close", (code: number) => {
        clearTimeout(timeout);
        if (!timedOut && code === 0) resolve();
        else if (!timedOut) reject(new Error(`Process exited with code ${code}`));
      });

      process.on("error", (err: Error) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
  }

  /**
   * Extract JavaScript files from target domain with graceful failure handling
   */
  async extractJavaScriptFiles(
    target: string,
    onOutput: (line: string) => void,
    onWarning?: (warning: string) => void
  ): Promise<string[]> {
    const jsFiles = new Set<string>();

    try {
      onOutput(`[*] Discovering JS files from: ${target}`);

      // 1. Try Katana for crawling - with 120s timeout and headless browser flags
      onOutput(`[+] Running Katana crawler with system chromium...`);
      try {
        // Use system chromium with headless flags, no sandbox, short timeout
        const katanaArgs = [
          "-u", target,
          "-jc",                      // Output JSON+crawl
          "-system-chrome",            // Use system installed chromium
          "-no-sandbox",               // Run without sandbox (safe in container)
          "-headless",                 // Headless mode
          "-delay", "1",               // 1ms delay between requests
          "-timeout", "10",            // 10s per request
        ];
        
        const katanaProcess = spawn(TOOLS.KATANA, katanaArgs, {
          stdio: ["ignore", "pipe", "pipe"],
        });

        // Use 120-second timeout with Promise.race for guaranteed abort
        const katanaPromise = this.streamOutput(
          katanaProcess,
          (line) => {
            // Extract JavaScript files and crawled URLs
            if (line.includes(".js") || line.includes("http")) {
              if (line.endsWith(".js")) {
                jsFiles.add(line.trim());
                onOutput(`[katana] Found JS: ${line.trim()}`);
              } else if (line.startsWith("http")) {
                onOutput(`[katana] Crawled: ${line.trim()}`);
              }
            }
          },
          undefined,
          120000,  // 120-second hard timeout
          true     // Silence stderr (don't show Katana logo spam)
        );

        // Race promise against 120s timeout
        await Promise.race([
          katanaPromise,
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Katana exceeded 120s timeout")), 120000)
          ),
        ]);

        onOutput(`[+] Katana completed, found ${jsFiles.size} JS files`);
      } catch (err: any) {
        const errStr = String(err).toLowerCase();
        if (errStr.includes("120") || errStr.includes("timeout")) {
          const msg = `Katana timeout (120s limit reached). Continuing with other methods...`;
          onOutput(`[!] ⏱️ ${msg}`);
          if (onWarning) onWarning(msg);
        } else if (errStr.includes("403") || errStr.includes("firewall") || errStr.includes("blocked") || errStr.includes("waf")) {
          const msg = `Katana blocked by target WAF, skipping to next step`;
          onOutput(`[!] ⚠️ ${msg}`);
          if (onWarning) onWarning(msg);
        } else {
          const msg = `Katana error (non-critical): ${err}`;
          onOutput(`[!] ${msg}`);
          if (onWarning) onWarning(msg);
        }
      }

      // 2. Try Waybackurls for historical URLs
      onOutput(`[+] Fetching from Wayback Machine...`);
      try {
        const waybackProcess = spawn("bash", [
          "-c",
          `echo ${target} | ${TOOLS.WAYBACKURLS} | grep -E '\\.js$'`,
        ]);
        await this.streamOutput(
          waybackProcess,
          (line) => {
            if (line.trim()) jsFiles.add(line.trim());
            onOutput(`[wayback] ${line}`);
          }
        );
      } catch (err: any) {
        const msg = `Waybackurls error (non-critical): ${err}`;
        onOutput(`[!] ${msg}`);
        if (onWarning) onWarning(msg);
      }

      // 3. Try Gau
      onOutput(`[+] Searching with Gau...`);
      try {
        const gauProcess = spawn("bash", [
          "-c",
          `echo ${target} | ${TOOLS.GAU} | grep -E '\\.js$'`,
        ]);
        await this.streamOutput(
          gauProcess,
          (line) => {
            if (line.trim()) jsFiles.add(line.trim());
            onOutput(`[gau] ${line}`);
          }
        );
      } catch (err: any) {
        const msg = `Gau error (non-critical): ${err}`;
        onOutput(`[!] ${msg}`);
        if (onWarning) onWarning(msg);
      }

      onOutput(`[✓] Found ${jsFiles.size} JavaScript files`);
      return Array.from(jsFiles);
    } catch (error) {
      const msg = `Fatal error in JS discovery: ${error}`;
      onOutput(`[FATAL] ${msg}`);
      if (onWarning) onWarning(msg);
      return Array.from(jsFiles); // Return what we found so far
    }
  }

  /**
   * Scan JavaScript files for secrets using Nuclei
   */
  async scanForSecrets(
    jsUrls: string[],
    scanId: string,
    userId: string,
    onOutput: (line: string) => void
  ): Promise<SecretScanResult[]> {
    const secrets: SecretScanResult[] = [];

    onOutput(`[*] Scanning ${jsUrls.length} JS files for secrets...`);

    // Create temp file with URLs
    const tempFile = `/tmp/js_urls_${Date.now()}.txt`;
    fs.writeFileSync(tempFile, jsUrls.join("\n"));

    try {
      onOutput(`[+] Running Nuclei with secrets templates...`);
      const nucleiProcess = spawn(TOOLS.NUCLEI, [
        "-l",
        tempFile,
        "-t",
        "cves/",
        "-t",
        "exposures/",
        "-json",
      ]);

      await this.streamOutput(
        nucleiProcess,
        (line) => {
          try {
            const finding = JSON.parse(line);
            const result: SecretScanResult = {
              url: finding.host || "",
              secretType: finding.template || "unknown",
              value: finding.extracted_results?.[0] || finding.description || "",
              confidence: finding.severity || "medium",
              template: finding.template_id || "",
            };
            secrets.push(result);
            onOutput(
              `[SECRET] Found: ${result.secretType} in ${result.url}`
            );

            // Store in database
            this.storeSecret(scanId, userId, finding, result);
          } catch {
            onOutput(`[scan] ${line}`);
          }
        },
        (error) => onOutput(`[ERROR] ${error}`)
      );
    } catch (err) {
      onOutput(`[!] Nuclei scan error: ${err}`);
    } finally {
      // Cleanup
      fs.unlinkSync(tempFile);
    }

    onOutput(`[✓] Scan complete. Found ${secrets.length} potential secrets`);
    return secrets;
  }

  /**
   * Store secret finding in database
   */
  private async storeSecret(
    scanId: string,
    userId: string,
    nucleiFinding: any,
    result: SecretScanResult
  ) {
    try {
      await pool.query(
        `INSERT INTO secrets_found 
         (scan_id, user_id, source_url, js_file_url, secret_type, secret_value, 
          confidence, severity, template_id, nuclei_matcher)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          scanId,
          userId,
          nucleiFinding.host || "",
          result.url,
          result.secretType,
          result.value,
          result.confidence,
          nucleiFinding.severity || "medium",
          result.template,
          JSON.stringify(nucleiFinding),
        ]
      );
    } catch (error) {
      console.error("[SecretScan] Database store error:", error);
    }
  }

  /**
   * Full JS-Secret workflow: Crawl -> Extract JS -> Scan with Nuclei
   */
  async runFullSecretScan(
    target: string,
    scanId: string,
    userId: string,
    onOutput: (line: string) => void,
    onWarning?: (warning: string) => void,
    onError?: (error: string) => void
  ): Promise<SecretScanResult[]> {
    try {
      onOutput(`\n${"=".repeat(60)}`);
      onOutput(`[SCAN] Starting JS-Secret Workflow`);
      onOutput(`[TARGET] ${target}`);
      onOutput(`[SCAN_ID] ${scanId}`);
      onOutput(`${"=".repeat(60)}\n`);

      // Step 1: Extract JS files
      const jsFiles = await this.extractJavaScriptFiles(target, onOutput, onWarning);

      if (!jsFiles || jsFiles.length === 0) {
        onOutput(`[!] No JavaScript files found`);
        if (onWarning) onWarning(`No JS files discovered on target`);
        return [];
      }

      // Step 2: Scan for secrets
      const secrets = await this.scanForSecrets(
        jsFiles,
        scanId,
        userId,
        onOutput
      );

      if (!secrets || secrets.length === 0) {
        onOutput(`[*] No secrets found in discovered JS files`);
      }

      onOutput(`\n${"=".repeat(60)}`);
      onOutput(`[✓] SCAN COMPLETE`);
      onOutput(`[STATS] JS Files: ${jsFiles.length}`);
      onOutput(`[STATS] Secrets Found: ${secrets?.length || 0}`);
      onOutput(`${"=".repeat(60)}\n`);

      return secrets || [];
    } catch (error) {
      const msg = `SCAN FAILED: ${error}`;
      onOutput(`[FATAL] ${msg}`);
      if (onError) onError(msg);
      // Don't rethrow - allow graceful degradation
      return [];
    }
  }
}

export const secretScanService = new SecretScanService();
