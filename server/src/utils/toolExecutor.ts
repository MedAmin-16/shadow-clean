import { spawn, execSync } from "child_process";
import { emitStdoutLog, emitExecLog } from "../sockets/socketManager";

/**
 * Execute a command and stream raw stdout line-by-line to socket
 * This bypasses any buffering and shows REAL tool output
 */
export async function executeToolWithStreaming(
  scanId: string,
  command: string,
  args: string[],
  agentLabel?: string,
  timeout: number = 30000
): Promise<{ stdout: string[]; stderr: string[]; exitCode: number }> {
  return new Promise((resolve) => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    
    // Emit the raw command being executed
    emitExecLog(scanId, `[${agentLabel || "TOOL"}] $ ${command} ${args.join(" ")}`, { 
      agentLabel 
    });

    const process = spawn(command, args, {
      timeout,
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });

    // Stream stdout line-by-line
    process.stdout?.on("data", (data: Buffer) => {
      const lines = data.toString().split("\n").filter(l => l.trim());
      lines.forEach((line) => {
        stdout.push(line);
        // CRITICAL: Emit EVERY line immediately with no buffering
        emitStdoutLog(scanId, `${line}`, { 
          agentLabel,
          type: "raw_tool_output"
        });
      });
    });

    // Stream stderr line-by-line (errors/warnings from tool)
    process.stderr?.on("data", (data: Buffer) => {
      const lines = data.toString().split("\n").filter(l => l.trim());
      lines.forEach((line) => {
        stderr.push(line);
        emitStdoutLog(scanId, `[ERROR] ${line}`, { 
          agentLabel,
          type: "raw_tool_error"
        });
      });
    });

    process.on("close", (exitCode) => {
      resolve({ stdout, stderr, exitCode: exitCode || 0 });
    });

    process.on("error", (error) => {
      emitStdoutLog(scanId, `[FATAL] Tool execution failed: ${error.message}`, { 
        agentLabel,
        type: "raw_tool_error"
      });
      resolve({ stdout, stderr, exitCode: 1 });
    });

    // Handle timeout
    setTimeout(() => {
      if (process.killed === false) {
        process.kill();
        emitStdoutLog(scanId, `[TIMEOUT] Tool execution exceeded ${timeout}ms`, { 
          agentLabel,
          type: "raw_tool_error"
        });
      }
    }, timeout);
  });
}

/**
 * Execute HTTP request and stream raw response to socket
 * Uses curl to make real HTTP requests with verbose output
 */
export async function executeHttpRequest(
  scanId: string,
  url: string,
  agentLabel: string,
  method: string = "GET",
  headers: Record<string, string> = {},
  data?: string
): Promise<string> {
  const curlArgs = [
    "-v", // Verbose: show headers, timing, etc.
    "-i", // Include response headers
    "--max-time", "10",
    "--connect-timeout", "5",
    "--insecure", // Allow self-signed certs
    "-X", method,
  ];

  // Add headers
  Object.entries(headers).forEach(([key, value]) => {
    curlArgs.push("-H", `${key}: ${value}`);
  });

  // Add data for POST/PUT
  if (data) {
    curlArgs.push("-d", data);
  }

  curlArgs.push(url);

  const result = await executeToolWithStreaming(scanId, "curl", curlArgs, agentLabel, 10000);
  return result.stdout.join("\n");
}

/**
 * Check if a target is reachable and get HTTP headers
 */
export async function probeHttpTarget(
  scanId: string,
  target: string,
  agentLabel: string
): Promise<{ reachable: boolean; headers: Record<string, string>; statusCode?: number }> {
  emitStdoutLog(scanId, `[${agentLabel}] Probing ${target}...`, { agentLabel });

  const url = target.startsWith("http") ? target : `https://${target}`;
  
  try {
    const result = await executeToolWithStreaming(
      scanId,
      "curl",
      ["-I", "-v", "--connect-timeout", "3", "--max-time", "5", "--insecure", url],
      agentLabel,
      5000
    );

    const output = result.stdout.join("\n");
    const headers: Record<string, string> = {};
    
    // Parse headers from curl -I output
    output.split("\n").forEach((line) => {
      if (line.includes(":") && !line.startsWith("<") && !line.startsWith(">")) {
        const [key, value] = line.split(":", 2);
        headers[key.trim()] = value.trim();
      }
    });

    return {
      reachable: result.exitCode === 0,
      headers,
      statusCode: extractStatusCode(output),
    };
  } catch (error) {
    return { reachable: false, headers: {} };
  }
}

function extractStatusCode(output: string): number | undefined {
  const match = output.match(/HTTP\/\d\.\d (\d{3})/);
  return match ? parseInt(match[1], 10) : undefined;
}

/**
 * Test a URL for SQL injection vulnerability
 * Uses curl to send test payloads and check responses
 */
export async function testSqlInjection(
  scanId: string,
  target: string,
  agentLabel: string
): Promise<{ vulnerable: boolean; evidence: string[] }> {
  emitStdoutLog(scanId, `[${agentLabel}] Testing for SQL injection...`, { agentLabel });

  const evidence: string[] = [];
  const testPayloads = [
    `' OR '1'='1`,
    `1' UNION SELECT NULL,NULL,NULL--`,
    `admin' --`,
    `' OR 1=1--`,
  ];

  const url = target.startsWith("http") ? target : `https://${target}`;
  
  // Test each payload
  for (const payload of testPayloads) {
    const encodedPayload = encodeURIComponent(payload);
    const testUrl = url.includes("?")
      ? `${url}&test=${encodedPayload}`
      : `${url}?test=${encodedPayload}`;

    const result = await executeToolWithStreaming(
      scanId,
      "curl",
      ["-s", "--max-time", "5", "--insecure", testUrl],
      agentLabel,
      5000
    );

    if (result.exitCode === 0) {
      const response = result.stdout.join("\n");
      // Look for SQL error indicators
      if (
        response.match(/SQL|syntax|database|mysql|postgres|sqlite/i) ||
        response.match(/error|exception|warning/i)
      ) {
        evidence.push(`Payload "${payload}" triggered error response`);
      }
    }
  }

  return {
    vulnerable: evidence.length > 0,
    evidence,
  };
}

/**
 * Test a URL for XSS vulnerability
 */
export async function testXss(
  scanId: string,
  target: string,
  agentLabel: string
): Promise<{ vulnerable: boolean; evidence: string[] }> {
  emitStdoutLog(scanId, `[${agentLabel}] Testing for XSS vulnerabilities...`, { agentLabel });

  const evidence: string[] = [];
  const xssPayloads = [
    "<script>alert('xss')</script>",
    "<img src=x onerror='alert(1)'>",
    "<svg onload=alert(1)>",
    "<iframe src='javascript:alert(1)'>",
  ];

  const url = target.startsWith("http") ? target : `https://${target}`;

  for (const payload of xssPayloads) {
    const encodedPayload = encodeURIComponent(payload);
    const testUrl = url.includes("?")
      ? `${url}&search=${encodedPayload}`
      : `${url}?search=${encodedPayload}`;

    const result = await executeToolWithStreaming(
      scanId,
      "curl",
      ["-s", "--max-time", "5", "--insecure", testUrl],
      agentLabel,
      5000
    );

    if (result.exitCode === 0) {
      const response = result.stdout.join("\n");
      // Check if payload appears unescaped in response
      if (response.includes(payload) || response.includes(payload.replace(/['"]/g, ""))) {
        evidence.push(`Payload "${payload}" reflected in response`);
      }
    }
  }

  return {
    vulnerable: evidence.length > 0,
    evidence,
  };
}
