/**
 * Smart Tool Output Filter
 * Shows ALL vulnerabilities from Low to Critical with color-coded severity badges
 * Format: [Severity Badge] [Tool] Target -> Finding Name
 */

// ANSI color codes
const ANSI = {
  RED_BG: "\x1b[41m",
  RED: "\x1b[31m",
  YELLOW: "\x1b[33m",
  GREEN: "\x1b[32m",
  CYAN: "\x1b[36m",
  WHITE: "\x1b[37m",
  BOLD: "\x1b[1m",
  RESET: "\x1b[0m",
};

// Severity icon map
const SEVERITY_ICONS: Record<string, string> = {
  critical: "☢️",
  high: "🔥",
  medium: "🟡",
  low: "🛡️",
  info: "ℹ️",
};

export interface FilteredOutput {
  importantLines: string[];
  summary: {
    findingsCount: number;
    successCount?: number;
  };
}

/**
 * Format a severity badge with color coding
 */
function formatSeverityBadge(severity: string): string {
  const lower = severity.toLowerCase();
  const icon = SEVERITY_ICONS[lower] || "ℹ️";
  
  if (lower === "critical") {
    // Red background with white text
    return `${ANSI.RED_BG}${ANSI.WHITE}${ANSI.BOLD} [ ${icon} CRITICAL ]${ANSI.RESET}`;
  } else if (lower === "high") {
    // Red text with bold
    return `${ANSI.RED}${ANSI.BOLD}[ ${icon} HIGH ]${ANSI.RESET}`;
  } else if (lower === "medium") {
    // Yellow text with bold
    return `${ANSI.YELLOW}${ANSI.BOLD}[ ${icon} MEDIUM ]${ANSI.RESET}`;
  } else if (lower === "low") {
    // Green text with bold
    return `${ANSI.GREEN}${ANSI.BOLD}[ ${icon} LOW ]${ANSI.RESET}`;
  } else {
    // Cyan for info
    return `${ANSI.CYAN}[ ${icon} INFO ]${ANSI.RESET}`;
  }
}

/**
 * HTTPX OUTPUT FILTER
 * Input: Raw httpx output with verbose lines
 * Output: Clean summary: [SUCCESS] url [200] [Title: ...] [Tech: ...]
 */
export function filterHttpxOutput(output: string, agentLabel: string = "HTTPX"): FilteredOutput {
  const lines = output.split("\n").filter(l => l.trim());
  const importantLines: string[] = [];
  let successCount = 0;

  lines.forEach(line => {
    // Skip verbose/noise lines
    if (line.includes("Using config") || line.includes("time=") || line.includes("rtt=") || 
        line.includes("elapsed") || line.includes("ms\">") || line.match(/^\[.*\]\s*\[.*\]/)) {
      return;
    }

    // Extract important info: URL, Status Code, Title, Tech
    if ((line.includes("http://") || line.includes("https://")) && 
        (line.includes("[") || line.match(/\d{3}/))) {
      
      const statusMatch = line.match(/\[(\d{3})\]/);
      const statusCode = statusMatch ? statusMatch[1] : "?";
      const titleMatch = line.match(/\[title:([^\]]+)\]/i) || line.match(/title="([^"]+)"/i);
      const title = titleMatch ? titleMatch[1].trim() : "N/A";
      const techMatch = line.match(/\[tech:([^\]]+)\]/i);
      const tech = techMatch ? techMatch[1].trim() : "";

      const url = line.match(/(https?:\/\/[^\s\[]+)/)?.[1] || line.split(/[\[\s]/)[0];
      
      const formattedLine = `${formatSeverityBadge("INFO")} [HTTPX] ${url} [${statusCode}]${title !== "N/A" ? ` [Title: ${title}]` : ""}${tech ? ` [Tech: ${tech}]` : ""}`;
      importantLines.push(formattedLine);
      successCount++;
    }
  });

  return {
    importantLines,
    summary: { findingsCount: importantLines.length, successCount: successCount }
  };
}

/**
 * SQLMAP/COMMIX OUTPUT FILTER - SHOW ALL FINDINGS
 * Input: Raw tool output
 * Output: All vulnerabilities with severity badges
 */
export function filterVulnToolOutput(output: string, tool: string = "TOOL"): FilteredOutput {
  const lines = output.split("\n").filter(l => l.trim());
  const importantLines: string[] = [];
  let findingsCount = 0;

  // Skip lines with noise
  const noisePatterns = [
    /testing parameter/i,
    /trying payload/i,
    /testing\s\*/i,
    /request\s#/i,
    /starting\s/i,
    /level=|risk=/i,
    /\(press enter to continue\)/i,
    /^---+$/,
    /^\[.*\]\s+$/,
  ];

  let currentTarget = "";
  let currentSeverity = "MEDIUM";

  lines.forEach((line) => {
    // Skip noise
    if (noisePatterns.some(pattern => pattern.test(line))) {
      return;
    }

    // Extract target URL
    if ((line.includes("http://") || line.includes("https://")) && line.length < 200) {
      currentTarget = line.trim();
      return;
    }

    // Determine severity and extract vulnerability info
    if (line.match(/vulnerable|injectable/i)) {
      currentSeverity = "CRITICAL";
    } else if (line.match(/rce|remote code execution/i)) {
      currentSeverity = "CRITICAL";
    } else if (line.match(/injection|xss/i)) {
      currentSeverity = "HIGH";
    } else if (line.match(/weakness|issue/i)) {
      currentSeverity = "MEDIUM";
    } else if (line.match(/informational|info/i)) {
      currentSeverity = "LOW";
    }

    // Log vulnerability findings
    if (line.match(/vulnerable|injection|rce|found|detected|exploitable|weakness|issue/i)) {
      const target = currentTarget || "unknown-target";
      const findingName = line.replace(/\s*\(.*?\)\s*/g, "").trim();
      importantLines.push(
        `${formatSeverityBadge(currentSeverity)} [${tool.toUpperCase()}] ${target} -> ${findingName}`
      );
      findingsCount++;
    }

    // Show payloads and evidence
    if (line.includes("payload") || line.includes("evidence") || line.match(/proof|poc/i)) {
      if (line.length < 150) {
        importantLines.push(`${formatSeverityBadge("INFO")} [${tool.toUpperCase()}] PoC/Payload: ${line.trim()}`);
      }
    }
  });

  return {
    importantLines,
    summary: { findingsCount }
  };
}

/**
 * NUCLEI OUTPUT FILTER - SHOW ALL FINDINGS WITH TEMPLATE IDs
 * Input: JSON or text nuclei output
 * Output: ALL findings (low to critical) with color-coded severity, template ID, and details
 */
export function filterNucleiOutput(output: string): FilteredOutput {
  const lines = output.split("\n").filter(l => l.trim());
  const importantLines: string[] = [];
  let findingsCount = 0;

  lines.forEach(line => {
    // Skip progress/info lines
    if (line.includes("templates loaded") || line.includes("rate limit") || 
        line.match(/^\[\d+:\d+:\d+\]/)) {
      return;
    }

    // Parse JSON findings - SHOW ALL SEVERITIES
    if (line.startsWith("{") && line.includes("\"template-id\"")) {
      try {
        const finding = JSON.parse(line);
        const severity = (finding.severity || "low").toLowerCase();
        const templateId = finding["template-id"] || "unknown";
        const name = finding.name || "Unknown";
        const target = finding.matched_at || finding.host || "N/A";

        // Show ALL severity levels
        importantLines.push(
          `${formatSeverityBadge(severity)} [NUCLEI] ${target} -> ${name} [Template: ${templateId}]`
        );
        findingsCount++;
      } catch {
        // Skip unparseable JSON
      }
    }

    // Handle plain text findings
    if (line.match(/\[critical\]|\[high\]|\[medium\]|\[low\]|\[cve-/i)) {
      const severityMatch = line.match(/\[(critical|high|medium|low)\]/i);
      const severity = severityMatch ? severityMatch[1] : "medium";
      importantLines.push(`${formatSeverityBadge(severity)} [NUCLEI] ${line.trim()}`);
      findingsCount++;
    }
  });

  return {
    importantLines,
    summary: { findingsCount }
  };
}

/**
 * KATANA OUTPUT FILTER
 * Input: Raw katana output (many URLs)
 * Output: Progress bar + summary only
 */
export function filterKatanaOutput(output: string, agentLabel: string = "KATANA"): FilteredOutput {
  const lines = output.split("\n").filter(l => l.trim());
  const urls = lines.filter(l => l.match(/^https?:\/\//));
  
  // Only emit summary, not individual URLs
  const importantLines = [
    `${formatSeverityBadge("INFO")} [KATANA] Discovered ${urls.length} URLs from crawling`
  ];

  // Add sample of important URLs (those with parameters)
  const parameterizedUrls = urls.filter(url => url.includes("?") || url.includes("="));
  if (parameterizedUrls.length > 0) {
    importantLines.push(
      `${formatSeverityBadge("HIGH")} [KATANA] Found ${parameterizedUrls.length} URLs with parameters (key targets for vulnerability testing)`
    );
  }

  return {
    importantLines,
    summary: { findingsCount: urls.length }
  };
}

/**
 * Apply filtering based on tool
 */
export function filterToolOutput(tool: string, output: string, agentLabel: string = ""): FilteredOutput {
  switch (tool.toLowerCase()) {
    case "httpx":
      return filterHttpxOutput(output, agentLabel || "HTTPX");
    case "sqlmap":
    case "commix":
      return filterVulnToolOutput(output, tool);
    case "nuclei":
      return filterNucleiOutput(output);
    case "katana":
      return filterKatanaOutput(output, agentLabel || "KATANA");
    default:
      // For unknown tools, just return all non-empty lines
      return {
        importantLines: output.split("\n").filter(l => l.trim()),
        summary: { findingsCount: 0 }
      };
  }
}
