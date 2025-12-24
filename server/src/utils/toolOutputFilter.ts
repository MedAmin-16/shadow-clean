/**
 * Smart Tool Output Filter
 * Filters verbose tool output to show ONLY important findings
 * Provides formatted output: [SUCCESS] target.com [200] [Title: Home] [Tech: PHP, Nginx]
 */

export interface FilteredOutput {
  importantLines: string[];
  summary: {
    findingsCount: number;
    successCount?: number;
  };
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
      
      const formattedLine = `[SUCCESS] ${url} [${statusCode}]${title !== "N/A" ? ` [Title: ${title}]` : ""}${tech ? ` [Tech: ${tech}]` : ""}`;
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
 * SQLMAP/COMMIX OUTPUT FILTER
 * Input: Raw tool output
 * Output: Only target URL, vulnerability found message, PoC payload
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

  lines.forEach((line, idx) => {
    // Skip noise
    if (noisePatterns.some(pattern => pattern.test(line))) {
      return;
    }

    // Vulnerability found
    if (line.match(/vulnerable|injection|rce|found|detected|exploitable/i)) {
      importantLines.push(`[FINDING] ${line.trim()}`);
      findingsCount++;
    }

    // PoC/Payload info
    if (line.includes("payload") && line.length < 150) {
      importantLines.push(`[PAYLOAD] ${line.trim()}`);
    }

    // Target URL
    if ((line.includes("http://") || line.includes("https://")) && line.length < 200) {
      importantLines.push(`[TARGET] ${line.trim()}`);
    }
  });

  return {
    importantLines,
    summary: { findingsCount }
  };
}

/**
 * NUCLEI OUTPUT FILTER
 * Input: JSON or text nuclei output
 * Output: Only critical findings with severity
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

    // Parse JSON findings
    if (line.startsWith("{") && line.includes("\"template-id\"")) {
      try {
        const finding = JSON.parse(line);
        const severity = finding.severity || "unknown";
        
        // Only show high/critical
        if (!severity.match(/low|medium/i)) {
          importantLines.push(
            `[CRITICAL-${severity.toUpperCase()}] ${finding.name || "Unknown"} on ${finding.matched_at || "N/A"}`
          );
          findingsCount++;
        }
      } catch {
        // Skip unparseable
      }
    }

    // Or plain text findings
    if (line.match(/\[critical\]|\[high\]|\[cve-/i)) {
      importantLines.push(`[FINDING] ${line.trim()}`);
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
    `[PROGRESS] Katana discovered ${urls.length} URLs from crawling`
  ];

  // Add sample of important URLs (those with parameters)
  const parameterizedUrls = urls.filter(url => url.includes("?") || url.includes("="));
  if (parameterizedUrls.length > 0) {
    importantLines.push(`[IMPORTANT] Found ${parameterizedUrls.length} URLs with parameters (key targets for vulnerability testing)`);
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
