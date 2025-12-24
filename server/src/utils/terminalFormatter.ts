import Table from "cli-table3";

/**
 * Professional Modern Terminal Formatter for Security Scanner
 * Features: ASCII banner, ANSI colors, boxes, timestamps, icons, progress bars, tables
 */

// ANSI color codes - no external dependencies
const ANSI = {
  // Colors
  CYAN: "\x1b[36m",
  MAGENTA: "\x1b[35m",
  GREEN: "\x1b[32m",
  YELLOW: "\x1b[33m",
  RED: "\x1b[31m",
  GRAY: "\x1b[90m",
  WHITE: "\x1b[37m",
  BOLD: "\x1b[1m",
  RESET: "\x1b[0m",
};

// Neon color palette using ANSI codes
export const colors = {
  neonBlue: (text: string) => `${ANSI.CYAN}${ANSI.BOLD}${text}${ANSI.RESET}`,
  neonMagenta: (text: string) => `${ANSI.MAGENTA}${ANSI.BOLD}${text}${ANSI.RESET}`,
  neonGreen: (text: string) => `${ANSI.GREEN}${ANSI.BOLD}${text}${ANSI.RESET}`,
  neonYellow: (text: string) => `${ANSI.YELLOW}${ANSI.BOLD}${text}${ANSI.RESET}`,
  neonRed: (text: string) => `${ANSI.RED}${ANSI.BOLD}${text}${ANSI.RESET}`,
  darkGray: (text: string) => `${ANSI.GRAY}${text}${ANSI.RESET}`,
  brightWhite: (text: string) => `${ANSI.WHITE}${ANSI.BOLD}${text}${ANSI.RESET}`,
};

// Unicode icons for different operations
export const icons = {
  speed: "⚡",
  discovery: "🔍",
  injection: "💉",
  check: "✅",
  warning: "⚠️",
  error: "❌",
  info: "ℹ️",
  target: "🎯",
  shield: "🛡️",
  scan: "📊",
  complete: "🏁",
  fire: "🔥",
  star: "⭐",
  arrow: "→",
  loading: "⏳",
};

/**
 * Get formatted timestamp [HH:mm:ss]
 */
function getTimestamp(): string {
  const now = new Date();
  const hours = String(now.getHours()).padStart(2, "0");
  const minutes = String(now.getMinutes()).padStart(2, "0");
  const seconds = String(now.getSeconds()).padStart(2, "0");
  return colors.darkGray(`[${hours}:${minutes}:${seconds}]`);
}

/**
 * Create ASCII art banner with neon gradient effect
 */
export function createBanner(toolName: string = "ELITE-SCANNER"): string {
  const neonCyan = (text: string) => `${ANSI.CYAN}${ANSI.BOLD}${text}${ANSI.RESET}`;
  const banner = `
${neonCyan("╔════════════════════════════════════════════════════════════════════════════╗")}
${neonCyan("║")}                                                                            ${neonCyan("║")}
${colors.neonMagenta("║  ███████████████████████████████████████████████████████████████████  ║")}
${colors.neonMagenta("║  ███████████████████████████████████████████████████████████████████  ║")}
${neonCyan("║")}                                                                            ${neonCyan("║")}
${neonCyan("║")}  ${colors.neonGreen(toolName.padStart(Math.floor((70 + toolName.length) / 2)).padEnd(70))}  ${neonCyan("║")}
${neonCyan("║")}                                                                            ${neonCyan("║")}
${colors.neonGreen("║  Modern Security Scanner | Multi-Agent Reconnaissance Engine              ║")}
${neonCyan("║")}                                                                            ${neonCyan("║")}
${colors.neonMagenta("║  ███████████████████████████████████████████████████████████████████  ║")}
${colors.neonMagenta("║  ███████████████████████████████████████████████████████████████████  ║")}
${neonCyan("║")}                                                                            ${neonCyan("║")}
${neonCyan("╚════════════════════════════════════════════════════════════════════════════╝")}`;
  return banner;
}

/**
 * Log with consistent formatting: [HH:mm:ss] [PHASE] message
 */
export function logPhaseInfo(phase: string, message: string, icon: string = icons.info): void {
  console.log(`${getTimestamp()} ${icon} ${colors.neonBlue(`[${phase}]`)} ${message}`);
}

/**
 * Log tool execution
 */
export function logToolExecution(phase: string, tool: string, args: string[]): void {
  const command = `${tool} ${args.join(" ")}`;
  console.log(`${getTimestamp()} ${colors.neonMagenta(icons.speed)} ${colors.neonMagenta(`[${phase}]`)} Executing: ${colors.brightWhite(command)}`);
}

/**
 * Log finding/vulnerability
 */
export function logFinding(phase: string, title: string, severity: "critical" | "high" | "medium" | "low"): void {
  const severityColor = {
    critical: colors.neonRed,
    high: colors.neonYellow,
    medium: (s: string) => `${ANSI.YELLOW}${s}${ANSI.RESET}`,
    low: (s: string) => `${ANSI.CYAN}${s}${ANSI.RESET}`,
  }[severity];
  
  console.log(`${getTimestamp()} ${colors.neonRed(icons.fire)} ${colors.neonMagenta(`[${phase}]`)} ${severityColor(severity.toUpperCase())} ${title}`);
}

/**
 * Log success/completion
 */
export function logSuccess(phase: string, message: string): void {
  console.log(`${getTimestamp()} ${colors.neonGreen(icons.check)} ${colors.neonGreen(`[${phase}]`)} ${colors.neonGreen(message)}`);
}

/**
 * Log warning
 */
export function logWarning(phase: string, message: string): void {
  console.log(`${getTimestamp()} ${colors.neonYellow(icons.warning)} ${colors.neonYellow(`[${phase}]`)} ${message}`);
}

/**
 * Log error
 */
export function logError(phase: string, message: string): void {
  console.log(`${getTimestamp()} ${colors.neonRed(icons.error)} ${colors.neonRed(`[${phase}]`)} ${message}`);
}

/**
 * Log discovery (subdomains, URLs, etc)
 */
export function logDiscovery(phase: string, count: number, type: string): void {
  console.log(`${getTimestamp()} ${colors.neonBlue(icons.discovery)} ${colors.neonBlue(`[${phase}]`)} Discovered ${colors.neonGreen(count.toString())} ${type}`);
}

/**
 * Create summary table for scan results
 */
export function createSummaryTable(data: {
  subdomains: string[];
  totalUrls: number;
  vulnerabilities: Array<{ title: string; severity: string; type: string }>;
  errors: string[];
}): string {
  const table = new Table({
    head: [
      colors.neonMagenta("METRIC"),
      colors.neonMagenta("COUNT"),
      colors.neonMagenta("STATUS"),
    ],
    style: {
      head: [],
      border: ["cyan"],
    },
  });

  // Count vulnerabilities by severity
  const criticalCount = data.vulnerabilities.filter(v => v.severity === "critical").length;
  const highCount = data.vulnerabilities.filter(v => v.severity === "high").length;
  const mediumCount = data.vulnerabilities.filter(v => v.severity === "medium").length;

  table.push(
    ["Live Subdomains", colors.neonBlue(data.subdomains.length.toString()), colors.neonGreen(icons.check)],
    ["Total URLs", colors.neonBlue(data.totalUrls.toString()), colors.neonGreen(icons.check)],
    ["Total Vulnerabilities", colors.neonRed(data.vulnerabilities.length.toString()), data.vulnerabilities.length > 0 ? colors.neonRed(icons.fire) : "-"],
    ["🔴 Critical", colors.neonRed(criticalCount.toString()), criticalCount > 0 ? colors.neonRed(icons.fire) : "-"],
    ["🟠 High", colors.neonYellow(highCount.toString()), highCount > 0 ? colors.neonYellow(icons.warning) : "-"],
    ["🟡 Medium", `${ANSI.YELLOW}${ANSI.BOLD}${mediumCount}${ANSI.RESET}`, mediumCount > 0 ? colors.neonYellow(icons.warning) : "-"],
    ["Errors", colors.neonRed(data.errors.length.toString()), data.errors.length > 0 ? colors.neonRed(icons.error) : colors.neonGreen("-")],
  );

  return table.toString();
}

/**
 * Create final summary report
 */
export function createFinalReport(
  target: string,
  data: {
    subdomains: string[];
    totalUrls: number;
    vulnerabilities: any[];
    errors: string[];
    metadata?: Record<string, any>;
  },
  duration: number
): string {
  const durationSec = (duration / 1000).toFixed(2);
  const neonCyan = (text: string) => `${ANSI.CYAN}${ANSI.BOLD}${text}${ANSI.RESET}`;
  
  const report = `
${colors.neonGreen("════════════════════════════════════════════════════════════════════════════")}
${colors.neonGreen("█")} ${colors.neonGreen("SCAN COMPLETE")} ${icons.complete}
${colors.neonGreen("════════════════════════════════════════════════════════════════════════════")}

${colors.neonBlue("Target:")} ${colors.brightWhite(target)}
${colors.neonBlue("Duration:")} ${colors.brightWhite(durationSec + "s")}
${colors.neonBlue("Timestamp:")} ${colors.brightWhite(new Date().toISOString())}

${createSummaryTable(data)}

${colors.neonGreen("════════════════════════════════════════════════════════════════════════════")}
${colors.neonMagenta("Ready for exploitation phase or report generation")}
${colors.neonGreen("════════════════════════════════════════════════════════════════════════════")}`;

  return report;
}

/**
 * Create progress line with stats
 */
export function createProgressLine(current: number, total: number, label: string): string {
  const percentage = Math.round((current / total) * 100);
  const barLength = 20;
  const filledLength = Math.round((percentage / 100) * barLength);
  const emptyLength = barLength - filledLength;
  
  const bar = colors.neonGreen("█".repeat(filledLength)) + colors.darkGray("░".repeat(emptyLength));
  return `${label}: ${bar} ${percentage}% (${current}/${total})`;
}
