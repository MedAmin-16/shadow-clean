import chalk from "chalk";
import Table from "cli-table3";

/**
 * Professional Modern Terminal Formatter for Security Scanner
 * Features: ASCII banner, neon colors, boxes, timestamps, icons, spinners, tables
 */

// Neon color palette
const colors = {
  neonBlue: chalk.hex("#00D9FF"),
  neonMagenta: chalk.hex("#FF00FF"),
  neonGreen: chalk.hex("#39FF14"),
  neonYellow: chalk.hex("#FFFF00"),
  neonRed: chalk.hex("#FF0040"),
  darkGray: chalk.hex("#333333"),
  brightWhite: chalk.white.bold,
};

// Unicode icons for different operations
const icons = {
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
  const banner = `
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║  ${colors.neonBlue("███████████████████████████████████████████████████████████████████")}  ║
║  ${colors.neonMagenta("███████████████████████████████████████████████████████████████████")}  ║
║                                                                            ║
║  ${colors.neonBlue.bold(toolName.padStart(Math.floor((70 + toolName.length) / 2)).padEnd(70))}  ║
║                                                                            ║
║  ${colors.neonGreen("Modern Security Scanner | Multi-Agent Reconnaissance Engine")}  ║
║                                                                            ║
║  ${colors.neonMagenta("███████████████████████████████████████████████████████████████████")}  ║
║  ${colors.neonBlue("███████████████████████████████████████████████████████████████████")}  ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝`;
  return banner;
}

/**
 * Create a boxed section for phase output
 */
export function createPhaseBox(phaseName: string, content: string, icon: string = icons.scan): string {
  const header = `${icon} ${colors.neonMagenta.bold(phaseName)}`;
  const lines = content.split("\n");
  const maxWidth = Math.max(...lines.map(l => l.length), header.length) + 4;
  
  const box = `
${colors.neonBlue("┌" + "─".repeat(maxWidth + 2) + "┐")}
${colors.neonBlue("│")} ${header.padEnd(maxWidth)} ${colors.neonBlue("│")}
${colors.neonBlue("├" + "─".repeat(maxWidth + 2) + "┤")}
${lines.map(line => colors.neonBlue("│") + " " + line.padEnd(maxWidth) + " " + colors.neonBlue("│")).join("\n")}
${colors.neonBlue("└" + "─".repeat(maxWidth + 2) + "┘")}`;
  
  return box;
}

/**
 * Log with consistent formatting: [HH:mm:ss] [PHASE] message
 */
export function logPhaseInfo(phase: string, message: string, icon: string = icons.info): void {
  console.log(`${getTimestamp()} ${colors.neonBlue(icon)} ${colors.neonBlue.bold(`[${phase}]`)} ${message}`);
}

/**
 * Log tool execution
 */
export function logToolExecution(phase: string, tool: string, args: string[]): void {
  const command = `${tool} ${args.join(" ")}`;
  console.log(`${getTimestamp()} ${colors.neonMagenta(icons.speed)} ${colors.neonMagenta.bold(`[${phase}]`)} Executing: ${colors.brightWhite(command)}`);
}

/**
 * Log finding/vulnerability
 */
export function logFinding(phase: string, title: string, severity: "critical" | "high" | "medium" | "low"): void {
  const severityColor = {
    critical: colors.neonRed,
    high: colors.neonYellow,
    medium: chalk.yellow,
    low: chalk.blue,
  }[severity];
  
  console.log(`${getTimestamp()} ${colors.neonRed(icons.fire)} ${colors.neonMagenta.bold(`[${phase}]`)} ${severityColor.bold(severity.toUpperCase())} ${title}`);
}

/**
 * Log success/completion
 */
export function logSuccess(phase: string, message: string): void {
  console.log(`${getTimestamp()} ${colors.neonGreen(icons.check)} ${colors.neonGreen.bold(`[${phase}]`)} ${colors.neonGreen(message)}`);
}

/**
 * Log warning
 */
export function logWarning(phase: string, message: string): void {
  console.log(`${getTimestamp()} ${colors.neonYellow(icons.warning)} ${colors.neonYellow.bold(`[${phase}]`)} ${message}`);
}

/**
 * Log error
 */
export function logError(phase: string, message: string): void {
  console.log(`${getTimestamp()} ${colors.neonRed(icons.error)} ${colors.neonRed.bold(`[${phase}]`)} ${message}`);
}

/**
 * Log discovery (subdomains, URLs, etc)
 */
export function logDiscovery(phase: string, count: number, type: string): void {
  console.log(`${getTimestamp()} ${colors.neonBlue(icons.discovery)} ${colors.neonBlue.bold(`[${phase}]`)} Discovered ${colors.neonGreen.bold(count.toString())} ${type}`);
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
      colors.neonMagenta.bold("METRIC"),
      colors.neonMagenta.bold("COUNT"),
      colors.neonMagenta.bold("STATUS"),
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
    ["Live Subdomains", colors.neonBlue.bold(data.subdomains.length.toString()), colors.neonGreen(icons.check)],
    ["Total URLs", colors.neonBlue.bold(data.totalUrls.toString()), colors.neonGreen(icons.check)],
    ["Total Vulnerabilities", colors.neonRed.bold(data.vulnerabilities.length.toString()), data.vulnerabilities.length > 0 ? colors.neonRed(icons.fire) : colors.neonGray("-")],
    ["🔴 Critical", colors.neonRed.bold(criticalCount.toString()), criticalCount > 0 ? colors.neonRed(icons.fire) : "-"],
    ["🟠 High", colors.neonYellow.bold(highCount.toString()), highCount > 0 ? colors.neonYellow(icons.warning) : "-"],
    ["🟡 Medium", chalk.yellow.bold(mediumCount.toString()), mediumCount > 0 ? chalk.yellow(icons.warning) : "-"],
    ["Errors", colors.neonRed.bold(data.errors.length.toString()), data.errors.length > 0 ? colors.neonRed(icons.error) : colors.neonGreen("-")],
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
  
  const report = `
${colors.neonGreen.bold("════════════════════════════════════════════════════════════════════════════")}
${colors.neonGreen.bold("█")} ${colors.neonGreen.bold("SCAN COMPLETE")} ${colors.neonGreen(icons.complete)}
${colors.neonGreen.bold("════════════════════════════════════════════════════════════════════════════")}

${colors.neonBlue("Target:")} ${colors.brightWhite(target)}
${colors.neonBlue("Duration:")} ${colors.brightWhite(durationSec + "s")}
${colors.neonBlue("Timestamp:")} ${colors.brightWhite(new Date().toISOString())}

${createSummaryTable(data)}

${colors.neonGreen.bold("════════════════════════════════════════════════════════════════════════════")}
${colors.neonMagenta("Ready for exploitation phase or report generation")}
${colors.neonGreen.bold("════════════════════════════════════════════════════════════════════════════")}`;

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

// Re-export colors and icons for use in other modules
export { colors, icons };
