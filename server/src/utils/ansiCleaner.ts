/**
 * Strip ANSI color codes from strings before sending to web frontend
 * Prevents raw escape sequences like [36m from appearing in terminal
 */

const ANSI_PATTERN = /\x1b\[[0-9;]*m/g;

export function stripAnsi(text: string): string {
  if (!text) return text;
  return text.replace(ANSI_PATTERN, "");
}

export function cleanTerminalOutput(lines: string[]): string[] {
  return lines.map((line) => stripAnsi(line));
}
