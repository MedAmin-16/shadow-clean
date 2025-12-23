type LogLevel = "info" | "warn" | "error" | "debug";

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  source: string;
  message: string;
  data?: Record<string, unknown>;
}

const logs: LogEntry[] = [];
const MAX_LOGS = 10000;

export function createLogger(source: string) {
  return {
    info: (message: string, data?: Record<string, unknown>) => logMessage("info", source, message, data),
    warn: (message: string, data?: Record<string, unknown>) => logMessage("warn", source, message, data),
    error: (message: string, data?: Record<string, unknown>) => logMessage("error", source, message, data),
    debug: (message: string, data?: Record<string, unknown>) => logMessage("debug", source, message, data),
  };
}

function logMessage(level: LogLevel, source: string, message: string, data?: Record<string, unknown>) {
  const timestamp = new Date().toISOString();
  const entry: LogEntry = { timestamp, level, source, message, data };
  
  logs.push(entry);
  if (logs.length > MAX_LOGS) {
    logs.shift();
  }

  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  const levelColors: Record<LogLevel, string> = {
    info: "\x1b[36m",
    warn: "\x1b[33m",
    error: "\x1b[31m",
    debug: "\x1b[90m",
  };
  const reset = "\x1b[0m";

  console.log(`${formattedTime} ${levelColors[level]}[${source}]${reset} ${message}`);
  if (data) {
    console.log(`  ${JSON.stringify(data)}`);
  }
}

export function getLogs(options?: { level?: LogLevel; source?: string; limit?: number }): LogEntry[] {
  let filtered = [...logs];
  
  if (options?.level) {
    filtered = filtered.filter((l) => l.level === options.level);
  }
  if (options?.source) {
    filtered = filtered.filter((l) => l.source === options.source);
  }
  if (options?.limit) {
    filtered = filtered.slice(-options.limit);
  }
  
  return filtered;
}
