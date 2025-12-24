import { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { Copy, Check } from "lucide-react";
import { VulnerabilityCounters, type VulnerabilityStats } from "./VulnerabilityCounters";

// Import Fira Code font from Google Fonts
import "@fontsource/fira-code";

export interface TerminalLog {
  id: string;
  timestamp: string;
  type: "exec" | "stdout" | "stderr" | "ai_thought" | "info" | "warning" | "error" | "progress" | "url_stream" | "phase_update" | "finding" | "poc_payload" | "poc_evidence" | "remediation" | "debug";
  message: string;
  command?: string;
  isAiLog?: boolean;
  phase?: "mapping" | "analyzing" | "exploiting" | "reporting";
  progress?: number;
  eta?: string;
  agentLabel?: string;
}

interface LiveTerminalProps {
  logs: TerminalLog[];
  isActive: boolean;
  planLevel: "STANDARD" | "PRO" | "ELITE";
  vulnStats?: VulnerabilityStats;
  className?: string;
}

const logStyles: Record<TerminalLog["type"], { prefix: string; color: string; bgColor: string }> = {
  exec: { prefix: "[SCAN]", color: "#00FFCC", bgColor: "rgba(0, 255, 204, 0.1)" },
  stdout: { prefix: "[INFO]", color: "#00FF00", bgColor: "rgba(0, 255, 0, 0.1)" },
  stderr: { prefix: "[ERROR]", color: "#FF0033", bgColor: "rgba(255, 0, 51, 0.1)" },
  ai_thought: { prefix: "[AI]", color: "#FF00FF", bgColor: "rgba(255, 0, 255, 0.1)" },
  info: { prefix: "[INFO]", color: "#00FFCC", bgColor: "rgba(0, 255, 204, 0.1)" },
  warning: { prefix: "[WARN]", color: "#FFAA00", bgColor: "rgba(255, 170, 0, 0.1)" },
  error: { prefix: "[ERROR]", color: "#FF0033", bgColor: "rgba(255, 0, 51, 0.1)" },
  progress: { prefix: "[PROGRESS]", color: "#00FF00", bgColor: "rgba(0, 255, 0, 0.1)" },
  url_stream: { prefix: "[CRAWLING]", color: "#00FFCC", bgColor: "rgba(0, 255, 204, 0.1)" },
  phase_update: { prefix: "[PHASE]", color: "#FFAA00", bgColor: "rgba(255, 170, 0, 0.1)" },
  finding: { prefix: "[CRITICAL]", color: "#FF0033", bgColor: "rgba(255, 0, 51, 0.2)" },
  poc_payload: { prefix: "[PAYLOAD]", color: "#00FF00", bgColor: "rgba(0, 255, 0, 0.1)" },
  poc_evidence: { prefix: "[EVIDENCE]", color: "#00FF00", bgColor: "rgba(0, 255, 0, 0.1)" },
  remediation: { prefix: "[FIX]", color: "#00FFCC", bgColor: "rgba(0, 255, 204, 0.1)" },
  debug: { prefix: "[DEBUG]", color: "#888888", bgColor: "rgba(136, 136, 136, 0.05)" },
};

// CRITICAL findings detection - BRIGHT RED highlighting
function isCriticalFinding(message: string): boolean {
  return message.match(/\[CRITICAL\]|\[HIGH\]|🚨|VULNERABILITY|SQL Injection|XSS/i) !== null;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  
  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  
  return (
    <button
      onClick={handleCopy}
      className="ml-2 p-1 hover:bg-green-500/20 rounded transition-colors"
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="w-4 h-4 text-green-400" />
      ) : (
        <Copy className="w-4 h-4 text-green-600 hover:text-green-400" />
      )}
    </button>
  );
}

function renderMessageWithLinks(message: string): JSX.Element {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const parts = message.split(urlRegex);
  
  return (
    <>
      {parts.map((part, idx) => 
        urlRegex.test(part) ? (
          <a
            key={idx}
            href={part}
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyan-300 hover:text-cyan-200 underline cursor-pointer"
          >
            {part}
          </a>
        ) : (
          <span key={idx}>{part}</span>
        )
      )}
    </>
  );
}

function BlinkingCursor() {
  return (
    <span className="animate-pulse inline-block w-2 h-4 bg-green-400 ml-1" />
  );
}

export function LiveTerminal({ logs, isActive, planLevel, vulnStats, className }: LiveTerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  const defaultStats: VulnerabilityStats = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  const displayStats = vulnStats || defaultStats;

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const handleScroll = () => {
    if (scrollRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
      const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
      setAutoScroll(isAtBottom);
    }
  };

  // TEMPORARILY: Show ALL logs regardless of plan level - debugging
  const filteredLogs = logs;
  
  console.log(`[TERMINAL] Rendering ${filteredLogs.length} logs, plan=${planLevel}`);

  const formatTimestamp = (ts: string) => {
    const date = new Date(ts);
    return date.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const badgeStyle = (logType: TerminalLog["type"]) => {
    const style = logStyles[logType];
    return {
      display: "inline-block",
      padding: "0.25rem 0.5rem",
      backgroundColor: style.bgColor,
      color: style.color,
      fontWeight: "bold",
      marginRight: "0.5rem",
      borderRadius: "2px",
      fontSize: "0.75rem",
      border: `1px solid ${style.color}`,
      textTransform: "uppercase" as const,
    };
  };

  return (
    <div style={{ backgroundColor: "#000000", border: "2px solid #00FFCC", borderRadius: "0.5rem", overflow: "hidden", boxShadow: "0 0 20px rgba(0, 255, 204, 0.3)" }} className={className}>
      <div style={{ padding: "1rem", borderBottom: "1px solid #00FFCC", display: "flex", justifyContent: "space-between", alignItems: "center", backgroundColor: "rgba(0, 255, 204, 0.05)" }}>
        <div style={{ fontFamily: "'Fira Code', monospace", color: "#00FFCC", fontSize: "0.875rem", fontWeight: "bold" }}>
          elite-scanner@swarm:~$ █
        </div>
        <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
          <span style={{ color: "#00FFCC", fontSize: "0.75rem", fontFamily: "'Fira Code', monospace", fontWeight: "bold" }}>
            {isActive ? "🔴 LIVE" : "⚪ IDLE"} | {planLevel}
          </span>
        </div>
      </div>

      <div style={{ padding: "1rem", backgroundColor: "#000000", borderBottom: "1px solid #00FFCC" }}>
        <VulnerabilityCounters stats={displayStats} />
      </div>
      
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        style={{
          height: "24rem",
          overflowY: "auto",
          padding: "1rem",
          backgroundColor: "#000000",
          fontFamily: "'Fira Code', monospace",
          fontSize: "0.875rem",
          color: "#ffffff",
        }}
      >
        {filteredLogs.length === 0 ? (
          <div style={{ color: "#00FFCC" }}>
            <span>▸</span> Initializing 14-Agent Reconnaissance Swarm...
          </div>
        ) : (
          filteredLogs.map((log) => (
            <div
              key={log.id}
              style={{
                color: "#ffffff",
                display: "block",
                marginBottom: "0.25rem",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                padding: "0.25rem 0.5rem",
              }}
            >
              <span style={{ color: "#666666", marginRight: "0.5rem", fontFamily: "'Fira Code', monospace" }}>
                {formatTimestamp(log.timestamp)}
              </span>
              <span style={badgeStyle(log.type)}>
                {logStyles[log.type].prefix}
              </span>
              {log.agentLabel && (
                <span style={{ color: "#00FFCC", marginRight: "0.5rem", fontWeight: "bold" }}>
                  [{log.agentLabel}]
                </span>
              )}
              <span style={{ color: "#FFFFFF" }}>
                {log.message}
              </span>
            </div>
          ))
        )}
        {isActive && filteredLogs.length > 0 && (
          <div style={{ color: "#00FFCC", marginTop: "0.5rem" }}>
            <span>▸</span>
          </div>
        )}
      </div>
    </div>
  );
}
