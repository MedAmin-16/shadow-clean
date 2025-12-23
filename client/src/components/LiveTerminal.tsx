import { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { Copy, Check } from "lucide-react";

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
  className?: string;
}

const logStyles: Record<TerminalLog["type"], { prefix: string; color: string }> = {
  exec: { prefix: "[EXEC]", color: "text-cyan-400" },
  stdout: { prefix: "[STDOUT]", color: "text-green-400" },
  stderr: { prefix: "[STDERR]", color: "text-red-400" },
  ai_thought: { prefix: "[AI THOUGHT]", color: "text-purple-400" },
  info: { prefix: "[INFO]", color: "text-blue-400" },
  warning: { prefix: "[WARN]", color: "text-yellow-400" },
  error: { prefix: "[ERROR]", color: "text-red-500" },
  progress: { prefix: "[PROGRESS]", color: "text-green-400" },
  url_stream: { prefix: "[CRAWLING]", color: "text-cyan-400" },
  phase_update: { prefix: "[PHASE]", color: "text-yellow-400" },
  finding: { prefix: "[FINDING]", color: "text-red-600 drop-shadow-[0_0_15px_rgba(220,38,38,1)] font-black" },
  poc_payload: { prefix: "[PoC PAYLOAD]", color: "text-green-400" },
  poc_evidence: { prefix: "[EVIDENCE]", color: "text-green-400" },
  remediation: { prefix: "[REMEDIATION]", color: "text-cyan-300" },
  debug: { prefix: "[DEBUG]", color: "text-gray-500" },
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

export function LiveTerminal({ logs, isActive, planLevel, className }: LiveTerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

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

  return (
    <div style={{ backgroundColor: "#000000", border: "1px solid #164e3f", borderRadius: "0.5rem", overflow: "hidden" }} className={className}>
      <div style={{ padding: "1rem", borderBottom: "1px solid #164e3f", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontFamily: "monospace", color: "#4ade80", fontSize: "0.875rem" }}>
          shadowtwin@swarm:~$ ▌
        </div>
        <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
          <span style={{ color: "#22c55e", fontSize: "0.75rem" }}>
            {isActive ? "LIVE" : "IDLE"} | {planLevel}
          </span>
        </div>
      </div>
      
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        style={{
          height: "24rem",
          overflowY: "auto",
          padding: "1rem",
          backgroundColor: "#000000",
          fontFamily: "monospace",
          fontSize: "0.875rem",
          color: "#ffffff",
        }}
      >
        {filteredLogs.length === 0 ? (
          <div style={{ color: "#15803d" }}>
            <span>▸</span> Initializing 10-Agent Swarm...
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
              }}
            >
              <span style={{ color: "#15803d", marginRight: "0.5rem" }}>
                {formatTimestamp(log.timestamp)}
              </span>
              <span style={{ color: "#22c55e", fontWeight: "bold" }}>
                [{log.type}]:
              </span>
              {" "}
              <span style={{ color: "#d1d5db" }}>
                {log.message}
              </span>
            </div>
          ))
        )}
        {isActive && filteredLogs.length > 0 && (
          <div style={{ color: "#22c55e", marginTop: "0.5rem" }}>
            <span>▸</span>
          </div>
        )}
      </div>
    </div>
  );
}
