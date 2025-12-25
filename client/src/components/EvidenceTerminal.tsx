import { useEffect, useRef, useState } from "react";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import "@fontsource/fira-code";
import { TerminalLog } from "./LiveTerminal";

interface EvidenceTerminalProps {
  logs: TerminalLog[];
  className?: string;
}

export function EvidenceTerminal({ logs, className }: EvidenceTerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Filter for confirmed vulnerabilities (Critical, High, Medium)
  const evidenceLogs = logs.filter(log => 
    log.type === "finding" || 
    log.message.includes("[CRITICAL]") || 
    log.message.includes("[HIGH]") || 
    log.message.includes("[MEDIUM]")
  );

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [evidenceLogs, autoScroll]);

  const handleScroll = () => {
    if (scrollRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
      const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
      setAutoScroll(isAtBottom);
    }
  };

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
    <div 
      style={{ 
        backgroundColor: "#000000", 
        border: "2px solid #BF40BF", 
        borderRadius: "0.5rem", 
        overflow: "hidden", 
        boxShadow: "0 0 20px rgba(191, 64, 191, 0.3)" 
      }} 
      className={cn("flex flex-col h-full", className)}
    >
      <div style={{ 
        padding: "1rem", 
        borderBottom: "1px solid #BF40BF", 
        display: "flex", 
        justifyContent: "space-between", 
        alignItems: "center", 
        backgroundColor: "rgba(191, 64, 191, 0.05)" 
      }}>
        <div style={{ 
          fontFamily: "'Fira Code', monospace", 
          color: "#BF40BF", 
          fontSize: "0.875rem", 
          fontWeight: "bold" 
        }}>
          <span>EVIDENCE_RECON_VAULT:~$ █</span>
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
          fontFamily: "'Fira Code', monospace",
          fontSize: "0.875rem",
          color: "#ffffff",
        }}
      >
        {evidenceLogs.length === 0 ? (
          <div style={{ color: "#BF40BF", opacity: 0.6 }}>
            <span>▸</span> Waiting for confirmed vulnerabilities...
          </div>
        ) : (
          evidenceLogs.map((log) => (
            <div
              key={log.id}
              style={{
                color: "#ffffff",
                display: "block",
                marginBottom: "0.75rem",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                padding: "0.5rem",
                borderLeft: "2px solid #BF40BF",
                backgroundColor: "rgba(191, 64, 191, 0.05)"
              }}
            >
              <div style={{ color: "#666666", fontSize: "0.75rem", marginBottom: "0.25rem" }}>
                {formatTimestamp(log.timestamp)} | CONFIRMED_VULN
              </div>
              <div style={{ color: "#FF0033", fontWeight: "bold" }}>
                {log.message}
              </div>
              {log.screenshot && (
                <div className="mt-3">
                  <a href={log.screenshot} target="_blank" rel="noopener noreferrer" className="block w-48 group">
                    <div className="relative overflow-hidden rounded border border-[#BF40BF]/30 bg-[#BF40BF]/5 aspect-video flex items-center justify-center">
                      <img 
                        src={log.screenshot} 
                        alt="Vulnerability Evidence" 
                        className="object-cover w-full h-full group-hover:scale-105 transition-transform duration-300"
                        onError={(e) => {
                          const target = e.target as HTMLImageElement;
                          target.style.display = 'none';
                          const parent = target.parentElement;
                          if (parent) {
                            parent.innerHTML = '<div class="text-[10px] text-[#BF40BF]/60 text-center p-2">📸 Screenshot Loading or Unavailable</div>';
                          }
                        }}
                      />
                      <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity">
                        <span className="text-[10px] text-white font-bold bg-[#BF40BF] px-2 py-0.5 rounded">VIEW FULL</span>
                      </div>
                    </div>
                  </a>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
