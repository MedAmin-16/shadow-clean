import { useEffect, useState, useCallback, useRef } from "react";
import { io, Socket } from "socket.io-client";
import type { TerminalLog } from "@/components/LiveTerminal";

interface UseTerminalOptions {
  scanId: string | null;
  userId?: string;
  enabled?: boolean;
}

export interface VulnerabilityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface UseTerminalReturn {
  logs: TerminalLog[];
  isConnected: boolean;
  clearLogs: () => void;
  vulnStats: VulnerabilityStats;
}

export function useTerminal({ scanId, userId, enabled = true }: UseTerminalOptions): UseTerminalReturn {
  const [logs, setLogs] = useState<TerminalLog[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [vulnStats, setVulnStats] = useState<VulnerabilityStats>({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });
  const socketRef = useRef<Socket | null>(null);

  const clearLogs = useCallback(() => {
    setLogs([]);
  }, []);

  useEffect(() => {
    if (!enabled || !scanId) {
      return;
    }

    const socket = io({
      path: "/socket.io",
      transports: ["websocket", "polling"],
    });

    socketRef.current = socket;

    socket.on("connect", () => {
      console.log("✅ [SOCKET] Connected to server");
      setIsConnected(true);
      
      if (userId) {
        console.log(`✅ [SOCKET] Authenticating as user: ${userId}`);
        socket.emit("authenticate", userId);
      }
      
      console.log(`✅ [SOCKET] Subscribing to scan: ${scanId}`);
      socket.emit("subscribe:scan", scanId);
    });

    socket.on("disconnect", () => {
      setIsConnected(false);
    });

    socket.on("terminal:log", (data: TerminalLog & { scanId: string }) => {
      console.log("✅ [SOCKET] terminal:log received:", { scanId, incomingScanId: data.scanId, message: data.message.substring(0, 80) });
      if (data.scanId === scanId) {
        console.log("✅ [SOCKET] Adding log to state - Total logs now:", logs.length + 1);
        const newLog: TerminalLog = {
          id: data.id || `log-${Date.now()}-${Math.random()}`,
          timestamp: data.timestamp || new Date().toISOString(),
          type: data.type || "stdout",
          message: data.message || "",
          command: data.command,
          isAiLog: data.isAiLog ?? false,
          agentLabel: data.agentLabel,
        };
        console.log("✅ [STATE] Updated - new log object:", newLog);
        setLogs((prev) => {
          const updated = [...prev, newLog];
          console.log("✅ [STATE] Logs array now has", updated.length, "items");
          return updated;
        });
      }
    });

    socket.on("vulnerability:stats", (data: { scanId: string; stats: VulnerabilityStats }) => {
      if (data.scanId === scanId) {
        console.log("✅ [SOCKET] Vulnerability stats updated:", data.stats);
        setVulnStats(data.stats);
      }
    });

    return () => {
      if (socketRef.current) {
        socketRef.current.emit("unsubscribe:scan", scanId);
        socketRef.current.disconnect();
        socketRef.current = null;
      }
    };
  }, [scanId, userId, enabled]);

  useEffect(() => {
    if (scanId) {
      setLogs([]);
    }
  }, [scanId]);

  return {
    logs,
    isConnected,
    clearLogs,
    vulnStats,
  };
}
