import { useEffect, useState } from "react";
import { Terminal, Zap } from "lucide-react";

interface LiveScanWidgetProps {
  scanId?: string | null;
  isActive?: boolean;
}

export function LiveScanWidget({ scanId, isActive = false }: LiveScanWidgetProps) {
  const [logs, setLogs] = useState<string[]>([]);

  useEffect(() => {
    if (!scanId) {
      setLogs([
        "[SYSTEM] Ready for elite secret scans...",
        "[AWAITING] Scan trigger from dashboard",
        "[STATUS] All 8 tools operational",
      ]);
      return;
    }

    // Fetch logs for this scan
    const fetchLogs = async () => {
      try {
        const response = await fetch(`/api/secret-scan/results/${scanId}`);
        const data = await response.json();
        if (data.logs) {
          setLogs(data.logs);
        }
      } catch (error) {
        console.error("Failed to fetch logs", error);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 1000);
    return () => clearInterval(interval);
  }, [scanId]);

  return (
    <div className="relative bg-black/80 border border-cyan-500/30 rounded-lg overflow-hidden shadow-2xl shadow-cyan-500/20">
      {/* Neon glow effect */}
      {isActive && (
        <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 to-green-500/10 animate-pulse pointer-events-none" />
      )}

      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-cyan-500/20 bg-black/50">
        <Terminal className="w-5 h-5 text-cyan-400 animate-pulse" />
        <h3 className="text-sm font-mono font-bold text-cyan-300">ELITE SCAN TERMINAL</h3>
        {isActive && (
          <>
            <Zap className="w-4 h-4 text-green-400 ml-auto animate-pulse" />
            <span className="text-xs font-mono text-green-400">LIVE</span>
          </>
        )}
      </div>

      {/* Terminal content */}
      <div className="p-4 font-mono text-xs space-y-1 max-h-64 overflow-y-auto scrollbar-thin scrollbar-track-black/50 scrollbar-thumb-cyan-500/50">
        {logs.length === 0 ? (
          <div className="text-gray-500 animate-pulse">[WAITING] No scan active...</div>
        ) : (
          logs.map((log, idx) => (
            <div key={idx} className="text-cyan-300 break-words">
              <span className="text-green-400">{log.split("]")[0]}]</span>
              {log.substring(log.indexOf("]") + 1)}
            </div>
          ))
        )}
      </div>

      {/* Status bar */}
      <div className="px-4 py-2 border-t border-cyan-500/20 bg-black/50 text-xs text-gray-400 flex justify-between">
        <span className="font-mono">{isActive ? "▌ STREAMING" : "◯ IDLE"}</span>
        <span>{new Date().toLocaleTimeString()}</span>
      </div>
    </div>
  );
}
