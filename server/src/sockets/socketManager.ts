import { Server as SocketServer, Socket } from "socket.io";
import type { Server as HttpServer } from "http";
import type { NotificationPayload } from "../types";
import type { PlanLevel } from "@shared/schema";
import { createLogger } from "../utils/logger";
import { storage } from "../../storage";
import { stripAnsi } from "../utils/ansiCleaner";

const logger = createLogger("socket");

let io: SocketServer | null = null;
const userSockets = new Map<string, Set<string>>();
const userPlanLevels = new Map<string, PlanLevel>();
const socketToUser = new Map<string, string>();
const logBuffer = new Map<string, TerminalLogPayload[]>(); // Buffer last 10 logs per scan
const vulnStats = new Map<string, { critical: number; high: number; medium: number; low: number }>(); // Track vulnerability counts per scan

export function initSocketServer(httpServer: HttpServer): SocketServer {
  io = new SocketServer(httpServer, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"],
    },
    path: "/socket.io",
  });

  io.on("connection", (socket: Socket) => {
    logger.info(`Client connected: ${socket.id}`);

    // Heartbeat mechanism to keep terminal alive
    const heartbeatInterval = setInterval(() => {
      if (socket.connected) {
        socket.emit("terminal:log", {
          id: `hb-${Date.now()}`,
          timestamp: new Date().toISOString(),
          type: "info",
          message: "[SYSTEM] Keep-Alive: Connection Active",
          isAiLog: false,
        });
      } else {
        clearInterval(heartbeatInterval);
      }
    }, 15000);

    socket.on("authenticate", async (userId: string) => {
      if (!userId) return;

      if (!userSockets.has(userId)) {
        userSockets.set(userId, new Set());
      }
      userSockets.get(userId)!.add(socket.id);
      socketToUser.set(socket.id, userId);
      socket.join(`user:${userId}`);
      
      try {
        const userCredits = await storage.getUserCredits(userId);
        const planLevel = userCredits.planLevel as PlanLevel;
        userPlanLevels.set(userId, planLevel);
        socket.join(`plan:${planLevel}`);
        logger.info(`User ${userId} authenticated on socket ${socket.id} with plan ${planLevel}`);
      } catch (error) {
        logger.warn(`Could not get plan level for user ${userId}`);
        userPlanLevels.set(userId, "PRO");
        socket.join(`plan:PRO`);
      }
    });

    socket.on("subscribe:scan", (jobId: string) => {
      socket.join(`scan:${jobId}`);
      logger.debug(`Socket ${socket.id} subscribed to scan ${jobId}`);
      
      // Send buffered logs immediately upon subscription
      const bufferedLogs = logBuffer.get(jobId) || [];
      console.log(`[SOCKET] Sending ${bufferedLogs.length} buffered logs to ${socket.id} for scan ${jobId}`);
      for (const log of bufferedLogs) {
        socket.emit("terminal:log", log);
      }
      
      // Send connection verification message
      socket.emit("terminal:log", {
        id: `sys-${Date.now()}`,
        scanId: jobId,
        timestamp: new Date().toISOString(),
        type: "info",
        message: `[SYSTEM] Connected to scan stream. Buffered logs: ${bufferedLogs.length}`,
        isAiLog: false,
      });
    });

    socket.on("unsubscribe:scan", (jobId: string) => {
      socket.leave(`scan:${jobId}`);
    });

    socket.on("disconnect", () => {
      logger.info(`Client disconnected: ${socket.id}`);
      const userId = socketToUser.get(socket.id);
      socketToUser.delete(socket.id);
      
      if (userId) {
        const sockets = userSockets.get(userId);
        if (sockets) {
          sockets.delete(socket.id);
          if (sockets.size === 0) {
            userSockets.delete(userId);
            userPlanLevels.delete(userId);
          }
        }
      }
    });
  });

  logger.info("Socket.io server initialized");
  return io;
}

export function getSocketServer(): SocketServer | null {
  return io;
}

export function emitScanCompleted(payload: NotificationPayload): void {
  if (!io) {
    logger.warn("Socket server not initialized");
    return;
  }

  io.to(`scan:${payload.jobId}`).emit("scanCompleted", {
    jobId: payload.jobId,
    status: payload.status,
    result: payload.result,
    error: payload.error,
  });

  io.to(`user:${payload.userId}`).emit("scanCompleted", {
    jobId: payload.jobId,
    target: payload.target,
    status: payload.status,
    result: payload.result,
    error: payload.error,
  });

  logger.info(`Emitted scanCompleted for job ${payload.jobId}`);
}

export function emitScanProgress(jobId: string, progress: number, phase?: string, eta?: string): void {
  if (!io) return;

  io.to(`scan:${jobId}`).emit("scanProgress", {
    jobId,
    progress,
    phase,
    eta,
  });
}

export function emitUrlStream(jobId: string, url: string): void {
  if (!io) return;

  io.to(`scan:${jobId}`).emit("urlStream", {
    jobId,
    url,
  });
}

export function emitPhaseUpdate(jobId: string, phase: string): void {
  if (!io) return;

  io.to(`scan:${jobId}`).emit("phaseUpdate", {
    jobId,
    phase,
  });
}

export function emitAiThought(scanId: string, thought: string, type: string = "reasoning"): void {
  if (!io) {
    logger.warn("Socket server not initialized");
    return;
  }
  
  const aiThoughtData: Record<string, unknown> = {
    scanId,
    timestamp: new Date().toISOString(),
    thought: `[AI THOUGHT]: ${thought}`,
    type,
  };
  
  io.to(`scan:${scanId}`).emit("aiThought", aiThoughtData);
  logger.debug(`[emitAiThought] Emitted to scan:${scanId}: ${thought}`);
}

export function emitToScan(scanId: string, event: string, data: any): void {
  if (!io) {
    logger.warn("Socket server not initialized");
    return;
  }
  logger.debug(`[emitToScan] Emitting ${event} to scan:${scanId}`, data);
  io.to(`scan:${scanId}`).emit(event, data);
}

export function emitToUser(userId: string, event: string, data: unknown): void {
  if (!io) return;

  io.to(`user:${userId}`).emit(event, data);
}

export function emitScannerDecision(scanId: string, decision: any): void {
  if (!io) return;

  io.to(`scan:${scanId}`).emit("scanner:decision", {
    scanId,
    decision,
  });

  logger.debug(`Emitted scanner decision for scan ${scanId}`);
}

export function emitScannerFinancialDecision(scanId: string, decision: any): void {
  if (!io) return;

  io.to(`scan:${scanId}`).emit("scanner:financial_decision", {
    scanId,
    decision,
  });
}

export function emitScannerSecurityDecision(scanId: string, decision: any): void {
  if (!io) return;

  io.to(`scan:${scanId}`).emit("scanner:security_decision", {
    scanId,
    decision,
  });
}

export function emitScannerReplanning(scanId: string, decision: any): void {
  if (!io) return;

  io.to(`scan:${scanId}`).emit("scanner:replanning", {
    scanId,
    decision,
  });
}

export function emitApprovalRequired(userId: string, scanId: string, approval: any): void {
  if (!io) return;

  io.to(`user:${userId}`).emit("scanner:approval_required", {
    scanId,
    approval,
  });

  io.to(`scan:${scanId}`).emit("scanner:approval_required", {
    scanId,
    approval,
  });

  logger.info(`Emitted approval required for scan ${scanId}, vulnerability ${approval.vulnerabilityId}`);
}

export interface TerminalLogPayload {
  id: string;
  scanId: string;
  timestamp: string;
  type: "exec" | "stdout" | "stderr" | "ai_thought" | "info" | "warning" | "error" | "finding" | "poc_payload" | "poc_evidence" | "remediation" | "phase_update" | "progress" | "url_stream" | "debug";
  message: string;
  command?: string;
  isAiLog?: boolean;
  agentLabel?: string;
  progress?: number;
  phase?: string;
  eta?: string;
  screenshot?: string;
}

export function trackVulnerability(scanId: string, severity: "critical" | "high" | "medium" | "low"): void {
  if (!vulnStats.has(scanId)) {
    vulnStats.set(scanId, { critical: 0, high: 0, medium: 0, low: 0 });
  }
  const stats = vulnStats.get(scanId)!;
  stats[severity]++;

  // Emit updated stats to all scan subscribers
  if (io) {
    io.to(`scan:${scanId}`).emit("vulnerability:stats", {
      scanId,
      stats,
      lastUpdate: new Date().toISOString(),
    });
  }
}

export function emitTerminalLog(scanId: string, log: Omit<TerminalLogPayload, "scanId">): void {
  if (!io) {
    console.error(`[SOCKET] io not initialized when emitting for scan ${scanId}`);
    return;
  }

  // FILTER: Block projectdiscovery banners, ASCII art, and version info from reaching frontend
  const shouldFilter = (message: string): boolean => {
    return (
      message.includes("projectdiscovery") ||
      message.includes("__") ||
      message.includes("/_/") ||
      message.includes("Current httpx version") ||
      message.includes("Current nuclei version") ||
      message.includes("v1.3.5") ||
      message.includes("outdated")
    );
  };

  // Do not emit filtered messages
  if (shouldFilter(log.message)) {
    return;
  }

  // Strip ANSI codes before sending to frontend
  const cleanMessage = stripAnsi(log.message);
  
  // LOG PUSH: Ensure logs are broadcasted to all scan subscribers
  const logWithMetadata = { ...log, scanId, message: cleanMessage };
  
  // Track vulnerability if message contains severity badge
  if (cleanMessage.match(/\[☢️ CRITICAL\]|\[🔥 HIGH\]|\[🟡 MEDIUM\]|\[🛡️ LOW\]/)) {
    if (cleanMessage.includes("☢️ CRITICAL")) {
      trackVulnerability(scanId, "critical");
    } else if (cleanMessage.includes("🔥 HIGH")) {
      trackVulnerability(scanId, "high");
    } else if (cleanMessage.includes("🟡 MEDIUM")) {
      trackVulnerability(scanId, "medium");
    } else if (cleanMessage.includes("🛡️ LOW")) {
      trackVulnerability(scanId, "low");
    }
  }

  const finalLog = { ...log, scanId, message: cleanMessage };
  
  // Buffer the log (keep last 10 per scan)
  if (!logBuffer.has(scanId)) {
    logBuffer.set(scanId, []);
  }
  const buffer = logBuffer.get(scanId)!;
  buffer.push(finalLog);
  if (buffer.length > 10) {
    buffer.shift(); // Remove oldest log
  }
  
  const scanRoom = io.sockets.adapter.rooms.get(`scan:${scanId}`);
  const eliteRoom = io.sockets.adapter.rooms.get(`plan:ELITE`);
  
  if (log.isAiLog || log.type === "ai_thought") {
    if (scanRoom && eliteRoom) {
      for (const socketId of Array.from(scanRoom)) {
        if (eliteRoom.has(socketId)) {
          io.to(socketId).emit("terminal:log", finalLog);
        }
      }
    }
  } else {
    const socketsInRoom = scanRoom ? scanRoom.size : 0;
    console.log(`[SOCKET] Emitting terminal:log to scan:${scanId} - Room has ${socketsInRoom} sockets - Message: "${log.message.substring(0, 60)}..."`);
    io.to(`scan:${scanId}`).emit("terminal:log", finalLog);
  }
}

export function emitExecLog(scanId: string, command: string, metadata?: { agentLabel?: string }): void {
  emitTerminalLog(scanId, {
    id: `exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    type: "exec",
    message: command,
    command,
    isAiLog: false,
    agentLabel: metadata?.agentLabel,
  });
}

export function emitStdoutLog(scanId: string, output: string, metadata?: { agentLabel?: string; type?: string; screenshot?: string }): void {
  const logType = (metadata?.type || "stdout") as TerminalLogPayload["type"];
  emitTerminalLog(scanId, {
    id: `stdout-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    type: logType,
    message: output,
    isAiLog: false,
    agentLabel: metadata?.agentLabel,
    screenshot: metadata?.screenshot,
  });
}

export function emitStderrLog(scanId: string, output: string): void {
  emitTerminalLog(scanId, {
    id: `stderr-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    type: "stderr",
    message: output,
    isAiLog: false,
  });
}

export function emitAiThoughtLog(scanId: string, thought: string): void {
  emitTerminalLog(scanId, {
    id: `ai-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    type: "ai_thought",
    message: thought,
    isAiLog: true,
  });
}

export function emitInfoLog(scanId: string, message: string, isAiLog = false): void {
  emitTerminalLog(scanId, {
    id: `info-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    type: "info",
    message,
    isAiLog,
  });
}

export function emitWarningLog(scanId: string, message: string, isAiLog = false): void {
  emitTerminalLog(scanId, {
    id: `warn-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    type: "warning",
    message,
    isAiLog,
  });
}

export function emitErrorLog(scanId: string, message: string): void {
  emitTerminalLog(scanId, {
    id: `error-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    type: "error",
    message,
    isAiLog: false,
  });
}
