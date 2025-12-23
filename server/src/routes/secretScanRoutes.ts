import { Router, Request, Response } from "express";
import { secretScanService } from "../services/secretScanService";
import { emitStdoutLog, emitInfoLog, emitWarningLog, emitErrorLog } from "../sockets/socketManager";
import { randomUUID } from "crypto";

const router = Router();

/**
 * POST /api/secret-scan/start
 * Start a JS-Secret scan with real-time streaming output
 */
router.post("/start", async (req: Request, res: Response) => {
  try {
    const { target, userId } = req.body;

    if (!target || !userId) {
      return res
        .status(400)
        .json({ error: "target and userId are required" });
    }

    const scanId = randomUUID();

    // Send initial response with scan ID
    res.json({
      success: true,
      scanId,
      target,
      status: "started",
      message: "Scan started. Output streaming to console.",
    });

    // Send immediate "Scan Initialized" message to frontend
    setImmediate(() => {
      emitInfoLog(scanId, `[SCAN INITIALIZED] Starting Elite Secret Scan`);
      emitInfoLog(scanId, `[TARGET] ${target}`);
      emitInfoLog(scanId, `[SCAN_ID] ${scanId}`);
    });

    // Run scan in background and stream output
    setImmediate(async () => {
      try {
        await secretScanService.runFullSecretScan(
          target,
          scanId,
          userId,
          (line: string) => {
            // Console output for real-time monitoring
            console.log(`[SCAN:${scanId}] ${line}`);
            // Emit to socket.io for live terminal
            emitStdoutLog(scanId, line);
          },
          (warning: string) => {
            // Handle warnings (tool blocked, etc)
            console.warn(`[SCAN:${scanId}] ⚠️ ${warning}`);
            emitWarningLog(scanId, warning);
          },
          (error: string) => {
            // Handle errors
            console.error(`[SCAN:${scanId}] ❌ ${error}`);
            emitErrorLog(scanId, error);
          }
        );
      } catch (error) {
        const errorMsg = `Scan failed: ${error}`;
        console.error(`[SCAN:${scanId}] ${errorMsg}`);
        emitErrorLog(scanId, errorMsg);
      }
    });
  } catch (error) {
    console.error("[SecretScan API] Error:", error);
    res.status(500).json({ error: "Scan initiation failed" });
  }
});

/**
 * GET /api/secret-scan/results/:scanId
 * Fetch results of a completed scan
 */
router.get("/results/:scanId", async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    const { pool } = await import("../../db");

    const result = await pool.query(
      `SELECT * FROM secrets_found WHERE scan_id = $1 ORDER BY found_at DESC`,
      [scanId]
    );

    res.json({
      scanId,
      totalSecrets: result.rows.length,
      secrets: result.rows,
    });
  } catch (error) {
    console.error("[SecretScan Results] Error:", error);
    res.status(500).json({ error: "Failed to fetch results" });
  }
});

/**
 * GET /api/secret-scan/stats
 * Overall scan statistics
 */
router.get("/stats", async (req: Request, res: Response) => {
  try {
    const { userId } = req.query;
    const { pool } = await import("../../db");

    const stats = await pool.query(
      `SELECT 
        COUNT(*) as total_secrets,
        COUNT(DISTINCT scan_id) as total_scans,
        COUNT(DISTINCT secret_type) as unique_types,
        MAX(found_at) as last_scan
      FROM secrets_found
      WHERE user_id = $1`,
      [userId]
    );

    res.json(stats.rows[0] || {});
  } catch (error) {
    console.error("[SecretScan Stats] Error:", error);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

export default router;
