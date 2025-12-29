import { Request, Response } from "express";
import { z } from "zod";
import { runShadowLogicScan, ShadowLogicAgent } from "../../agents/shadowLogic";
import type { 
  ShadowLogicScanConfig, 
  ShadowLogicThought,
  ShadowLogicScanResult 
} from "@shared/shadowLogic";
import { 
  SHADOW_LOGIC_COSTS,
  SHADOW_LOGIC_TEST_DESCRIPTIONS,
  DEFAULT_SHADOW_LOGIC_CONFIG 
} from "@shared/shadowLogic";
import { storage } from "../../storage";
import { hasFeatureAccess } from "@shared/schema";
import { nanoid } from "nanoid";
import { getSocketServer } from "../sockets/socketManager";

const activeShadowLogicScans = new Map<string, {
  agent: ShadowLogicAgent;
  thoughts: ShadowLogicThought[];
}>();

// Normalize URLs - add https:// if no protocol
const normalizeUrl = (url: string): string => {
  if (!url) return url;
  if (!/^https?:\/\//.test(url)) {
    return `https://${url}`;
  }
  return url;
};

const shadowLogicScanRequestSchema = z.object({
  targetUrl: z.string().min(1, "Target URL is required").transform(normalizeUrl).pipe(z.string().url("Invalid URL format")),
  registrationUrl: z.string().min(1).transform(normalizeUrl).pipe(z.string().url()).optional().or(z.literal("")),
  loginUrl: z.string().min(1).transform(normalizeUrl).pipe(z.string().url()).optional().or(z.literal("")),
  testCredentials: z.object({
    username: z.string().optional(),
    password: z.string().optional(),
    email: z.string().email().optional(),
  }).optional(),
  testTypes: z.array(z.enum([
    "price_manipulation",
    "quantity_manipulation",
    "privilege_escalation",
    "idor",
    "workflow_bypass",
    "parameter_tampering",
    "race_condition",
    "session_hijacking"
  ])).optional(),
  maxDepth: z.number().min(1).max(10).optional(),
  excludeUrls: z.array(z.string()).optional(),
  safetyMode: z.boolean().optional(),
  headless: z.boolean().optional(),
});

export async function startShadowLogicScan(req: Request, res: Response) {
  try {
    const session = (req as any).session;
    const userId = session?.userId || (req as any).userId || req.headers["x-user-id"] as string;
    
    // Log incoming request payload for debugging
    console.log("[ShadowLogic] INCOMING REQUEST PAYLOAD:", {
      body: req.body,
      contentType: req.headers['content-type'],
      userId,
      hasSession: !!session,
    });
    
    if (!userId) {
      console.log("[ShadowLogic] Missing userId. Session:", session, "Headers:", req.headers);
      return res.status(401).json({ success: false, error: "Authentication required", code: "AUTH_REQUIRED" });
    }

    const userCredits = await storage.getUserCredits(userId);
    if (!hasFeatureAccess(userCredits.planLevel, "shadow_logic")) {
      return res.status(403).json({ 
        success: false, 
        error: "ShadowLogic™ is only available on the ELITE plan",
        requiredPlan: "ELITE"
      });
    }

    let validatedData;
    try {
      validatedData = shadowLogicScanRequestSchema.parse(req.body);
      console.log("[ShadowLogic] ✓ Validation passed. Parsed URLs:", {
        targetUrl: validatedData.targetUrl,
        registrationUrl: validatedData.registrationUrl,
        loginUrl: validatedData.loginUrl,
      });
    } catch (validationError) {
      console.log("[ShadowLogic] ✗ Validation failed:", validationError);
      throw validationError;
    }

    const estimatedCost = SHADOW_LOGIC_COSTS.baseCost + SHADOW_LOGIC_COSTS.aiAnalysisCost;
    if (userCredits.balance < estimatedCost) {
      return res.status(402).json({
        success: false,
        error: "Insufficient credits",
        required: estimatedCost,
        current: userCredits.balance,
      });
    }

    const config: ShadowLogicScanConfig = {
      targetUrl: validatedData.targetUrl,
      registrationUrl: validatedData.registrationUrl,
      loginUrl: validatedData.loginUrl,
      testCredentials: validatedData.testCredentials,
      testTypes: validatedData.testTypes || DEFAULT_SHADOW_LOGIC_CONFIG.testTypes!,
      maxDepth: validatedData.maxDepth || DEFAULT_SHADOW_LOGIC_CONFIG.maxDepth!,
      excludeUrls: validatedData.excludeUrls,
      safetyMode: validatedData.safetyMode ?? DEFAULT_SHADOW_LOGIC_CONFIG.safetyMode!,
      headless: validatedData.headless ?? DEFAULT_SHADOW_LOGIC_CONFIG.headless!,
    };

    const scanId = nanoid();
    const thoughts: ShadowLogicThought[] = [];
    const agent = new ShadowLogicAgent(config, userId, scanId, (thought) => {
      thoughts.push(thought);
    });

    activeShadowLogicScans.set(scanId, { agent, thoughts });

    res.json({
      success: true,
      scanId,
      message: "ShadowLogic™ scan initiated",
      estimatedCost,
    });

    // Subscribe socket to scan events and send initial heartbeat
    const io = getSocketServer();
    if (io) {
      io.to(`user:${userId}`).emit("subscribe:scan", scanId);
      // Send immediate system event to indicate scan started
      setTimeout(() => {
        io.to(`scan:${scanId}`).emit("shadowLogic:system", {
          message: "[SYSTEM] ShadowLogic Engine Started - Initializing security audit..."
        });
      }, 100);
    }

    runShadowLogicScan(config, userId, scanId, (thought) => {
      const scan = activeShadowLogicScans.get(scanId);
      if (scan) {
        scan.thoughts.push(thought);
      }
    }).then(async (result) => {
      await storage.deductCredits(userId, result.creditCost, {
        description: "ShadowLogic™ scan",
        agentType: "shadow_logic",
        scanId: result.id,
      });
      activeShadowLogicScans.delete(scanId);
      console.log(`[ShadowLogic] Scan ${scanId} completed with ${result.vulnerabilities.length} vulnerabilities`);
    }).catch((error) => {
      console.error(`[ShadowLogic] Scan ${scanId} failed:`, error);
      activeShadowLogicScans.delete(scanId);
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors.map(e => ({
        field: e.path.join('.'),
        message: e.message,
        code: e.code,
      }));
      console.error("[ShadowLogic] Validation errors:", formattedErrors);
      return res.status(400).json({ 
        success: false, 
        error: "Validation failed",
        details: formattedErrors,
        hint: "Make sure targetUrl is a valid domain (e.g., 'example.com' or 'https://example.com')"
      });
    }
    console.error("[ShadowLogic] Start scan error:", error);
    res.status(500).json({ 
      success: false, 
      error: error instanceof Error ? error.message : "Unknown error" 
    });
  }
}

export async function getShadowLogicScanStatus(req: Request, res: Response) {
  try {
    const { scanId } = req.params;
    let scan = activeShadowLogicScans.get(scanId);

    // If not in memory, try to fetch from database to ensure truth
    let dbStatus: string | undefined;
    let result: any;
    
    if (!scan) {
      const dbScan = await storage.getScan(scanId);
      if (!dbScan) {
        return res.status(404).json({ 
          success: false, 
          error: "Scan not found" 
        });
      }
      dbStatus = dbScan.status;
      // Mock result object for the response if scan is completed or in DB
      result = {
        id: dbScan.id,
        status: dbScan.status,
        statistics: dbScan.agentResults?.statistics || {
          pagesVisited: 0,
          formsAnalyzed: 0,
          apiEndpointsDiscovered: 0,
          testsExecuted: 0,
          vulnerabilitiesFound: 0,
          timeElapsed: 0,
        },
        vulnerabilities: dbScan.agentResults?.vulnerabilities || [],
        businessFlows: dbScan.agentResults?.businessFlows || [],
      };
    } else {
      result = scan.agent.getResult();
    }

    res.json({
      success: true,
      data: {
        id: result.id,
        status: result.status,
        progress: calculateProgress(result),
        statistics: result.statistics,
        vulnerabilitiesFound: result.vulnerabilities?.length || 0,
        businessFlowsDiscovered: result.businessFlows?.length || 0,
      },
    });
  } catch (error) {
    console.error("[ShadowLogic] Get status error:", error);
    res.status(500).json({ 
      success: false, 
      error: error instanceof Error ? error.message : "Unknown error" 
    });
  }
}

export async function getShadowLogicThoughts(req: Request, res: Response) {
  try {
    const { scanId } = req.params;
    const after = req.query.after as string | undefined;
    
    const scan = activeShadowLogicScans.get(scanId);
    let thoughts: ShadowLogicThought[] = [];
    let currentStatus: string = "initializing";

    if (scan) {
      thoughts = [...scan.thoughts];
      currentStatus = scan.agent.getResult().status;
    } else {
      // If scan is not in memory, it might be in database
      const dbScan = await storage.getScan(scanId);
      if (dbScan) {
        thoughts = dbScan.agentResults?.thoughts || [];
        currentStatus = dbScan.status;
      } else {
        return res.status(404).json({ 
          success: false, 
          error: "Scan not found" 
        });
      }
    }

    // AI Response Flush / Heartbeat Logic:
    // If AI is "analyzing" but thoughts are empty or stalled,
    // inject a heartbeat thought to keep UI updated and truthful
    if (thoughts.length === 0 || (currentStatus === "analyzing" && thoughts[thoughts.length-1].type !== "observation")) {
       thoughts.push({
         id: `heartbeat-${Date.now()}`,
         timestamp: new Date().toISOString(),
         type: "observation",
         message: `[Heartbeat] System active in ${currentStatus} phase...`,
         details: "ShadowLogic engine is processing current state data."
       });
    }

    if (after) {
      const afterIndex = thoughts.findIndex(t => t.id === after);
      if (afterIndex >= 0) {
        thoughts = thoughts.slice(afterIndex + 1);
      }
    }

    // STREAM FIX: Force 200 OK with fresh data, never 304 Not Modified
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("ETag", "");
    
    res.status(200).json({
      success: true,
      data: thoughts,
      status: currentStatus,
      timestamp: new Date().toISOString(),
      thoughtCount: thoughts.length,
    });
  } catch (error) {
    console.error("[ShadowLogic] Get thoughts error:", error);
    res.status(500).json({ 
      success: false, 
      error: error instanceof Error ? error.message : "Unknown error" 
    });
  }
}

export async function getShadowLogicResult(req: Request, res: Response) {
  try {
    const { scanId } = req.params;
    const scan = activeShadowLogicScans.get(scanId);

    if (!scan) {
      return res.status(404).json({ 
        success: false, 
        error: "Scan not found or already completed. Results may have been collected." 
      });
    }

    const result = scan.agent.getResult();
    
    if (result.status !== "completed" && result.status !== "error") {
      return res.status(202).json({
        success: true,
        message: "Scan still in progress",
        status: result.status,
      });
    }

    activeShadowLogicScans.delete(scanId);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error("[ShadowLogic] Get result error:", error);
    res.status(500).json({ 
      success: false, 
      error: error instanceof Error ? error.message : "Unknown error" 
    });
  }
}

export async function getShadowLogicTestTypes(req: Request, res: Response) {
  res.json({
    success: true,
    data: SHADOW_LOGIC_TEST_DESCRIPTIONS,
  });
}

const DEFAULT_USER_ID = "user-1";

export async function getShadowLogicCost(req: Request, res: Response) {
  try {
    const session = (req as any).session;
    const userId = session?.userId || (req as any).userId || req.headers["x-user-id"] as string || DEFAULT_USER_ID;

    const userCredits = await storage.getUserCredits(userId);
    
    res.json({
      success: true,
      data: {
        baseCost: SHADOW_LOGIC_COSTS.baseCost,
        aiAnalysisCost: SHADOW_LOGIC_COSTS.aiAnalysisCost,
        estimatedTotal: SHADOW_LOGIC_COSTS.baseCost + SHADOW_LOGIC_COSTS.aiAnalysisCost,
        currentBalance: userCredits.balance,
        canRun: userCredits.balance >= (SHADOW_LOGIC_COSTS.baseCost + SHADOW_LOGIC_COSTS.aiAnalysisCost),
        hasAccess: hasFeatureAccess(userCredits.planLevel, "shadow_logic"),
        planLevel: userCredits.planLevel,
      },
    });
  } catch (error) {
    console.error("[ShadowLogic] Get cost error:", error);
    res.status(500).json({ 
      success: false, 
      error: error instanceof Error ? error.message : "Unknown error" 
    });
  }
}

export async function cancelShadowLogicScan(req: Request, res: Response) {
  try {
    const { scanId } = req.params;
    const scan = activeShadowLogicScans.get(scanId);

    if (!scan) {
      return res.status(404).json({ 
        success: false, 
        error: "Scan not found" 
      });
    }

    activeShadowLogicScans.delete(scanId);

    res.json({
      success: true,
      message: "Scan cancelled",
    });
  } catch (error) {
    console.error("[ShadowLogic] Cancel scan error:", error);
    res.status(500).json({ 
      success: false, 
      error: error instanceof Error ? error.message : "Unknown error" 
    });
  }
}

function calculateProgress(result: ShadowLogicScanResult): number {
  const phases = ["initializing", "registering", "mapping", "analyzing", "testing", "reporting", "completed"];
  const currentIndex = phases.indexOf(result.status);
  if (currentIndex < 0) return 0;
  return Math.round((currentIndex / (phases.length - 1)) * 100);
}
