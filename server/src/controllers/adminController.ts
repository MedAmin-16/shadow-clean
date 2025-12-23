import type { Request, Response, NextFunction } from "express";
import bcrypt from "bcrypt";
import { randomUUID } from "crypto";
import { db } from "../../db";
import { users as usersTable, userCreditsTable } from "@shared/schema";
import { creditService } from "../services/creditService";
import { eq } from "drizzle-orm";

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

interface AdminSession {
  isAdmin: boolean;
  adminEmail: string;
  loginTime: number;
}

const adminSessions = new Map<string, AdminSession>();

export async function adminLogin(req: Request, res: Response) {
  try {
    const { email, password } = req.body;
    const clientIp = req.ip || req.socket.remoteAddress || "unknown";

    const attempts = loginAttempts.get(clientIp);
    if (attempts) {
      const timeSinceLastAttempt = Date.now() - attempts.lastAttempt;
      if (attempts.count >= MAX_LOGIN_ATTEMPTS && timeSinceLastAttempt < LOCKOUT_DURATION) {
        const remainingTime = Math.ceil((LOCKOUT_DURATION - timeSinceLastAttempt) / 60000);
        console.warn(`Admin login blocked for IP ${clientIp}: Too many attempts`);
        return res.status(429).json({ 
          message: `Too many login attempts. Please try again in ${remainingTime} minutes.` 
        });
      }
      if (timeSinceLastAttempt >= LOCKOUT_DURATION) {
        loginAttempts.delete(clientIp);
      }
    }

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    if (!ADMIN_EMAIL || !ADMIN_PASSWORD_HASH) {
      console.error("Admin credentials not configured in environment");
      return res.status(500).json({ message: "Admin access not configured" });
    }

    if (email !== ADMIN_EMAIL) {
      recordFailedAttempt(clientIp);
      console.warn(`Failed admin login attempt from ${clientIp}: Invalid email`);
      return res.status(403).json({ message: "Access denied" });
    }

    const isValidPassword = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (!isValidPassword) {
      recordFailedAttempt(clientIp);
      console.warn(`Failed admin login attempt from ${clientIp}: Invalid password`);
      return res.status(403).json({ message: "Access denied" });
    }

    loginAttempts.delete(clientIp);

    const sessionToken = randomUUID();
    adminSessions.set(sessionToken, {
      isAdmin: true,
      adminEmail: email,
      loginTime: Date.now(),
    });

    console.log(`Admin login successful from ${clientIp}`);
    res.json({
      success: true,
      token: sessionToken,
      message: "Admin login successful",
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
}

function recordFailedAttempt(ip: string) {
  const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  attempts.count++;
  attempts.lastAttempt = Date.now();
  loginAttempts.set(ip, attempts);
}

export async function verifyAdmin(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ isAdmin: false, message: "No token provided" });
    }

    const token = authHeader.substring(7);
    const session = adminSessions.get(token);

    if (!session || !session.isAdmin) {
      return res.status(403).json({ isAdmin: false, message: "Invalid or expired session" });
    }

    const SESSION_DURATION = 8 * 60 * 60 * 1000;
    if (Date.now() - session.loginTime > SESSION_DURATION) {
      adminSessions.delete(token);
      return res.status(403).json({ isAdmin: false, message: "Session expired" });
    }

    res.json({ isAdmin: true, email: session.adminEmail });
  } catch (error) {
    console.error("Admin verification error:", error);
    res.status(500).json({ isAdmin: false, message: "Internal server error" });
  }
}

export async function adminLogout(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      adminSessions.delete(token);
    }
    res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("Admin logout error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.substring(7);
  
  if (!token || token.length < 32) {
    return res.status(401).json({ message: "Invalid token format" });
  }

  const session = adminSessions.get(token);

  if (!session || !session.isAdmin) {
    return res.status(403).json({ message: "Access denied" });
  }

  const SESSION_DURATION = 8 * 60 * 60 * 1000;
  if (Date.now() - session.loginTime > SESSION_DURATION) {
    adminSessions.delete(token);
    return res.status(403).json({ message: "Session expired" });
  }

  next();
}

const agentStateStore = new Map<string, boolean>([
  ["agent-1", true],
  ["agent-2", true],
  ["agent-3", true],
  ["agent-4", false],
  ["agent-5", true],
  ["agent-6", true],
  ["agent-7", true],
]);

const threatFeedStore = new Map<string, { apiKey: string; enabled: boolean; lastSync: number | null }>([
  ["trellix", { apiKey: "", enabled: false, lastSync: null }],
  ["rapid7", { apiKey: "", enabled: false, lastSync: null }],
  ["virustotal", { apiKey: "", enabled: false, lastSync: null }],
  ["crowdstrike", { apiKey: "", enabled: false, lastSync: null }],
]);

export async function getAdminStats(req: Request, res: Response) {
  try {
    const stats = {
      totalCreditsConsumed: 45200,
      totalCreditsSold: 125000,
      activeUsers: 156,
      totalScans: 3420,
      agentPerformance: [
        { agentId: "agent-1", agentName: "Agent 1 - Reconnaissance", successRate: 98, avgRuntime: 2.3, totalRuns: 1250 },
        { agentId: "agent-2", agentName: "Agent 2 - Vulnerability Scanner", successRate: 95, avgRuntime: 8.7, totalRuns: 890 },
        { agentId: "agent-3", agentName: "Agent 3 - Threat Analyzer", successRate: 94, avgRuntime: 4.5, totalRuns: 723 },
        { agentId: "agent-4", agentName: "Agent 4 - Stealth Mode", successRate: 0, avgRuntime: 0, totalRuns: 0 },
        { agentId: "agent-5", agentName: "Agent 5 - WAF Generator", successRate: 92, avgRuntime: 1.8, totalRuns: 456 },
        { agentId: "agent-6", agentName: "Agent 6 - Report Generator", successRate: 99, avgRuntime: 3.2, totalRuns: 780 },
        { agentId: "agent-7", agentName: "Agent 7 - Auto-Remediation", successRate: 87, avgRuntime: 6.1, totalRuns: 321 },
      ],
      fallbackAudit: {
        autonomousFixes: 823,
        manualFallbacks: 134,
        recentFallbacks: [
          { timestamp: Date.now() - 3600000, reason: "Missing WAF API Key", userId: "user-2" },
          { timestamp: Date.now() - 7200000, reason: "Missing WAF API Key", userId: "user-3" },
          { timestamp: Date.now() - 14400000, reason: "Rate limit exceeded", userId: "user-1" },
        ],
      },
      agentStatus: Array.from(agentStateStore.entries()).map(([agentId, enabled]) => ({
        agentId,
        agentName: getAgentName(agentId),
        enabled,
        description: getAgentDescription(agentId),
      })),
      threatFeeds: Array.from(threatFeedStore.entries()).map(([feedId, data]) => ({
        feedId,
        feedName: getThreatFeedName(feedId),
        hasApiKey: !!data.apiKey,
        enabled: data.enabled,
        lastSync: data.lastSync,
      })),
    };
    res.json(stats);
  } catch (error) {
    console.error("Error fetching admin stats:", error);
    res.status(500).json({ message: "Failed to fetch admin stats" });
  }
}

function getAgentName(agentId: string): string {
  const names: Record<string, string> = {
    "agent-1": "Agent 1 - Reconnaissance",
    "agent-2": "Agent 2 - Vulnerability Scanner",
    "agent-3": "Agent 3 - Threat Analyzer",
    "agent-4": "Agent 4 - Stealth Mode",
    "agent-5": "Agent 5 - WAF Generator",
    "agent-6": "Agent 6 - Report Generator",
    "agent-7": "Agent 7 - Auto-Remediation",
  };
  return names[agentId] || agentId;
}

function getAgentDescription(agentId: string): string {
  const descriptions: Record<string, string> = {
    "agent-1": "Performs initial target reconnaissance and asset discovery",
    "agent-2": "Scans for known vulnerabilities and CVEs",
    "agent-3": "Analyzes threats and generates risk assessments",
    "agent-4": "Stealth scanning mode for sensitive environments",
    "agent-5": "Generates WAF rules and security policies",
    "agent-6": "Compiles comprehensive security reports",
    "agent-7": "Automatically applies security fixes when possible",
  };
  return descriptions[agentId] || "";
}

function getThreatFeedName(feedId: string): string {
  const names: Record<string, string> = {
    "trellix": "Trellix Threat Intelligence",
    "rapid7": "Rapid7 InsightVM",
    "virustotal": "VirusTotal Enterprise",
    "crowdstrike": "CrowdStrike Falcon",
  };
  return names[feedId] || feedId;
}

export async function getAdminUsers(req: Request, res: Response) {
  try {
    // Fetch all users with their credits using a proper LEFT JOIN
    const usersWithCredits = await db
      .select({
        userId: usersTable.id,
        username: usersTable.username,
        balance: userCreditsTable.balance,
        planLevel: userCreditsTable.planLevel,
      })
      .from(usersTable)
      .leftJoin(userCreditsTable, eq(usersTable.id, userCreditsTable.userId));
    
    // For users without credit records, initialize them
    const results = await Promise.all(
      usersWithCredits.map(async (user) => {
        if (user.balance === null || user.planLevel === null) {
          // Initialize credits for user without existing credit record
          const credits = await creditService.getUserCredits(user.userId);
          return {
            userId: user.userId,
            username: user.username,
            balance: credits.balance,
            planLevel: credits.planLevel,
          };
        }
        return {
          userId: user.userId,
          username: user.username,
          balance: user.balance,
          planLevel: user.planLevel,
        };
      })
    );
    
    res.json(results);
  } catch (error) {
    console.error("Error fetching admin users:", error);
    res.status(500).json({ message: "Failed to fetch users" });
  }
}

export async function toggleAgent(req: Request, res: Response) {
  try {
    const { agentId, enabled } = req.body;
    
    if (!agentId || typeof enabled !== "boolean") {
      return res.status(400).json({ message: "Invalid request: agentId and enabled required" });
    }
    
    if (!agentStateStore.has(agentId)) {
      return res.status(404).json({ message: "Agent not found" });
    }
    
    agentStateStore.set(agentId, enabled);
    console.log(`Agent ${agentId} ${enabled ? "enabled" : "disabled"} by admin`);
    
    res.json({ 
      success: true, 
      agentId, 
      enabled,
      agentName: getAgentName(agentId),
    });
  } catch (error) {
    console.error("Error toggling agent:", error);
    res.status(500).json({ message: "Failed to toggle agent" });
  }
}

export async function updateThreatFeed(req: Request, res: Response) {
  try {
    const { feedId, apiKey, enabled } = req.body;
    
    if (!feedId) {
      return res.status(400).json({ message: "Feed ID required" });
    }
    
    const feed = threatFeedStore.get(feedId);
    if (!feed) {
      return res.status(404).json({ message: "Threat feed not found" });
    }
    
    if (apiKey !== undefined) {
      feed.apiKey = apiKey;
    }
    if (enabled !== undefined) {
      feed.enabled = enabled;
    }
    if (feed.enabled && feed.apiKey) {
      feed.lastSync = Date.now();
    }
    
    threatFeedStore.set(feedId, feed);
    console.log(`Threat feed ${feedId} updated by admin`);
    
    res.json({
      success: true,
      feedId,
      feedName: getThreatFeedName(feedId),
      hasApiKey: !!feed.apiKey,
      enabled: feed.enabled,
      lastSync: feed.lastSync,
    });
  } catch (error) {
    console.error("Error updating threat feed:", error);
    res.status(500).json({ message: "Failed to update threat feed" });
  }
}

export async function getThreatFeeds(req: Request, res: Response) {
  try {
    const feeds = Array.from(threatFeedStore.entries()).map(([feedId, data]) => ({
      feedId,
      feedName: getThreatFeedName(feedId),
      hasApiKey: !!data.apiKey,
      enabled: data.enabled,
      lastSync: data.lastSync,
    }));
    res.json(feeds);
  } catch (error) {
    console.error("Error fetching threat feeds:", error);
    res.status(500).json({ message: "Failed to fetch threat feeds" });
  }
}

export async function adjustCredits(req: Request, res: Response) {
  try {
    const { userId, amount, reason } = req.body;
    
    if (!userId || typeof amount !== "number") {
      return res.status(400).json({ message: "userId and numeric amount are required" });
    }
    
    if (amount === 0) {
      return res.status(400).json({ message: "Amount must be non-zero" });
    }
    
    let newBalance: number;
    
    if (amount >= 0) {
      // Add credits
      const updatedCredits = await creditService.addCredits(userId, amount, "admin_adjustment", {
        description: reason || `Admin credit adjustment: +${amount}`,
      });
      newBalance = updatedCredits.balance;
    } else {
      // Subtract credits (deduct the absolute value)
      const deductResult = await creditService.deductCredits(userId, Math.abs(amount), {
        description: reason || `Admin credit adjustment: ${amount}`,
      });
      
      if (!deductResult.success) {
        return res.status(400).json({ 
          success: false, 
          message: deductResult.error || "Failed to deduct credits" 
        });
      }
      
      newBalance = deductResult.newBalance;
    }
    
    console.log(`Admin adjusted credits for user ${userId}: ${amount > 0 ? '+' : ''}${amount} - Reason: ${reason || 'No reason provided'}`);
    
    res.json({ 
      success: true, 
      userId, 
      amount, 
      reason,
      newBalance,
    });
  } catch (error) {
    console.error("Error adjusting credits:", error);
    res.status(500).json({ message: "Failed to adjust credits" });
  }
}
