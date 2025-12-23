import { Request, Response } from "express";
import { creditService } from "../services/creditService";
import { storage } from "../../storage";

const DEFAULT_USER_ID = "user-1";

export async function getCurrentUser(req: Request, res: Response) {
  try {
    const session = (req as any).session;
    const userId = session?.userId || DEFAULT_USER_ID;
    
    const credits = await creditService.getUserCredits(userId);
    
    let username = "Client User";
    let email = "client@company.com";
    
    if (session?.userId) {
      const user = await storage.getUser(session.userId);
      if (user) {
        username = user.username;
        email = user.username;
      }
    }
    
    return res.json({
      userId: credits.userId,
      planLevel: credits.planLevel,
      balance: credits.balance,
      email: email,
      name: username
    });
  } catch (error) {
    console.error("[UserController] Get current user error:", error);
    return res.status(500).json({ error: "Failed to retrieve user data" });
  }
}

export async function clientLogout(req: Request, res: Response) {
  try {
    const session = (req as any).session;
    if (session) {
      session.destroy((err: any) => {
        if (err) {
          console.error("[UserController] Session destroy error:", err);
        }
      });
    }
    res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("[UserController] Logout error:", error);
    return res.status(500).json({ error: "Logout failed" });
  }
}
