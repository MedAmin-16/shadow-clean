import type { Request, Response, NextFunction } from "express";
import type { AuthenticatedRequest } from "../types";

export function sessionAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const session = (req as any).session;
  
  if (!session) {
    console.error("[SessionAuth] No session object on request. Headers:", req.headers);
    res.status(500).json({
      error: "Server configuration error",
    });
    return;
  }
  
  if (!session.userId) {
    console.error("[SessionAuth] No userId in session. Session ID:", req.sessionID, "Session data:", session);
    res.status(401).json({
      error: "Authentication required to start a scan",
    });
    return;
  }
  
  req.userId = session.userId;
  next();
}

export function optionalSessionAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const session = (req as any).session;
  
  if (!session) {
    console.error("[SessionAuth] Session middleware not initialized");
    next();
    return;
  }
  
  if (session.userId) {
    req.userId = session.userId;
  }
  next();
}
