import type { Request, Response } from "express";
import { storage } from "../../storage";
import bcrypt from "bcrypt";

export async function register(req: Request, res: Response) {
  try {
    const { username, password, email, full_name } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ message: "Username, email, and password are required" });
    }

    const existingUser = await storage.getUserByUsername(username);
    if (existingUser) {
      console.log(`[Auth] Registration failed: User ${username} already exists`);
      return res.status(409).json({ message: "User already exists" });
    }

    console.log(`[Auth] Registering new user: ${username} (${email})`);
    
    const user = await storage.createUser({ username, password_hash: password, email });
    
    console.log(`[Auth] User created successfully: ${username} (ID: ${user.id})`);

    const session = (req as any).session;
    if (!session) {
      console.error("[Auth] Session not available");
      return res.status(500).json({ message: "Session configuration error" });
    }
    session.userId = user.id;

    // Explicitly save the session before sending response
    session.save((err: Error | null) => {
      if (err) {
        console.error("[Auth] Session save error:", err);
        return res.status(500).json({ message: "Session save failed" });
      }

      console.log(`[Auth] Registration complete and session saved: ${username}`);

      res.status(201).json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
        },
        message: "Registration successful",
      });
    });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : "";
    console.error("[Auth] Registration error:", errorMsg);
    if (errorStack) console.error("[Auth] Stack:", errorStack);
    res.status(500).json({ message: "Registration failed", error: errorMsg });
  }
}

export async function login(req: Request, res: Response) {
  try {
    const { username, email, password } = req.body;
    const loginField = username || email;

    if (!loginField || !password) {
      return res.status(400).json({ message: "Username/email and password are required" });
    }

    // Try to find user by email first, then by username
    let user = null;
    if (email) {
      user = await storage.getUserByEmail(email);
    }
    if (!user && username) {
      user = await storage.getUserByUsername(username);
    }
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const credits = await storage.getUserCredits(user.id);

    const session = (req as any).session;
    if (!session) {
      console.error("[Auth] Session not available");
      return res.status(500).json({ message: "Session configuration error" });
    }
    session.userId = user.id;

    // Explicitly save the session before sending response
    session.save((err: Error | null) => {
      if (err) {
        console.error("[Auth] Session save error:", err);
        return res.status(500).json({ message: "Session save failed" });
      }

      console.log(`[Auth] User logged in: ${username} (ID: ${user.id})`);

      res.json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          balance: credits.balance,
          planLevel: credits.planLevel,
        },
      });
    });
  } catch (error) {
    console.error("[Auth] Login error:", error);
    res.status(500).json({ message: "Login failed" });
  }
}
