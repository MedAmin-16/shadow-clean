import type { Request, Response } from "express";
import { storage } from "../../storage";

export async function getActivities(req: Request, res: Response) {
  try {
    const limit = parseInt(req.query.limit as string) || 10;
    const activities = await storage.getActivities(limit);
    res.json(activities);
  } catch (error) {
    console.error("Error fetching activities:", error);
    res.status(500).json({ error: "Failed to fetch activities" });
  }
}
