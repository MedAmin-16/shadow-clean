import type { Request, Response } from "express";
import { storage } from "../../storage";
import { updateSettingsSchema } from "@shared/schema";

export async function getSettings(req: Request, res: Response) {
  try {
    const userId = req.query.userId as string || "default";
    const settings = await storage.getSettings(userId);
    res.json(settings);
  } catch (error) {
    console.error("Error fetching settings:", error);
    res.status(500).json({ error: "Failed to fetch settings" });
  }
}

export async function updateSettings(req: Request, res: Response) {
  try {
    const userId = req.query.userId as string || "default";
    const parsed = updateSettingsSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }
    
    const settings = await storage.updateSettings(userId, parsed.data);
    res.json(settings);
  } catch (error) {
    console.error("Error updating settings:", error);
    res.status(500).json({ error: "Failed to update settings" });
  }
}
