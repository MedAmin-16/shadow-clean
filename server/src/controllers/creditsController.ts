import { Request, Response } from "express";
import { creditService } from "../services/creditService";
import { z } from "zod";
import type { PlanLevel } from "@shared/schema";

const addCreditsSchema = z.object({
  userId: z.string().min(1),
  amount: z.number().positive(),
  description: z.string().optional(),
});

const refundCreditsSchema = z.object({
  userId: z.string().min(1),
  amount: z.number().positive(),
  reason: z.string().min(1),
  originalTransactionId: z.number().optional(),
});

const setPlanLevelSchema = z.object({
  userId: z.string().min(1),
  planLevel: z.enum(["STANDARD", "PRO", "ELITE"]),
});

export async function getUserCredits(req: Request, res: Response) {
  try {
    const { userId } = req.params;
    
    if (!userId) {
      return res.status(400).json({ error: "User ID is required" });
    }

    const credits = await creditService.getUserCredits(userId);
    return res.json(credits);
  } catch (error) {
    console.error("[CreditsController] Get credits error:", error);
    return res.status(500).json({ error: "Failed to retrieve credits" });
  }
}

export async function addCredits(req: Request, res: Response) {
  try {
    const validation = addCreditsSchema.safeParse(req.body);
    
    if (!validation.success) {
      return res.status(400).json({ error: validation.error.errors });
    }

    const { userId, amount, description } = validation.data;
    const credits = await creditService.addCredits(userId, amount, "purchase", { description });
    
    return res.json({
      success: true,
      credits,
      message: `Successfully added ${amount} credits`,
    });
  } catch (error) {
    console.error("[CreditsController] Add credits error:", error);
    return res.status(500).json({ error: "Failed to add credits" });
  }
}

export async function refundCredits(req: Request, res: Response) {
  try {
    const validation = refundCreditsSchema.safeParse(req.body);
    
    if (!validation.success) {
      return res.status(400).json({ error: validation.error.errors });
    }

    const { userId, amount, reason, originalTransactionId } = validation.data;
    const credits = await creditService.refundCredits(userId, amount, reason, originalTransactionId);
    
    return res.json({
      success: true,
      credits,
      message: `Successfully refunded ${amount} credits`,
    });
  } catch (error) {
    console.error("[CreditsController] Refund credits error:", error);
    return res.status(500).json({ error: "Failed to refund credits" });
  }
}

export async function getTransactionHistory(req: Request, res: Response) {
  try {
    const { userId } = req.params;
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = parseInt(req.query.offset as string) || 0;
    
    if (!userId) {
      return res.status(400).json({ error: "User ID is required" });
    }

    const history = await creditService.getTransactionHistory(userId, limit, offset);
    return res.json(history);
  } catch (error) {
    console.error("[CreditsController] Get history error:", error);
    return res.status(500).json({ error: "Failed to retrieve transaction history" });
  }
}

export async function checkCredits(req: Request, res: Response) {
  try {
    const { userId } = req.params;
    const requiredAmount = parseInt(req.query.amount as string) || 0;
    
    if (!userId) {
      return res.status(400).json({ error: "User ID is required" });
    }

    const result = await creditService.checkSufficientCredits(userId, requiredAmount);
    return res.json(result);
  } catch (error) {
    console.error("[CreditsController] Check credits error:", error);
    return res.status(500).json({ error: "Failed to check credits" });
  }
}

export async function setPlanLevel(req: Request, res: Response) {
  try {
    const validation = setPlanLevelSchema.safeParse(req.body);
    
    if (!validation.success) {
      return res.status(400).json({ error: validation.error.errors });
    }

    const { userId, planLevel } = validation.data;
    const credits = await creditService.setUserPlanLevel(userId, planLevel as PlanLevel);
    
    return res.json({
      success: true,
      credits,
      message: `Successfully updated plan to ${planLevel}`,
    });
  } catch (error) {
    console.error("[CreditsController] Set plan level error:", error);
    return res.status(500).json({ error: "Failed to update plan level" });
  }
}
