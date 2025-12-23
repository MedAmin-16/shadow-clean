import type { Response, NextFunction } from "express";
import type { AuthenticatedRequest } from "../types";
import { storage } from "../../storage";
import {
  type PlanLevel,
  type FeatureId,
  type GatedAgentId,
  hasFeatureAccess,
  hasAgentAccess,
  getRequiredPlanForFeature,
  getRequiredPlanForAgent,
  PLAN_FEATURE_CONFIGS,
} from "@shared/schema";

export interface PlanGatedRequest extends AuthenticatedRequest {
  userPlanLevel?: PlanLevel;
}

async function getUserPlanLevel(userId: string): Promise<PlanLevel> {
  try {
    const credits = await storage.getUserCredits(userId);
    return credits.planLevel as PlanLevel;
  } catch {
    return "PRO";
  }
}

export function requireFeature(feature: FeatureId) {
  return async (req: PlanGatedRequest, res: Response, next: NextFunction) => {
    const session = (req as any).session;
    
    if (!session?.userId) {
      return res.status(401).json({
        error: "Authentication required",
        code: "AUTH_REQUIRED",
      });
    }

    const userId = session.userId;
    const planLevel = await getUserPlanLevel(userId);
    req.userId = userId;
    req.userPlanLevel = planLevel;

    if (!hasFeatureAccess(planLevel, feature)) {
      const requiredPlan = getRequiredPlanForFeature(feature);
      return res.status(403).json({
        error: "Upgrade required",
        code: "UPGRADE_REQUIRED",
        message: `This feature requires the ${PLAN_FEATURE_CONFIGS[requiredPlan].displayName}. Please upgrade your plan to access this feature.`,
        currentPlan: planLevel,
        requiredPlan,
        feature,
      });
    }

    next();
  };
}

export function requireAgent(agent: GatedAgentId) {
  return async (req: PlanGatedRequest, res: Response, next: NextFunction) => {
    const session = (req as any).session;
    
    if (!session?.userId) {
      return res.status(401).json({
        error: "Authentication required",
        code: "AUTH_REQUIRED",
      });
    }

    const userId = session.userId;
    const planLevel = await getUserPlanLevel(userId);
    req.userId = userId;
    req.userPlanLevel = planLevel;

    if (!hasAgentAccess(planLevel, agent)) {
      const requiredPlan = getRequiredPlanForAgent(agent);
      return res.status(403).json({
        error: "Upgrade required",
        code: "UPGRADE_REQUIRED",
        message: `The ${agent} agent requires the ${PLAN_FEATURE_CONFIGS[requiredPlan].displayName}. Please upgrade your plan.`,
        currentPlan: planLevel,
        requiredPlan,
        agent,
      });
    }

    next();
  };
}

export function requireMinPlan(minPlan: PlanLevel) {
  const planHierarchy: Record<PlanLevel, number> = {
    PRO: 1,
    ELITE: 2,
  };

  return async (req: PlanGatedRequest, res: Response, next: NextFunction) => {
    const session = (req as any).session;
    
    if (!session?.userId) {
      return res.status(401).json({
        error: "Authentication required",
        code: "AUTH_REQUIRED",
      });
    }

    const userId = session.userId;
    const planLevel = await getUserPlanLevel(userId);
    req.userId = userId;
    req.userPlanLevel = planLevel;

    if (planHierarchy[planLevel] < planHierarchy[minPlan]) {
      return res.status(403).json({
        error: "Upgrade required",
        code: "UPGRADE_REQUIRED",
        message: `This feature requires the ${PLAN_FEATURE_CONFIGS[minPlan].displayName}. Please upgrade your plan.`,
        currentPlan: planLevel,
        requiredPlan: minPlan,
      });
    }

    next();
  };
}

export async function checkFeatureAccess(
  userId: string,
  feature: FeatureId
): Promise<{ allowed: boolean; planLevel: PlanLevel; requiredPlan?: PlanLevel; message?: string }> {
  const planLevel = await getUserPlanLevel(userId);
  
  if (hasFeatureAccess(planLevel, feature)) {
    return { allowed: true, planLevel };
  }

  const requiredPlan = getRequiredPlanForFeature(feature);
  return {
    allowed: false,
    planLevel,
    requiredPlan,
    message: `This feature requires the ${PLAN_FEATURE_CONFIGS[requiredPlan].displayName}.`,
  };
}

export async function checkAgentAccess(
  userId: string,
  agent: GatedAgentId
): Promise<{ allowed: boolean; planLevel: PlanLevel; requiredPlan?: PlanLevel; message?: string }> {
  const planLevel = await getUserPlanLevel(userId);
  
  if (hasAgentAccess(planLevel, agent)) {
    return { allowed: true, planLevel };
  }

  const requiredPlan = getRequiredPlanForAgent(agent);
  return {
    allowed: false,
    planLevel,
    requiredPlan,
    message: `The ${agent} agent requires the ${PLAN_FEATURE_CONFIGS[requiredPlan].displayName}.`,
  };
}

export function getAccessibleFeatures(planLevel: PlanLevel): FeatureId[] {
  return PLAN_FEATURE_CONFIGS[planLevel].allowedFeatures;
}

export function getAccessibleAgents(planLevel: PlanLevel): GatedAgentId[] {
  return PLAN_FEATURE_CONFIGS[planLevel].allowedAgents;
}
