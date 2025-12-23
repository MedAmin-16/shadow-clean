import { useQuery } from "@tanstack/react-query";
import type { PlanLevel, FeatureId, GatedAgentId } from "@shared/schema";

interface FeatureAccessResponse {
  success: boolean;
  planLevel: PlanLevel;
  features: FeatureId[];
  agents: GatedAgentId[];
  monitoringFrequency: "none" | "weekly" | "daily";
  maxScansPerMonth: number;
}

export function useFeatureAccess() {
  return useQuery<FeatureAccessResponse>({
    queryKey: ["/api/features/access"],
    retry: false,
    staleTime: 60000,
  });
}

export function useHasFeature(feature: FeatureId): boolean {
  const { data } = useFeatureAccess();
  if (!data) return false;
  return data.features.includes(feature);
}

export function useHasAgent(agent: GatedAgentId): boolean {
  const { data } = useFeatureAccess();
  if (!data) return false;
  return data.agents.includes(agent);
}

export function usePlanLevel(): PlanLevel | undefined {
  const { data } = useFeatureAccess();
  return data?.planLevel;
}

export function getRequiredPlan(feature: FeatureId): "STANDARD" | "PRO" | "ELITE" {
  const eliteFeatures: FeatureId[] = [
    "ai_threat_intel",
    "database_sandbox", 
    "ai_remediation",
    "compliance_reports",
    "phishing_simulation",
    "daily_monitoring",
    "rl_exploiter",
    "autonomous_defense",
  ];

  const proFeatures: FeatureId[] = [
    "cloud_security",
    "visual_attack_path",
    "weekly_monitoring",
    "exploiter_agent",
    "prophet_agent",
  ];

  if (eliteFeatures.includes(feature)) return "ELITE";
  if (proFeatures.includes(feature)) return "PRO";
  return "STANDARD";
}
