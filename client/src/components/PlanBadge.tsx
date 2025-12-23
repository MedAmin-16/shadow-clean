import { Crown, Zap } from "lucide-react";

interface PlanBadgeProps {
  plan: "free" | "pro" | "elite";
  className?: string;
}

export function PlanBadge({ plan, className = "" }: PlanBadgeProps) {
  const planConfig: Record<string, { icon: React.ReactNode; label: string; colors: string }> = {
    free: {
      icon: <Zap className="w-3 h-3" />,
      label: "FREE",
      colors: "bg-blue-500/20 text-blue-300 border-blue-500/40",
    },
    pro: {
      icon: <Crown className="w-3 h-3" />,
      label: "PRO",
      colors: "bg-purple-500/20 text-purple-300 border-purple-500/40",
    },
    elite: {
      icon: <Crown className="w-3 h-3" />,
      label: "ELITE",
      colors: "bg-gradient-to-r from-yellow-500/30 to-amber-500/20 text-yellow-200 border-yellow-500/40 shadow-lg shadow-yellow-500/30 animate-pulse",
    },
  };

  const config = planConfig[plan];

  return (
    <div
      className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border font-mono text-xs font-bold ${config.colors} ${className}`}
    >
      {config.icon}
      <span>{config.label}</span>
      {plan === "elite" && <span className="ml-1">⚡</span>}
    </div>
  );
}
