import { Badge } from "@/components/ui/badge";

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className = "" }: SeverityBadgeProps) {
  const variants: Record<Severity, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    info: "bg-gray-500/10 text-gray-500 border-gray-500/20",
  };

  return (
    <Badge 
      variant="outline" 
      className={`${variants[severity]} ${className}`}
      data-testid={`badge-severity-${severity}`}
    >
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </Badge>
  );
}
