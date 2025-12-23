import { Badge } from "@/components/ui/badge";

type Status = "running" | "complete" | "failed" | "pending" | "active";

interface StatusBadgeProps {
  status: Status;
  className?: string;
}

export function StatusBadge({ status, className = "" }: StatusBadgeProps) {
  const variants: Record<Status, string> = {
    running: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    complete: "bg-green-500/10 text-green-500 border-green-500/20",
    failed: "bg-red-500/10 text-red-500 border-red-500/20",
    pending: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    active: "bg-green-500/10 text-green-500 border-green-500/20",
  };

  const labels: Record<Status, string> = {
    running: "Running",
    complete: "Complete",
    failed: "Failed",
    pending: "Pending",
    active: "Active",
  };

  return (
    <Badge 
      variant="outline" 
      className={`${variants[status]} ${className}`}
      data-testid={`badge-status-${status}`}
    >
      {status === "running" && (
        <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" />
      )}
      {status === "active" && (
        <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-green-500" />
      )}
      {labels[status]}
    </Badge>
  );
}
