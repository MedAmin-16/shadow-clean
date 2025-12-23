import { StatusBadge } from "../StatusBadge";

export default function StatusBadgeExample() {
  return (
    <div className="flex flex-wrap gap-2">
      <StatusBadge status="running" />
      <StatusBadge status="complete" />
      <StatusBadge status="failed" />
      <StatusBadge status="pending" />
      <StatusBadge status="active" />
    </div>
  );
}
