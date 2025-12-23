import { SeverityBadge } from "../SeverityBadge";

export default function SeverityBadgeExample() {
  return (
    <div className="flex flex-wrap gap-2">
      <SeverityBadge severity="critical" />
      <SeverityBadge severity="high" />
      <SeverityBadge severity="medium" />
      <SeverityBadge severity="low" />
      <SeverityBadge severity="info" />
    </div>
  );
}
