import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { VulnerabilityRow } from "./VulnerabilityRow";
import { AlertTriangle } from "lucide-react";

interface Vulnerability {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  affectedAsset: string;
  cveId?: string;
}

interface RecentVulnerabilitiesProps {
  vulnerabilities: Vulnerability[];
  onViewAll?: () => void;
}

export function RecentVulnerabilities({ vulnerabilities, onViewAll }: RecentVulnerabilitiesProps) {
  return (
    <Card data-testid="card-recent-vulnerabilities">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-primary" />
          Recent Vulnerabilities
        </CardTitle>
        {onViewAll && (
          <button 
            onClick={onViewAll}
            className="text-xs text-primary hover:underline"
            data-testid="button-view-all-vulnerabilities"
          >
            View all
          </button>
        )}
      </CardHeader>
      <CardContent className="p-0">
        {vulnerabilities.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">No vulnerabilities found</p>
        ) : (
          vulnerabilities.map((vuln) => (
            <VulnerabilityRow
              key={vuln.id}
              {...vuln}
              onClick={() => console.log('View vulnerability:', vuln.id)}
            />
          ))
        )}
      </CardContent>
    </Card>
  );
}
