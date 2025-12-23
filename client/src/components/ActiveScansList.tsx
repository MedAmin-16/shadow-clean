import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "./StatusBadge";
import { Radar } from "lucide-react";

interface Scan {
  id: string;
  projectName: string;
  status: "running" | "complete" | "failed" | "pending";
  progress?: number;
}

interface ActiveScansListProps {
  scans: Scan[];
}

export function ActiveScansList({ scans }: ActiveScansListProps) {
  return (
    <Card data-testid="card-active-scans">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Radar className="h-4 w-4 text-primary" />
          Active Scans
        </CardTitle>
        <span className="text-xs text-muted-foreground">{scans.length} total</span>
      </CardHeader>
      <CardContent className="space-y-3">
        {scans.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-4">No active scans</p>
        ) : (
          scans.map((scan) => (
            <div 
              key={scan.id} 
              className="flex items-center justify-between gap-4"
              data-testid={`scan-item-${scan.id}`}
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{scan.projectName}</p>
                {scan.status === "running" && scan.progress !== undefined && (
                  <div className="mt-1 h-1.5 w-full bg-muted rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-primary transition-all"
                      style={{ width: `${scan.progress}%` }}
                    />
                  </div>
                )}
              </div>
              <StatusBadge status={scan.status} />
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}
