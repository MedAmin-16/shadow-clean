import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "./StatusBadge";
import { Activity } from "lucide-react";

interface TwinStatusWidgetProps {
  projectName: string;
  status: "running" | "complete" | "failed" | "pending" | "active";
  lastScanTime: string;
  assetsCount: number;
}

export function TwinStatusWidget({ projectName, status, lastScanTime, assetsCount }: TwinStatusWidgetProps) {
  return (
    <Card data-testid="widget-twin-status">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Activity className="h-4 w-4 text-primary" />
          Twin Status
        </CardTitle>
        <StatusBadge status={status} />
      </CardHeader>
      <CardContent>
        <div className="text-lg font-semibold">{projectName}</div>
        <div className="flex items-center justify-between gap-4 mt-2 text-sm text-muted-foreground">
          <span>{assetsCount} assets monitored</span>
          <span>Last scan: {lastScanTime}</span>
        </div>
      </CardContent>
    </Card>
  );
}
