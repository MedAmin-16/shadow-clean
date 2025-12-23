import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Activity, 
  Shield, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle,
  User,
  Folder,
  Radar
} from "lucide-react";

type ActivityType = "scan_started" | "scan_completed" | "scan_failed" | "vulnerability_found" | "project_created" | "user_login";

interface ActivityItem {
  id: string;
  type: ActivityType;
  message: string;
  timestamp: string;
  details?: string;
}

interface ActivityLogProps {
  activities: ActivityItem[];
}

export function ActivityLog({ activities }: ActivityLogProps) {
  const getIcon = (type: ActivityType) => {
    switch (type) {
      case "scan_started":
        return <Radar className="h-4 w-4 text-blue-500" />;
      case "scan_completed":
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case "scan_failed":
        return <XCircle className="h-4 w-4 text-red-500" />;
      case "vulnerability_found":
        return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case "project_created":
        return <Folder className="h-4 w-4 text-primary" />;
      case "user_login":
        return <User className="h-4 w-4 text-muted-foreground" />;
      default:
        return <Activity className="h-4 w-4 text-muted-foreground" />;
    }
  };

  return (
    <Card data-testid="card-activity-log">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Shield className="h-4 w-4 text-primary" />
          Activity Log
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[300px]">
          <div className="divide-y">
            {activities.map((activity) => (
              <div 
                key={activity.id} 
                className="flex items-start gap-3 p-4"
                data-testid={`activity-item-${activity.id}`}
              >
                <div className="mt-0.5">{getIcon(activity.type)}</div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm">{activity.message}</p>
                  {activity.details && (
                    <p className="text-xs text-muted-foreground mt-0.5">{activity.details}</p>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">{activity.timestamp}</p>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
