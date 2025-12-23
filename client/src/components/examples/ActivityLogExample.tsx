import { ActivityLog } from "../ActivityLog";

// todo: remove mock functionality
const mockActivities = [
  {
    id: "1",
    type: "vulnerability_found" as const,
    message: "Critical vulnerability detected in Production API",
    timestamp: "2 minutes ago",
    details: "SQL Injection in /auth/login endpoint",
  },
  {
    id: "2",
    type: "scan_completed" as const,
    message: "Full scan completed for Staging Environment",
    timestamp: "15 minutes ago",
    details: "Score: 82/100",
  },
  {
    id: "3",
    type: "scan_started" as const,
    message: "Scan initiated for Internal Tools",
    timestamp: "1 hour ago",
  },
  {
    id: "4",
    type: "project_created" as const,
    message: "New project created: Mobile API",
    timestamp: "2 hours ago",
  },
  {
    id: "5",
    type: "user_login" as const,
    message: "User logged in",
    timestamp: "3 hours ago",
    details: "From IP: 192.168.1.100",
  },
];

export default function ActivityLogExample() {
  return <ActivityLog activities={mockActivities} />;
}
