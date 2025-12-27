import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { SecurityScoreCard } from "@/components/SecurityScoreCard";
import { TwinStatusWidget } from "@/components/TwinStatusWidget";
import { ActiveScansList } from "@/components/ActiveScansList";
import { RecentVulnerabilities } from "@/components/RecentVulnerabilities";
import { ProjectCard } from "@/components/ProjectCard";
import { ActivityLog } from "@/components/ActivityLog";
import { CreateProjectDialog } from "@/components/CreateProjectDialog";
import { LiveTerminal } from "@/components/LiveTerminal";
import { useTerminal } from "@/hooks/useTerminal";
import { Plus, Search, Zap, Square } from "lucide-react";
import { Input } from "@/components/ui/input";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { Project, Activity, Scan } from "@shared/schema";
import { LiveScanWidget } from "@/components/LiveScanWidget";
import { VulnerabilityCard } from "@/components/VulnerabilityCard";
import { ProphetAISection } from "@/components/ProphetAISection";
import { PlanBadge } from "@/components/PlanBadge";
import { ScanResultsPage } from "@/components/ScanResultsPage";

interface DashboardMetrics {
  securityScore: number;
  totalProjects: number;
  activeScans: number;
  completedScans: number;
  totalScans: number;
  totalVulnerabilities: number;
  totalReports: number;
}

interface Vulnerability {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  project: string;
  date: string;
  cvss?: number;
  url?: string;
  payload?: string;
  responseSnippet?: string;
  remediationCode?: string;
  description?: string;
  tool?: string;
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? "s" : ""} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
  return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
}

interface UserData {
  userId: string;
  planLevel: string;
}

export default function DashboardPage() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [terminalScanId, setTerminalScanId] = useState<string | null>(null);
  const [showTerminal, setShowTerminal] = useState(true);
  const [showProphetAnalysis, setShowProphetAnalysis] = useState(true);

  const { data: user } = useQuery<UserData & { planLevel?: string }>({
    queryKey: ["/api/user/me"],
  });

  const stopScanMutation = useMutation({
    mutationFn: async (scanId: string) => {
      const response = await apiRequest("POST", `/api/scans/${scanId}/stop`, {});
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scans"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/metrics"] });
    },
  });

  const { data: metrics } = useQuery<DashboardMetrics>({
    queryKey: ["/api/dashboard/metrics"],
  });

  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
  });

  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: ["/api/scans"],
    refetchInterval: (query) => {
      const scans = query.state.data as Scan[] | undefined;
      return scans?.some(s => s.status === "running" || s.status === "pending") ? 3000 : false;
    }
  });

  const { data: activities = [] } = useQuery<Activity[]>({
    queryKey: ["/api/activity"],
  });

  const { data: vulnerabilities = [] } = useQuery<Vulnerability[]>({
    queryKey: ["/api/dashboard/vulnerabilities"],
  });

  const activeScan = useMemo(() => {
    return scans.find(s => s.status === "running");
  }, [scans]);

  const { logs, isConnected, vulnStats } = useTerminal({
    scanId: terminalScanId || activeScan?.id || null,
    userId: user?.userId,
    enabled: showTerminal && (!!terminalScanId || !!activeScan),
  });

  const createProjectMutation = useMutation({
    mutationFn: async (data: { name: string }) => {
      const response = await apiRequest("POST", "/api/projects", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/projects"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/metrics"] });
      queryClient.invalidateQueries({ queryKey: ["/api/activity"] });
      setCreateDialogOpen(false);
    },
  });

  const displayProjects = projects.slice(0, 3);

  const displayScans = scans.slice(0, 5).map((scan) => ({
    id: scan.id,
    projectName: scan.target,
    status: scan.status === "running" ? "running" as const : 
            scan.status === "pending" ? "pending" as const : 
            scan.status === "complete" ? "complete" as const : "complete" as const,
    progress: scan.progress,
  }));

  const displayActivities = activities.map((a) => ({
    id: a.id,
    type: a.type,
    message: a.message,
    timestamp: formatTimestamp(a.timestamp),
  }));

  const displayVulnerabilities = vulnerabilities.map((v) => ({
    id: v.id,
    title: v.title,
    severity: v.severity,
    affectedAsset: v.project,
    cveId: undefined,
    cvss: v.cvss,
    url: v.url,
    payload: v.payload,
    responseSnippet: v.responseSnippet,
    remediationCode: v.remediationCode,
    description: v.description,
    tool: v.tool,
    timestamp: v.date,
  }));

  return (
    <div className="p-6 space-y-6" data-testid="page-dashboard">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Dashboard</h1>
          <p className="text-muted-foreground">Monitor your security posture across all projects</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search projects..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 w-64"
              data-testid="input-search"
            />
          </div>
          <Button onClick={() => setCreateDialogOpen(true)} data-testid="button-new-project">
            <Plus className="h-4 w-4 mr-2" />
            New Project
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <SecurityScoreCard 
          score={metrics?.securityScore || 0} 
          trend="up" 
          trendValue={5} 
          lastScan={displayProjects[0]?.lastScanDate || "Never"} 
        />
        <TwinStatusWidget
          projectName={displayProjects[0]?.name || "No Projects"}
          status={displayScans.some(s => s.status === "running") ? "active" : "pending"}
          lastScanTime={displayProjects[0]?.lastScanDate || "Never"}
          assetsCount={displayProjects[0]?.assetCount || 0}
        />
        <div className="md:col-span-2 relative">
          <ActiveScansList scans={displayScans} />
          {activeScan && (
            <Button 
              variant="destructive" 
              size="sm" 
              className="absolute top-4 right-4 h-7 text-[10px] px-2 shadow-lg shadow-red-500/20"
              onClick={() => stopScanMutation.mutate(activeScan.id)}
              disabled={stopScanMutation.isPending}
            >
              <Square className="h-3 w-3 mr-1 fill-current" />
              STOP SCAN
            </Button>
          )}
        </div>
      </div>

      {/* Elite Scan Section */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <div className="space-y-4">
            <h2 className="text-lg font-semibold">Live Scan Terminal</h2>
            <LiveScanWidget scanId={terminalScanId || activeScan?.id} isActive={activeScan?.status === "running"} />
          </div>
        </div>
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Plan Status</h2>
          <div className="bg-gradient-to-br from-black/80 to-black border border-cyan-500/30 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-300">Your Plan</span>
              <PlanBadge plan={user?.planLevel === "ELITE" ? "elite" : user?.planLevel === "PRO" ? "pro" : "free"} />
            </div>
            {user?.planLevel === "ELITE" && (
              <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded text-xs text-yellow-200 text-center">
                🌟 ELITE MEMBER - All tools unlocked
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Vulnerability Findings Grid */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold">Latest Findings</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <VulnerabilityCard
            title="AWS Access Key Leaked"
            severity="critical"
            tool="Katana + Nuclei"
            url="/assets/config.js"
            details="Unencrypted AWS credentials found in JavaScript files"
            timestamp="2 min ago"
          />
          <VulnerabilityCard
            title="SQL Injection Endpoint"
            severity="high"
            tool="SQLMap"
            url="/api/search?q="
            details="Database query parameter not sanitized"
            timestamp="5 min ago"
          />
          <VulnerabilityCard
            title="Exposed API Token"
            severity="high"
            tool="Subjs + Nuclei"
            url="/static/app.js"
            details="OAuth token visible in source code"
            timestamp="8 min ago"
          />
          <VulnerabilityCard
            title="Weak Password Hash"
            severity="medium"
            tool="Gau + Nuclei"
            url="/api/users"
            details="MD5 hashing detected for password storage"
            timestamp="12 min ago"
          />
          <VulnerabilityCard
            title="Hidden Admin Panel"
            severity="medium"
            tool="Waybackurls"
            url="/admin/dashboard"
            details="Found via historical Wayback Machine data"
            timestamp="15 min ago"
          />
          <VulnerabilityCard
            title="Info Disclosure"
            severity="low"
            tool="HTTPX"
            url="/debug.php"
            details="Debug endpoint exposing system information"
            timestamp="20 min ago"
          />
        </div>
      </div>

      {/* Prophet AI Predictions */}
      {showProphetAnalysis && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Threat Prediction Engine</h2>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowProphetAnalysis(false)}
              className="text-xs"
            >
              Dismiss
            </Button>
          </div>
          <ProphetAISection
            isAnalyzing={activeScan?.status === "running"}
            predictions={[
              {
                path: "Likely AWS credentials in /api/config.js - HIGH PRIORITY",
                confidence: 92,
                type: "secret",
              },
              {
                path: "SQL injection vulnerable endpoint pattern detected",
                confidence: 78,
                type: "vulnerability",
              },
              {
                path: "Admin panel discovered via historical records",
                confidence: 85,
                type: "endpoint",
              },
              {
                path: "OAuth token exposure in main application bundle",
                confidence: 88,
                type: "secret",
              },
            ]}
          />
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <RecentVulnerabilities
            vulnerabilities={displayVulnerabilities}
            onViewAll={() => console.log("View all vulnerabilities")}
          />
        </div>
        <ActivityLog activities={displayActivities} />
      </div>

      <div>
        <div className="flex items-center justify-between gap-4 mb-4">
          <h2 className="text-lg font-semibold">Your Projects</h2>
          <button
            className="text-sm text-primary hover:underline"
            onClick={() => console.log("View all projects")}
            data-testid="link-view-all-projects"
          >
            View all
          </button>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {displayProjects.map((project) => (
            <ProjectCard
              key={project.id}
              {...project}
              onClick={() => console.log("Project clicked:", project.id)}
            />
          ))}
        </div>
      </div>

      <CreateProjectDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onSubmit={(data) => createProjectMutation.mutate(data)}
      />

      {showTerminal && activeScan && (
        <div>
          <h2 className="text-lg font-semibold mb-4">Live Scan Terminal</h2>
          <LiveTerminal
            logs={logs}
            isActive={activeScan.status === "running" && isConnected}
            planLevel={(user?.planLevel as "STANDARD" | "PRO" | "ELITE") || "STANDARD"}
            vulnStats={vulnStats}
          />
        </div>
      )}
    </div>
  );
}
