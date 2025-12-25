import { useState, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { StatusBadge } from "@/components/StatusBadge";
import { Badge } from "@/components/ui/badge";
import { LiveTerminal } from "@/components/LiveTerminal";
import { EvidenceTerminal } from "@/components/EvidenceTerminal";
import { useTerminal } from "@/hooks/useTerminal";
import { 
  Search, 
  Play, 
  Clock, 
  CheckCircle2, 
  XCircle, 
  Radar, 
  Filter,
  Target,
  Shield,
  Bug,
  FileText,
  Loader2,
  Brain,
  Cpu,
  ShieldCheck,
  Terminal
} from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { Scan, AgentType } from "@shared/schema";

interface UserData {
  userId: string;
  planLevel: string;
  balance: number;
  email: string;
  name: string;
}

type DisplayAgentType = "recon" | "scanner" | "exploiter" | "rl_exploiter" | "prophet" | "reporter" | "autonomous_defense";

interface AgentInfo {
  label: string;
  icon: typeof Radar;
  eliteOnly?: boolean;
}

const AGENT_LABELS: Record<DisplayAgentType, AgentInfo> = {
  recon: { label: "[AGENT-01] Network Reconnaissance", icon: Target },
  scanner: { label: "[AGENT-02-07] Multi-Scanner Suite", icon: Shield },
  exploiter: { label: "[AGENT-08] Exploitation & PoC", icon: Bug },
  rl_exploiter: { label: "[AGENT-09] Logic-AI (Groq)", icon: Cpu, eliteOnly: true },
  prophet: { label: "[AGENT-10] Prophet-AI (Groq)", icon: Brain, eliteOnly: true },
  reporter: { label: "Report Generation", icon: FileText },
  autonomous_defense: { label: "Defense Orchestration", icon: ShieldCheck, eliteOnly: true },
};

const PRO_AGENTS: DisplayAgentType[] = ["recon", "scanner", "reporter"];
const ELITE_AGENTS: DisplayAgentType[] = ["recon", "scanner", "exploiter", "rl_exploiter", "prophet", "reporter", "autonomous_defense"];

function formatDate(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins} min ago`;
  if (diffHours < 24) return `${diffHours} hours ago`;
  return `${diffDays} days ago`;
}

function calculateDuration(startedAt: string, completedAt?: string): string {
  const start = new Date(startedAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  const diffMs = end - start;
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  
  if (diffSecs < 60) return `${diffSecs}s`;
  return `${diffMins}m ${diffSecs % 60}s`;
}

export default function ScansPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [targetInput, setTargetInput] = useState("");
  const [terminalScanId, setTerminalScanId] = useState<string | null>(null);
  const [showTerminal, setShowTerminal] = useState(false);

  const { data: user } = useQuery<UserData>({
    queryKey: ["/api/user/me"],
  });

  const { data: scans = [], isLoading } = useQuery<Scan[]>({
    queryKey: ["/api/scans"],
  });

  const activeScan = useMemo(() => {
    return scans.find(s => s.status === "running");
  }, [scans]);

  const { logs, isConnected, vulnStats } = useTerminal({
    scanId: terminalScanId || activeScan?.id || null,
    userId: user?.userId,
    enabled: showTerminal && (!!terminalScanId || !!activeScan),
  });

  // Keep a simple effect to invalidate query on certain socket events if needed
  // but let's stick to the refetchInterval for now as it's more stable given the project structure
  /*
  useEffect(() => {
    if (isConnected) {
      // socket logic
    }
  }, [isConnected]);
  */

  const displayAgents = useMemo(() => {
    if (user?.planLevel === "ELITE") {
      return ELITE_AGENTS;
    }
    return PRO_AGENTS;
  }, [user?.planLevel]);
  
  const canViewTerminal = user?.planLevel === "PRO" || user?.planLevel === "ELITE";

  const startScanMutation = useMutation({
    mutationFn: async (target: string) => {
      const response = await apiRequest("POST", "/api/scans", { target });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scans"] });
      setIsDialogOpen(false);
      setTargetInput("");
    },
  });

  const handleStartScan = () => {
    if (targetInput.trim()) {
      startScanMutation.mutate(targetInput.trim());
    }
  };

  const filteredScans = scans.filter((scan) => {
    const matchesSearch = scan.target.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === "all" || scan.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "running":
        return <Radar className="h-4 w-4 text-blue-500 animate-pulse" />;
      case "complete":
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case "failed":
        return <XCircle className="h-4 w-4 text-red-500" />;
      case "pending":
        return <Clock className="h-4 w-4 text-yellow-500" />;
      default:
        return null;
    }
  };

  const getVulnerabilityCount = (scan: Scan): number => {
    const scannerResult = scan.agentResults?.scanner;
    if (scannerResult?.status === "complete" && scannerResult.data) {
      return scannerResult.data.vulnerabilities?.length || 0;
    }
    return 0;
  };

  const getSecurityScore = (scan: Scan): number | undefined => {
    const reporterResult = scan.agentResults?.reporter;
    if (reporterResult?.status === "complete" && reporterResult.data) {
      return reporterResult.data.securityScore;
    }
    return undefined;
  };

  return (
    <div className="p-6 space-y-6" data-testid="page-scans">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Scans</h1>
          <p className="text-muted-foreground">View and manage security scans</p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button data-testid="button-start-scan">
              <Play className="h-4 w-4 mr-2" />
              Start New Scan
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Start New Security Scan</DialogTitle>
              <DialogDescription>
                Enter a target URL or IP address to scan. The scan will run agents in sequence based on your plan level.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="target">Target</Label>
                <Input
                  id="target"
                  placeholder="e.g., example.com or 192.168.1.1"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleStartScan()}
                  data-testid="input-target"
                />
              </div>
              <div className="space-y-2">
                <p className="text-sm font-medium">
                  Agents that will run ({user?.planLevel || "STANDARD"} Plan):
                </p>
                <div className="grid grid-cols-2 gap-2">
                  {ELITE_AGENTS.map((agent) => {
                    const agentInfo = AGENT_LABELS[agent];
                    const Icon = agentInfo.icon;
                    const isLocked = agentInfo.eliteOnly && user?.planLevel !== "ELITE";
                    return (
                      <div 
                        key={agent} 
                        className={`flex items-center gap-2 text-sm p-2 rounded ${isLocked ? "opacity-50 text-muted-foreground bg-muted" : "text-foreground"}`}
                      >
                        <Icon className="h-4 w-4" />
                        <span>{agentInfo.label}</span>
                        {isLocked && <Badge variant="secondary" className="ml-auto text-xs">ELITE</Badge>}
                      </div>
                    );
                  })}
                </div>
                {user?.planLevel !== "ELITE" && (
                  <p className="text-xs text-muted-foreground mt-2">
                    Upgrade to <strong>ELITE</strong> to unlock AGENT-08 (Logic-AI), AGENT-09 (Prophet-AI), AGENT-10 (Deep Investigation) with Groq Llama-3-70b analysis
                  </p>
                )}
              </div>
            </div>
            <DialogFooter>
              <Button 
                variant="outline" 
                onClick={() => setIsDialogOpen(false)}
                data-testid="button-cancel-scan"
              >
                Cancel
              </Button>
              <Button 
                onClick={handleStartScan}
                disabled={!targetInput.trim() || startScanMutation.isPending}
                data-testid="button-confirm-scan"
              >
                {startScanMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Starting...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Start Scan
                  </>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <div className="flex flex-wrap items-center gap-4">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search scans..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
            data-testid="input-search-scans"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-40" data-testid="select-status-filter">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="running">Running</SelectItem>
              <SelectItem value="complete">Complete</SelectItem>
              <SelectItem value="failed">Failed</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-4">
        {isLoading ? (
          <Card>
            <CardContent className="py-12 text-center">
              <Loader2 className="h-8 w-8 animate-spin mx-auto text-muted-foreground" />
              <p className="text-muted-foreground mt-2">Loading scans...</p>
            </CardContent>
          </Card>
        ) : filteredScans.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <p className="text-muted-foreground">
                {scans.length === 0 
                  ? "No scans yet. Click \"Start New Scan\" to begin."
                  : "No scans found matching your filters."}
              </p>
            </CardContent>
          </Card>
        ) : (
          filteredScans.map((scan) => (
            <Card
              key={scan.id}
              className="hover-elevate cursor-pointer"
              data-testid={`card-scan-${scan.id}`}
            >
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-4 flex-1 min-w-0">
                    {getStatusIcon(scan.status)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium">{scan.target}</span>
                        <StatusBadge status={scan.status} />
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-sm text-muted-foreground">
                        <span>Started: {formatDate(scan.startedAt)}</span>
                        <span>Duration: {calculateDuration(scan.startedAt, scan.completedAt)}</span>
                      </div>
                      
                      {scan.status === "running" && (
                        <div className="mt-3 space-y-2">
                          <div className="flex items-center gap-2 text-sm">
                            {scan.currentAgent && (
                              <>
                                <Loader2 className="h-3 w-3 animate-spin" />
                                <span className="text-muted-foreground">
                                  Running: {AGENT_LABELS[scan.currentAgent as DisplayAgentType]?.label || scan.currentAgent}
                                </span>
                              </>
                            )}
                          </div>
                          <div className="h-1.5 w-full max-w-md bg-muted rounded-full overflow-hidden">
                            <div
                              className="h-full bg-primary transition-all"
                              style={{ width: `${scan.progress}%` }}
                            />
                          </div>
                          <div className="flex gap-1">
                            {displayAgents.map((agent) => {
                              const result = scan.agentResults?.[agent];
                              const isComplete = result?.status === "complete";
                              const isRunning = scan.currentAgent === agent;
                              const Icon = AGENT_LABELS[agent].icon;
                              
                              return (
                                <div
                                  key={agent}
                                  className={`flex items-center justify-center w-8 h-8 rounded-md ${
                                    isComplete 
                                      ? "bg-green-500/20 text-green-500" 
                                      : isRunning 
                                        ? "bg-blue-500/20 text-blue-500" 
                                        : "bg-muted text-muted-foreground"
                                  }`}
                                  title={AGENT_LABELS[agent].label}
                                >
                                  <Icon className="h-4 w-4" />
                                </div>
                              );
                            })}
                          </div>
                          
                          {canViewTerminal && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="mt-3 gap-2"
                              onClick={(e) => {
                                e.stopPropagation();
                                setTerminalScanId(scan.id);
                                setShowTerminal(!showTerminal || terminalScanId !== scan.id);
                              }}
                            >
                              <Terminal className="h-4 w-4" />
                              {showTerminal && terminalScanId === scan.id ? "Hide Terminal" : "Show Live Terminal"}
                            </Button>
                          )}
                        </div>
                      )}
                      
                      {scan.error && (
                        <p className="mt-1 text-sm text-red-500">Error: {scan.error}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    {getSecurityScore(scan) !== undefined && (
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">Score</p>
                        <p className="text-lg font-semibold">{getSecurityScore(scan)}</p>
                      </div>
                    )}
                    {getVulnerabilityCount(scan) > 0 && (
                      <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20">
                        {getVulnerabilityCount(scan)} vulnerabilities
                      </Badge>
                    )}
                  </div>
                </div>
              </CardContent>
              
              {showTerminal && terminalScanId === scan.id && canViewTerminal && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 p-4 border-t border-green-900/30">
                  <LiveTerminal
                    logs={logs}
                    isActive={scan.status === "running" && isConnected}
                    planLevel={(user?.planLevel as "STANDARD" | "PRO" | "ELITE") || "STANDARD"}
                    vulnStats={vulnStats}
                    className="h-full"
                  />
                  <EvidenceTerminal
                    logs={logs}
                    className="h-full"
                  />
                </div>
              )}
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
