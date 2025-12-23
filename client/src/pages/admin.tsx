import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { queryClient } from "@/lib/queryClient";
import { LogOut } from "lucide-react";
import {
  Shield,
  DollarSign,
  Users,
  Activity,
  Settings,
  Zap,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  TrendingUp,
  Clock,
  Database,
  Key,
} from "lucide-react";

interface AdminStats {
  totalCreditsConsumed: number;
  totalCreditsSold: number;
  activeUsers: number;
  totalScans: number;
  agentPerformance: {
    agentId: string;
    agentName: string;
    successRate: number;
    avgRuntime: number;
    totalRuns: number;
  }[];
  fallbackAudit: {
    autonomousFixes: number;
    manualFallbacks: number;
    recentFallbacks?: {
      timestamp: number;
      reason: string;
      userId: string;
    }[];
  };
  agentStatus: {
    agentId: string;
    agentName: string;
    enabled: boolean;
    description?: string;
  }[];
  threatFeeds?: {
    feedId: string;
    feedName: string;
    hasApiKey: boolean;
    enabled: boolean;
    lastSync: number | null;
  }[];
}

interface UserCreditsRow {
  userId: string;
  username: string;
  balance: number;
  planLevel: string;
}

function getAdminToken() {
  return localStorage.getItem("adminToken");
}

async function adminApiRequest(method: string, url: string, body?: any) {
  const token = getAdminToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  return response;
}

export default function AdminPage() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [selectedUser, setSelectedUser] = useState("");
  const [creditAdjustment, setCreditAdjustment] = useState("");
  const [adjustmentReason, setAdjustmentReason] = useState("");
  const [isVerifying, setIsVerifying] = useState(true);
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [threatFeedApiKey, setThreatFeedApiKey] = useState("");
  const [selectedThreatFeed, setSelectedThreatFeed] = useState("");

  useEffect(() => {
    const verifyAdmin = async () => {
      const token = getAdminToken();
      if (!token) {
        setLocation("/admin/login");
        return;
      }

      try {
        const response = await fetch("/api/admin/verify", {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (!response.ok) {
          localStorage.removeItem("adminToken");
          setLocation("/admin/login");
          return;
        }

        setIsAuthorized(true);
      } catch (error) {
        localStorage.removeItem("adminToken");
        setLocation("/admin/login");
      } finally {
        setIsVerifying(false);
      }
    };

    verifyAdmin();
  }, [setLocation]);

  const handleLogout = async () => {
    const token = getAdminToken();
    try {
      await fetch("/api/admin/logout", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch (error) {
      console.error("Logout error:", error);
    }
    localStorage.removeItem("adminToken");
    setLocation("/admin/login");
  };

  const { data: stats, isLoading: statsLoading } = useQuery<AdminStats>({
    queryKey: ["/api/admin/stats"],
    queryFn: async () => {
      const response = await adminApiRequest("GET", "/api/admin/stats");
      if (!response.ok) throw new Error("Failed to fetch stats");
      return response.json();
    },
    enabled: isAuthorized,
  });

  const { data: users } = useQuery<UserCreditsRow[]>({
    queryKey: ["/api/admin/users"],
    queryFn: async () => {
      const response = await adminApiRequest("GET", "/api/admin/users");
      if (!response.ok) throw new Error("Failed to fetch users");
      return response.json();
    },
    enabled: isAuthorized,
  });

  const toggleAgentMutation = useMutation({
    mutationFn: async ({ agentId, enabled }: { agentId: string; enabled: boolean }) => {
      const response = await adminApiRequest("POST", "/api/admin/agents/toggle", { agentId, enabled });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/stats"] });
      toast({ title: "Agent status updated" });
    },
    onError: () => {
      toast({ title: "Failed to update agent", variant: "destructive" });
    },
  });

  const adjustCreditsMutation = useMutation({
    mutationFn: async (data: { userId: string; amount: number; reason: string }) => {
      const response = await adminApiRequest("POST", "/api/admin/credits/adjust", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/stats"] });
      toast({ title: "Credits adjusted successfully" });
      setCreditAdjustment("");
      setAdjustmentReason("");
    },
    onError: () => {
      toast({ title: "Failed to adjust credits", variant: "destructive" });
    },
  });

  const updateThreatFeedMutation = useMutation({
    mutationFn: async (data: { feedId: string; apiKey?: string; enabled?: boolean }) => {
      const response = await adminApiRequest("POST", "/api/admin/threat-feeds/update", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/stats"] });
      toast({ title: "Threat feed updated successfully" });
      setThreatFeedApiKey("");
      setSelectedThreatFeed("");
    },
    onError: () => {
      toast({ title: "Failed to update threat feed", variant: "destructive" });
    },
  });

  const handleAdjustCredits = () => {
    if (!selectedUser || !creditAdjustment) return;
    adjustCreditsMutation.mutate({
      userId: selectedUser,
      amount: parseInt(creditAdjustment),
      reason: adjustmentReason || "Admin adjustment",
    });
  };

  if (isVerifying || statsLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <RefreshCw className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  if (!isAuthorized) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6 space-y-6" data-testid="page-admin">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2 text-white">
            <Shield className="h-6 w-6 text-red-500" />
            Admin Control Panel
          </h1>
          <p className="text-slate-400">System monitoring and management</p>
        </div>
        <div className="flex items-center gap-4">
          <Badge variant="outline" className="text-sm border-red-500/30 text-red-400" data-testid="badge-owner-access">
            Owner Access
          </Badge>
          <Button
            variant="outline"
            size="sm"
            onClick={handleLogout}
            className="border-slate-600 text-slate-300 hover:bg-slate-700"
            data-testid="button-admin-logout"
          >
            <LogOut className="h-4 w-4 mr-2" />
            Logout
          </Button>
        </div>
      </div>

      <Tabs defaultValue="financial" className="space-y-4" data-testid="admin-tabs">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="financial" data-testid="tab-financial">Financial Audit</TabsTrigger>
          <TabsTrigger value="agents" data-testid="tab-agents">Agent Controls</TabsTrigger>
          <TabsTrigger value="performance" data-testid="tab-performance">Performance</TabsTrigger>
          <TabsTrigger value="threat-feeds" data-testid="tab-threat-feeds">Threat Feeds</TabsTrigger>
        </TabsList>

        <TabsContent value="financial" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">Total Credits Consumed</CardTitle>
                <DollarSign className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats?.totalCreditsConsumed?.toLocaleString() || 0}</div>
                <p className="text-xs text-muted-foreground">All-time usage</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">Total Credits Sold</CardTitle>
                <TrendingUp className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats?.totalCreditsSold?.toLocaleString() || 0}</div>
                <p className="text-xs text-muted-foreground">Revenue credits</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">Active Users</CardTitle>
                <Users className="h-4 w-4 text-blue-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats?.activeUsers || 0}</div>
                <p className="text-xs text-muted-foreground">Registered accounts</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
                <Activity className="h-4 w-4 text-purple-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats?.totalScans || 0}</div>
                <p className="text-xs text-muted-foreground">Scans executed</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Credit Adjustment</CardTitle>
              <CardDescription>Manually adjust user credits (add or deduct)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-4">
                <div className="space-y-2">
                  <Label>Select User</Label>
                  <Select value={selectedUser} onValueChange={setSelectedUser}>
                    <SelectTrigger data-testid="select-user-credits">
                      <SelectValue placeholder="Choose user..." />
                    </SelectTrigger>
                    <SelectContent>
                      {users?.map((user) => (
                        <SelectItem key={user.userId} value={user.userId}>
                          {user.username} ({user.balance} credits)
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Amount (+/-)</Label>
                  <Input
                    type="number"
                    placeholder="+500 or -100"
                    value={creditAdjustment}
                    onChange={(e) => setCreditAdjustment(e.target.value)}
                    data-testid="input-credit-amount"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Reason</Label>
                  <Input
                    placeholder="Reason for adjustment"
                    value={adjustmentReason}
                    onChange={(e) => setAdjustmentReason(e.target.value)}
                    data-testid="input-credit-reason"
                  />
                </div>
                <div className="flex items-end">
                  <Button
                    onClick={handleAdjustCredits}
                    disabled={!selectedUser || !creditAdjustment || adjustCreditsMutation.isPending}
                    data-testid="button-apply-credit-adjustment"
                  >
                    Apply Adjustment
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>User Credits Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Username</TableHead>
                    <TableHead>Plan Level</TableHead>
                    <TableHead className="text-right">Balance</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users?.map((user) => (
                    <TableRow key={user.userId}>
                      <TableCell className="font-medium">{user.username}</TableCell>
                      <TableCell>
                        <Badge variant={user.planLevel === "ELITE" ? "default" : "secondary"}>
                          {user.planLevel}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">{user.balance.toLocaleString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="agents" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Agent System Controls
              </CardTitle>
              <CardDescription>Enable or disable agents for maintenance</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {stats?.agentStatus?.map((agent) => (
                  <div key={agent.agentId} className="flex items-center justify-between p-4 border rounded-lg" data-testid={`agent-control-${agent.agentId}`}>
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-full ${agent.enabled ? "bg-green-100 dark:bg-green-900" : "bg-red-100 dark:bg-red-900"}`}>
                        {agent.enabled ? (
                          <CheckCircle2 className="h-5 w-5 text-green-600" />
                        ) : (
                          <XCircle className="h-5 w-5 text-red-600" />
                        )}
                      </div>
                      <div>
                        <p className="font-medium">{agent.agentName}</p>
                        <p className="text-sm text-muted-foreground">{agent.description || `ID: ${agent.agentId}`}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <Badge variant={agent.enabled ? "default" : "destructive"} data-testid={`badge-agent-status-${agent.agentId}`}>
                        {agent.enabled ? "Active" : "Disabled"}
                      </Badge>
                      <Switch
                        checked={agent.enabled}
                        onCheckedChange={(checked) =>
                          toggleAgentMutation.mutate({ agentId: agent.agentId, enabled: checked })
                        }
                        data-testid={`switch-agent-${agent.agentId}`}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
                Fallback Audit
              </CardTitle>
              <CardDescription>Autonomous fixes vs manual fallbacks (missing WAF API keys)</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="p-4 border rounded-lg bg-green-50 dark:bg-green-950">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap className="h-5 w-5 text-green-600" />
                    <span className="font-medium">Autonomous Fixes</span>
                  </div>
                  <div className="text-3xl font-bold text-green-600">
                    {stats?.fallbackAudit?.autonomousFixes || 0}
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">WAF API deployed automatically</p>
                </div>
                <div className="p-4 border rounded-lg bg-yellow-50 dark:bg-yellow-950">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="h-5 w-5 text-yellow-600" />
                    <span className="font-medium">Manual Fallbacks</span>
                  </div>
                  <div className="text-3xl font-bold text-yellow-600">
                    {stats?.fallbackAudit?.manualFallbacks || 0}
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">Copy-paste rules generated</p>
                </div>
              </div>
              <Separator className="my-4" />
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Automation Rate</span>
                <span className="font-medium">
                  {stats?.fallbackAudit
                    ? Math.round(
                        (stats.fallbackAudit.autonomousFixes /
                          (stats.fallbackAudit.autonomousFixes + stats.fallbackAudit.manualFallbacks || 1)) *
                          100
                      )
                    : 0}
                  %
                </span>
              </div>
              <Progress
                value={
                  stats?.fallbackAudit
                    ? (stats.fallbackAudit.autonomousFixes /
                        (stats.fallbackAudit.autonomousFixes + stats.fallbackAudit.manualFallbacks || 1)) *
                      100
                    : 0
                }
                className="mt-2"
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="performance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                Agent Performance Monitoring
              </CardTitle>
              <CardDescription>Success rates and runtime for critical agents</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Agent</TableHead>
                    <TableHead>Success Rate</TableHead>
                    <TableHead>Avg Runtime</TableHead>
                    <TableHead className="text-right">Total Runs</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {stats?.agentPerformance?.map((agent) => (
                    <TableRow key={agent.agentId}>
                      <TableCell className="font-medium">{agent.agentName}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Progress value={agent.successRate} className="w-20" />
                          <span className="text-sm">{agent.successRate}%</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Clock className="h-4 w-4 text-muted-foreground" />
                          {agent.avgRuntime}s
                        </div>
                      </TableCell>
                      <TableCell className="text-right">{agent.totalRuns}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threat-feeds" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                Threat Intelligence Feed Management
              </CardTitle>
              <CardDescription>Configure premium threat intelligence API sources</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                {stats?.threatFeeds?.map((feed) => (
                  <div key={feed.feedId} className="flex items-center justify-between p-4 border rounded-lg" data-testid={`threat-feed-${feed.feedId}`}>
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-full ${feed.enabled && feed.hasApiKey ? "bg-green-100 dark:bg-green-900" : "bg-slate-100 dark:bg-slate-800"}`}>
                        <Key className={`h-5 w-5 ${feed.enabled && feed.hasApiKey ? "text-green-600" : "text-muted-foreground"}`} />
                      </div>
                      <div>
                        <p className="font-medium">{feed.feedName}</p>
                        <p className="text-sm text-muted-foreground">
                          {feed.hasApiKey ? "API Key configured" : "No API key set"}
                          {feed.lastSync && ` | Last sync: ${new Date(feed.lastSync).toLocaleString()}`}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge variant={feed.hasApiKey && feed.enabled ? "default" : "outline"}>
                        {feed.hasApiKey && feed.enabled ? "Active" : feed.hasApiKey ? "Ready" : "Not Configured"}
                      </Badge>
                      <Switch
                        checked={feed.enabled}
                        disabled={!feed.hasApiKey}
                        onCheckedChange={(checked) =>
                          updateThreatFeedMutation.mutate({ feedId: feed.feedId, enabled: checked })
                        }
                        data-testid={`switch-threat-feed-${feed.feedId}`}
                      />
                    </div>
                  </div>
                ))}
              </div>

              <Separator />

              <div className="space-y-4">
                <Label className="text-sm font-medium">Configure API Key</Label>
                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">Select Feed</Label>
                    <Select value={selectedThreatFeed} onValueChange={setSelectedThreatFeed}>
                      <SelectTrigger data-testid="select-threat-feed">
                        <SelectValue placeholder="Choose feed..." />
                      </SelectTrigger>
                      <SelectContent>
                        {stats?.threatFeeds?.map((feed) => (
                          <SelectItem key={feed.feedId} value={feed.feedId}>
                            {feed.feedName}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">API Key</Label>
                    <Input
                      type="password"
                      placeholder="Enter API key..."
                      value={threatFeedApiKey}
                      onChange={(e) => setThreatFeedApiKey(e.target.value)}
                      data-testid="input-threat-feed-api-key"
                    />
                  </div>
                  <div className="flex items-end">
                    <Button
                      onClick={() => {
                        if (selectedThreatFeed && threatFeedApiKey) {
                          updateThreatFeedMutation.mutate({
                            feedId: selectedThreatFeed,
                            apiKey: threatFeedApiKey,
                            enabled: true,
                          });
                        }
                      }}
                      disabled={!selectedThreatFeed || !threatFeedApiKey || updateThreatFeedMutation.isPending}
                      data-testid="button-save-threat-feed"
                    >
                      <Key className="h-4 w-4 mr-2" />
                      Save API Key
                    </Button>
                  </div>
                </div>
              </div>

              <Separator />

              <div>
                <Label className="text-sm font-medium mb-2 block">Active Feed Source</Label>
                <Select defaultValue="internal">
                  <SelectTrigger className="w-[300px]" data-testid="select-active-feed-source">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="internal">Internal ShadowTwin Intelligence</SelectItem>
                    {stats?.threatFeeds?.filter(f => f.hasApiKey && f.enabled).map((feed) => (
                      <SelectItem key={feed.feedId} value={feed.feedId}>
                        {feed.feedName}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
