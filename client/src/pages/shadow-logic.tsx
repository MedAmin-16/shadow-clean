import { useState, useEffect, useCallback, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Checkbox } from "@/components/ui/checkbox";
import { ShadowLogicTerminal } from "@/components/ShadowLogicTerminal";
import { Brain, Shield, AlertTriangle, Crown, Play, StopCircle, Target, Zap, Eye } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { io, Socket } from "socket.io-client";
import type { 
  ShadowLogicThought, 
  ShadowLogicTestType,
  ShadowLogicScanResult 
} from "@shared/shadowLogic";

interface CostData {
  success: boolean;
  data: {
    baseCost: number;
    aiAnalysisCost: number;
    estimatedTotal: number;
    currentBalance: number;
    canRun: boolean;
    hasAccess: boolean;
    planLevel: string;
  };
}

interface ScanStartResponse {
  success: boolean;
  scanId: string;
  message: string;
  estimatedCost: number;
}

interface ThoughtsResponse {
  success: boolean;
  data: ShadowLogicThought[];
  status: string;
}

interface ResultResponse {
  success: boolean;
  data: ShadowLogicScanResult;
}

const TEST_TYPE_OPTIONS: { id: ShadowLogicTestType; label: string; description: string }[] = [
  { id: "price_manipulation", label: "Price Manipulation", description: "Test for price tampering in checkout flows" },
  { id: "quantity_manipulation", label: "Quantity Manipulation", description: "Test for negative quantities and inventory exploits" },
  { id: "privilege_escalation", label: "Privilege Escalation", description: "Test for unauthorized admin access" },
  { id: "idor", label: "IDOR", description: "Test for insecure direct object references" },
  { id: "workflow_bypass", label: "Workflow Bypass", description: "Test for step-skipping in business processes" },
  { id: "parameter_tampering", label: "Parameter Tampering", description: "Test for hidden parameter manipulation" },
];

export default function ShadowLogicPage() {
  const [targetUrl, setTargetUrl] = useState("");
  const [registrationUrl, setRegistrationUrl] = useState("");
  const [selectedTests, setSelectedTests] = useState<ShadowLogicTestType[]>([
    "price_manipulation",
    "quantity_manipulation",
    "privilege_escalation",
    "idor",
    "workflow_bypass",
  ]);
  const [safetyMode, setSafetyMode] = useState(true);
  const [maxDepth, setMaxDepth] = useState(5);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [thoughts, setThoughts] = useState<ShadowLogicThought[]>([]);
  const [scanResult, setScanResult] = useState<ShadowLogicScanResult | null>(null);
  const [lastThoughtId, setLastThoughtId] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);
  const [userId, setUserId] = useState<string | null>(null);

  // Initialize socket connection
  useEffect(() => {
    if (!socketRef.current) {
      socketRef.current = io();
      socketRef.current.on("connect", () => {
        const id = socketRef.current?.id;
        console.log("[ShadowLogic] Socket connected:", id);
      });
      socketRef.current.on("error", (error: any) => {
        console.error("[ShadowLogic] Socket error:", error);
      });
    }
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, []);

  // Get userId from auth
  useEffect(() => {
    const fetchUserId = async () => {
      try {
        const response = await fetch("/api/user/me", { credentials: "include" });
        if (response.ok) {
          const data = await response.json();
          setUserId(data.userId);
          if (socketRef.current) {
            socketRef.current.emit("authenticate", data.userId);
          }
        }
      } catch (error) {
        console.error("Failed to fetch user:", error);
      }
    };
    fetchUserId();
  }, []);

  // Listen to socket events for progress and URL streaming
  useEffect(() => {
    if (!activeScanId || !socketRef.current) return;

    console.log("[ShadowLogic] Setting up listeners for scan:", activeScanId);

    const handleSystemEvent = (data: any) => {
      console.log("[ShadowLogic] System event:", data);
      setThoughts((prev) => [
        ...prev,
        {
          id: `system-${Date.now()}`,
          timestamp: new Date().toISOString(),
          type: "observation",
          message: data.message || data,
        } as ShadowLogicThought,
      ]);
    };

    const handleProgress = (data: { progress: number; phase?: string }) => {
      console.log("[ShadowLogic] Progress:", data);
      if (data.progress === 100) {
        // Scan complete
      }
    };

    const handleUrlStream = (data: { url: string }) => {
      console.log("[ShadowLogic] URL discovered:", data.url);
      setThoughts((prev) => [
        ...prev,
        {
          id: `url-${data.url}-${Date.now()}`,
          timestamp: new Date().toISOString(),
          type: "discovery",
          message: `Discovered URL: ${data.url}`,
        } as ShadowLogicThought,
      ]);
    };

    const handlePhaseUpdate = (data: { phase: string }) => {
      console.log("[ShadowLogic] Phase update:", data.phase);
      setThoughts((prev) => [
        ...prev,
        {
          id: `phase-${Date.now()}`,
          timestamp: new Date().toISOString(),
          type: "observation",
          message: `Phase: ${data.phase}`,
        } as ShadowLogicThought,
      ]);
    };

    socketRef.current.on("shadowLogic:system", handleSystemEvent);
    socketRef.current.on("scanProgress", handleProgress);
    socketRef.current.on("urlStream", handleUrlStream);
    socketRef.current.on("phaseUpdate", handlePhaseUpdate);

    return () => {
      socketRef.current?.off("shadowLogic:system", handleSystemEvent);
      socketRef.current?.off("scanProgress", handleProgress);
      socketRef.current?.off("urlStream", handleUrlStream);
      socketRef.current?.off("phaseUpdate", handlePhaseUpdate);
    };
  }, [activeScanId]);

  const { data: costData } = useQuery<CostData>({
    queryKey: ["/api/shadow-logic/cost"],
  });

  const startScanMutation = useMutation({
    mutationFn: async (config: any) => {
      const response = await apiRequest("POST", "/api/shadow-logic/scan", config);
      return response.json() as Promise<ScanStartResponse>;
    },
    onSuccess: (data) => {
      setActiveScanId(data.scanId);
      setThoughts([]);
      setScanResult(null);
      setLastThoughtId(null);
      // Subscribe socket to this scan
      if (socketRef.current) {
        socketRef.current.emit("subscribe:scan", data.scanId);
      }
    },
  });

  const cancelScanMutation = useMutation({
    mutationFn: async (scanId: string) => {
      return apiRequest("DELETE", `/api/shadow-logic/scan/${scanId}`);
    },
    onSuccess: () => {
      setActiveScanId(null);
    },
  });

  const pollThoughts = useCallback(async () => {
    if (!activeScanId) return;

    try {
      const url = lastThoughtId
        ? `/api/shadow-logic/scan/${activeScanId}/thoughts?after=${lastThoughtId}`
        : `/api/shadow-logic/scan/${activeScanId}/thoughts`;
      
      const response = await fetch(url, { credentials: "include" });
      const data: ThoughtsResponse = await response.json();
      
      if (data.data && data.data.length > 0) {
        setThoughts(prev => [...prev, ...data.data]);
        setLastThoughtId(data.data[data.data.length - 1].id);
      }

      if (data.status === "completed" || data.status === "error") {
        const resultResponse = await fetch(`/api/shadow-logic/scan/${activeScanId}/result`, { credentials: "include" });
        const resultData: ResultResponse = await resultResponse.json();
        if (resultData.data) {
          setScanResult(resultData.data);
          setActiveScanId(null);
        }
      }
    } catch (error) {
      console.error("Error polling thoughts:", error);
    }
  }, [activeScanId, lastThoughtId]);

  useEffect(() => {
    if (!activeScanId) return;

    const interval = setInterval(pollThoughts, 1000);
    return () => clearInterval(interval);
  }, [activeScanId, pollThoughts]);

  const handleStartScan = () => {
    if (!targetUrl) return;

    startScanMutation.mutate({
      targetUrl,
      registrationUrl: registrationUrl || undefined,
      testTypes: selectedTests,
      maxDepth,
      safetyMode,
      headless: true,
    });
  };

  const handleTestToggle = (testId: ShadowLogicTestType) => {
    setSelectedTests(prev => 
      prev.includes(testId)
        ? prev.filter(t => t !== testId)
        : [...prev, testId]
    );
  };

  const hasAccess = costData?.data?.hasAccess ?? false;
  const canRun = costData?.data?.canRun ?? false;

  if (!hasAccess) {
    return (
      <div className="p-8">
        <Card className="max-w-2xl mx-auto border-amber-500/50 bg-gradient-to-br from-amber-500/5 to-orange-500/5">
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 p-4 rounded-full bg-amber-500/20">
              <Crown className="w-12 h-12 text-amber-500" />
            </div>
            <CardTitle className="text-2xl">ShadowLogic is an ELITE Feature</CardTitle>
            <CardDescription className="text-lg">
              Unlock autonomous AI-powered business logic vulnerability detection
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="grid gap-4">
              <div className="flex items-center gap-3">
                <Brain className="w-5 h-5 text-purple-400" />
                <span>AI-powered autonomous pentesting agent</span>
              </div>
              <div className="flex items-center gap-3">
                <Eye className="w-5 h-5 text-blue-400" />
                <span>Real-time live terminal with agent thought process</span>
              </div>
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-green-400" />
                <span>Business logic vulnerability detection</span>
              </div>
              <div className="flex items-center gap-3">
                <Zap className="w-5 h-5 text-yellow-400" />
                <span>Automated price, IDOR, and workflow bypass testing</span>
              </div>
            </div>
            <Button className="w-full" size="lg">
              Upgrade to ELITE Plan
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <Brain className="w-8 h-8 text-purple-500" />
            ShadowLogic
            <Badge className="bg-gradient-to-r from-purple-500 to-pink-500 text-white">
              ELITE
            </Badge>
          </h1>
          <p className="text-muted-foreground mt-1">
            Autonomous AI Business Logic Auditor - Thinks and acts like a human pentester
          </p>
        </div>
        {costData?.data && (
          <div className="text-right">
            <p className="text-sm text-muted-foreground">Estimated Cost</p>
            <p className="text-2xl font-bold">{costData.data.estimatedTotal} credits</p>
            <p className="text-sm text-muted-foreground">
              Balance: {costData.data.currentBalance} credits
            </p>
          </div>
        )}
      </div>

      <Tabs defaultValue="scan" className="space-y-6">
        <TabsList>
          <TabsTrigger value="scan">New Scan</TabsTrigger>
          <TabsTrigger value="results" disabled={!scanResult}>
            Results {scanResult && `(${scanResult.vulnerabilities.length})`}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="scan" className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="w-5 h-5" />
                  Target Configuration
                </CardTitle>
                <CardDescription>
                  Configure the target application for business logic testing
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="targetUrl">Target URL *</Label>
                  <Input
                    id="targetUrl"
                    placeholder="https://example.com"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    disabled={!!activeScanId}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="registrationUrl">Registration URL (Optional)</Label>
                  <Input
                    id="registrationUrl"
                    placeholder="https://example.com/signup"
                    value={registrationUrl}
                    onChange={(e) => setRegistrationUrl(e.target.value)}
                    disabled={!!activeScanId}
                  />
                  <p className="text-xs text-muted-foreground">
                    If provided, the agent will attempt to self-register on the target
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="maxDepth">Crawl Depth: {maxDepth}</Label>
                  <Input
                    id="maxDepth"
                    type="range"
                    min={1}
                    max={10}
                    value={maxDepth}
                    onChange={(e) => setMaxDepth(parseInt(e.target.value))}
                    disabled={!!activeScanId}
                    className="w-full"
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="safetyMode">Safety Mode</Label>
                    <p className="text-xs text-muted-foreground">
                      Prevents destructive actions on target
                    </p>
                  </div>
                  <Switch
                    id="safetyMode"
                    checked={safetyMode}
                    onCheckedChange={setSafetyMode}
                    disabled={!!activeScanId}
                  />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  Test Types
                </CardTitle>
                <CardDescription>
                  Select the business logic vulnerabilities to test for
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {TEST_TYPE_OPTIONS.map((test) => (
                  <div key={test.id} className="flex items-start space-x-3">
                    <Checkbox
                      id={test.id}
                      checked={selectedTests.includes(test.id)}
                      onCheckedChange={() => handleTestToggle(test.id)}
                      disabled={!!activeScanId}
                    />
                    <div className="space-y-0.5">
                      <Label htmlFor={test.id} className="font-medium cursor-pointer">
                        {test.label}
                      </Label>
                      <p className="text-xs text-muted-foreground">{test.description}</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {!canRun && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Insufficient Credits</AlertTitle>
              <AlertDescription>
                You need at least {costData?.data?.estimatedTotal} credits to run this scan.
                Current balance: {costData?.data?.currentBalance} credits.
              </AlertDescription>
            </Alert>
          )}

          <div className="flex gap-4">
            {!activeScanId ? (
              <Button
                size="lg"
                onClick={handleStartScan}
                disabled={!targetUrl || !canRun || startScanMutation.isPending || selectedTests.length === 0}
                className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700"
              >
                <Play className="w-4 h-4 mr-2" />
                {startScanMutation.isPending ? "Initializing..." : "Launch ShadowLogic"}
              </Button>
            ) : (
              <Button
                size="lg"
                variant="destructive"
                onClick={() => cancelScanMutation.mutate(activeScanId)}
                disabled={cancelScanMutation.isPending}
              >
                <StopCircle className="w-4 h-4 mr-2" />
                Stop Scan
              </Button>
            )}
          </div>

          <ShadowLogicTerminal
            thoughts={thoughts}
            isActive={!!activeScanId}
          />
        </TabsContent>

        <TabsContent value="results" className="space-y-6">
          {scanResult && (
            <>
              <div className="grid gap-4 md:grid-cols-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Pages Visited
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-bold">{scanResult.statistics.pagesVisited}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      Forms Analyzed
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-bold">{scanResult.statistics.formsAnalyzed}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      API Endpoints
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-bold">{scanResult.statistics.apiEndpointsDiscovered}</p>
                  </CardContent>
                </Card>
                <Card className="bg-red-500/10 border-red-500/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-red-400">
                      Vulnerabilities
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-bold text-red-400">
                      {scanResult.statistics.vulnerabilitiesFound}
                    </p>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>Discovered Vulnerabilities</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {scanResult.vulnerabilities.length === 0 ? (
                    <p className="text-muted-foreground text-center py-8">
                      No business logic vulnerabilities were discovered in this scan.
                    </p>
                  ) : (
                    scanResult.vulnerabilities.map((vuln) => (
                      <Card key={vuln.id} className="border-l-4 border-l-red-500">
                        <CardHeader className="pb-2">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-lg">{vuln.title}</CardTitle>
                            <Badge variant={vuln.severity === "critical" ? "destructive" : "secondary"}>
                              {vuln.severity.toUpperCase()}
                            </Badge>
                          </div>
                          <CardDescription>{vuln.type.replace(/_/g, " ").toUpperCase()}</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <p>{vuln.description}</p>
                          <div className="grid gap-2 text-sm">
                            <div>
                              <span className="font-medium">Affected Endpoint: </span>
                              <code className="bg-muted px-1 py-0.5 rounded">{vuln.affectedEndpoint}</code>
                            </div>
                            <div>
                              <span className="font-medium">Impact: </span>
                              {vuln.impact}
                            </div>
                            <div>
                              <span className="font-medium">Remediation: </span>
                              {vuln.remediation}
                            </div>
                            {vuln.cweId && (
                              <div>
                                <span className="font-medium">CWE: </span>
                                <a
                                  href={`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace("CWE-", "")}.html`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-blue-400 hover:underline"
                                >
                                  {vuln.cweId}
                                </a>
                              </div>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
