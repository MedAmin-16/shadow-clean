import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  Shield,
  Cloud,
  Key,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Lock,
  Eye,
  EyeOff,
  AlertTriangle,
  Zap,
} from "lucide-react";

interface IntegrationStatus {
  id: string;
  name: string;
  vendor: string;
  connected: boolean;
  lastTested: string | null;
  testResult: "success" | "failed" | "pending" | null;
}

interface IntegrationsData {
  planLevel: string;
  integrations: IntegrationStatus[];
}

export default function IntegrationsPage() {
  const { toast } = useToast();
  const [showCloudflareKey, setShowCloudflareKey] = useState(false);
  const [showAwsKey, setShowAwsKey] = useState(false);
  const [cloudflareApiKey, setCloudflareApiKey] = useState("");
  const [cloudflareZoneId, setCloudflareZoneId] = useState("");
  const [awsAccessKey, setAwsAccessKey] = useState("");
  const [awsSecretKey, setAwsSecretKey] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [testingIntegration, setTestingIntegration] = useState<string | null>(null);

  const { data: integrations, isLoading } = useQuery<IntegrationsData>({
    queryKey: ["/api/integrations"],
  });

  const saveIntegrationMutation = useMutation({
    mutationFn: async (data: { integrationId: string; credentials: Record<string, string> }) => {
      const response = await apiRequest("POST", "/api/integrations/save", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integrations"] });
      toast({ title: "Integration saved successfully" });
    },
    onError: () => {
      toast({ title: "Failed to save integration", variant: "destructive" });
    },
  });

  const testIntegrationMutation = useMutation({
    mutationFn: async (integrationId: string) => {
      setTestingIntegration(integrationId);
      const response = await apiRequest("POST", "/api/integrations/test", { integrationId });
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/integrations"] });
      if (data.success) {
        toast({ title: "Connection successful!", description: "Your API key is valid and working." });
      } else {
        toast({ title: "Connection failed", description: data.error, variant: "destructive" });
      }
      setTestingIntegration(null);
    },
    onError: () => {
      toast({ title: "Test failed", variant: "destructive" });
      setTestingIntegration(null);
    },
  });

  const deleteIntegrationMutation = useMutation({
    mutationFn: async (integrationId: string) => {
      const response = await apiRequest("DELETE", `/api/integrations/${integrationId}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/integrations"] });
      toast({ title: "Integration removed" });
    },
    onError: () => {
      toast({ title: "Failed to remove integration", variant: "destructive" });
    },
  });

  const handleSaveCloudflare = () => {
    if (!cloudflareApiKey || !cloudflareZoneId) {
      toast({ title: "Please fill in all fields", variant: "destructive" });
      return;
    }
    saveIntegrationMutation.mutate({
      integrationId: "cloudflare_waf",
      credentials: {
        apiKey: cloudflareApiKey,
        zoneId: cloudflareZoneId,
      },
    });
    setCloudflareApiKey("");
    setCloudflareZoneId("");
  };

  const handleSaveAws = () => {
    if (!awsAccessKey || !awsSecretKey) {
      toast({ title: "Please fill in all fields", variant: "destructive" });
      return;
    }
    saveIntegrationMutation.mutate({
      integrationId: "aws_waf",
      credentials: {
        accessKeyId: awsAccessKey,
        secretAccessKey: awsSecretKey,
        region: awsRegion,
      },
    });
    setAwsAccessKey("");
    setAwsSecretKey("");
  };

  const getIntegrationStatus = (id: string): IntegrationStatus | undefined => {
    return integrations?.integrations?.find((i) => i.id === id);
  };

  const cloudflareStatus = getIntegrationStatus("cloudflare_waf");
  const awsStatus = getIntegrationStatus("aws_waf");

  if (isLoading) {
    return (
      <div className="p-6 flex items-center justify-center">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const isElite = integrations?.planLevel === "ELITE";

  return (
    <div className="p-6 space-y-6 max-w-4xl" data-testid="page-integrations">
      <div>
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <Key className="h-6 w-6 text-primary" />
          Integrations Settings
        </h1>
        <p className="text-muted-foreground">
          Connect your WAF services for automated security hotfix deployment
        </p>
      </div>

      {!isElite && (
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            WAF integrations require an <strong>ELITE</strong> tier subscription. Upgrade to enable
            automated hotfix deployment to your security infrastructure.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-6">
        <Card className={!isElite ? "opacity-60 pointer-events-none" : ""}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-orange-100 dark:bg-orange-900 rounded-lg">
                  <Cloud className="h-6 w-6 text-orange-600" />
                </div>
                <div>
                  <CardTitle>Cloudflare WAF</CardTitle>
                  <CardDescription>Automated WAF rule deployment to Cloudflare</CardDescription>
                </div>
              </div>
              {cloudflareStatus?.connected ? (
                <Badge className="bg-green-500">
                  <CheckCircle2 className="h-3 w-3 mr-1" />
                  Connected
                </Badge>
              ) : (
                <Badge variant="secondary">
                  <XCircle className="h-3 w-3 mr-1" />
                  Not Connected
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {cloudflareStatus?.connected ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-green-50 dark:bg-green-950 rounded-lg">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-5 w-5 text-green-600" />
                    <span className="font-medium">Integration Active</span>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => testIntegrationMutation.mutate("cloudflare_waf")}
                      disabled={testingIntegration === "cloudflare_waf"}
                    >
                      {testingIntegration === "cloudflare_waf" ? (
                        <RefreshCw className="h-4 w-4 animate-spin mr-1" />
                      ) : (
                        <Zap className="h-4 w-4 mr-1" />
                      )}
                      Test Connection
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => deleteIntegrationMutation.mutate("cloudflare_waf")}
                    >
                      Disconnect
                    </Button>
                  </div>
                </div>
                {cloudflareStatus.lastTested && (
                  <p className="text-sm text-muted-foreground">
                    Last tested: {new Date(cloudflareStatus.lastTested).toLocaleString()}
                    {cloudflareStatus.testResult && (
                      <Badge
                        variant={cloudflareStatus.testResult === "success" ? "default" : "destructive"}
                        className="ml-2"
                      >
                        {cloudflareStatus.testResult}
                      </Badge>
                    )}
                  </p>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="cf-api-key">API Token</Label>
                    <div className="relative">
                      <Input
                        id="cf-api-key"
                        type={showCloudflareKey ? "text" : "password"}
                        placeholder="Enter your Cloudflare API token"
                        value={cloudflareApiKey}
                        onChange={(e) => setCloudflareApiKey(e.target.value)}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0"
                        onClick={() => setShowCloudflareKey(!showCloudflareKey)}
                      >
                        {showCloudflareKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="cf-zone-id">Zone ID</Label>
                    <Input
                      id="cf-zone-id"
                      placeholder="Your Cloudflare Zone ID"
                      value={cloudflareZoneId}
                      onChange={(e) => setCloudflareZoneId(e.target.value)}
                    />
                  </div>
                </div>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Lock className="h-4 w-4" />
                  Your API keys are encrypted and stored securely
                </div>
                <Button onClick={handleSaveCloudflare} disabled={saveIntegrationMutation.isPending}>
                  <Shield className="h-4 w-4 mr-2" />
                  Save & Connect
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className={!isElite ? "opacity-60 pointer-events-none" : ""}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-yellow-100 dark:bg-yellow-900 rounded-lg">
                  <Cloud className="h-6 w-6 text-yellow-600" />
                </div>
                <div>
                  <CardTitle>AWS WAF</CardTitle>
                  <CardDescription>Automated rule deployment to AWS Web Application Firewall</CardDescription>
                </div>
              </div>
              {awsStatus?.connected ? (
                <Badge className="bg-green-500">
                  <CheckCircle2 className="h-3 w-3 mr-1" />
                  Connected
                </Badge>
              ) : (
                <Badge variant="secondary">
                  <XCircle className="h-3 w-3 mr-1" />
                  Not Connected
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {awsStatus?.connected ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-green-50 dark:bg-green-950 rounded-lg">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-5 w-5 text-green-600" />
                    <span className="font-medium">Integration Active</span>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => testIntegrationMutation.mutate("aws_waf")}
                      disabled={testingIntegration === "aws_waf"}
                    >
                      {testingIntegration === "aws_waf" ? (
                        <RefreshCw className="h-4 w-4 animate-spin mr-1" />
                      ) : (
                        <Zap className="h-4 w-4 mr-1" />
                      )}
                      Test Connection
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => deleteIntegrationMutation.mutate("aws_waf")}
                    >
                      Disconnect
                    </Button>
                  </div>
                </div>
                {awsStatus.lastTested && (
                  <p className="text-sm text-muted-foreground">
                    Last tested: {new Date(awsStatus.lastTested).toLocaleString()}
                    {awsStatus.testResult && (
                      <Badge
                        variant={awsStatus.testResult === "success" ? "default" : "destructive"}
                        className="ml-2"
                      >
                        {awsStatus.testResult}
                      </Badge>
                    )}
                  </p>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="space-y-2">
                    <Label htmlFor="aws-access-key">Access Key ID</Label>
                    <div className="relative">
                      <Input
                        id="aws-access-key"
                        type={showAwsKey ? "text" : "password"}
                        placeholder="AKIAIOSFODNN7EXAMPLE"
                        value={awsAccessKey}
                        onChange={(e) => setAwsAccessKey(e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="aws-secret-key">Secret Access Key</Label>
                    <div className="relative">
                      <Input
                        id="aws-secret-key"
                        type={showAwsKey ? "text" : "password"}
                        placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                        value={awsSecretKey}
                        onChange={(e) => setAwsSecretKey(e.target.value)}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0"
                        onClick={() => setShowAwsKey(!showAwsKey)}
                      >
                        {showAwsKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="aws-region">Region</Label>
                    <Input
                      id="aws-region"
                      placeholder="us-east-1"
                      value={awsRegion}
                      onChange={(e) => setAwsRegion(e.target.value)}
                    />
                  </div>
                </div>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Lock className="h-4 w-4" />
                  Your API keys are encrypted and stored securely
                </div>
                <Button onClick={handleSaveAws} disabled={saveIntegrationMutation.isPending}>
                  <Shield className="h-4 w-4 mr-2" />
                  Save & Connect
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Separator />

      <Card>
        <CardHeader>
          <CardTitle>How Integrations Work</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="p-4 border rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <div className="p-1.5 bg-blue-100 dark:bg-blue-900 rounded">
                  <span className="text-sm font-bold text-blue-600">1</span>
                </div>
                <span className="font-medium">Scan Completes</span>
              </div>
              <p className="text-sm text-muted-foreground">
                Agent 7 identifies critical vulnerabilities requiring immediate protection
              </p>
            </div>
            <div className="p-4 border rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <div className="p-1.5 bg-blue-100 dark:bg-blue-900 rounded">
                  <span className="text-sm font-bold text-blue-600">2</span>
                </div>
                <span className="font-medium">Rules Generated</span>
              </div>
              <p className="text-sm text-muted-foreground">
                ShadowTwin generates platform-specific WAF rules to block exploit attempts
              </p>
            </div>
            <div className="p-4 border rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <div className="p-1.5 bg-blue-100 dark:bg-blue-900 rounded">
                  <span className="text-sm font-bold text-blue-600">3</span>
                </div>
                <span className="font-medium">Auto-Deploy</span>
              </div>
              <p className="text-sm text-muted-foreground">
                Rules are automatically pushed to your WAF via API (or provided as copy-paste if not
                connected)
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
