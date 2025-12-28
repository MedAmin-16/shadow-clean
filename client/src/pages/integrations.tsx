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
  Diamond,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

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
  const [upgradeDialogOpen, setUpgradeDialogOpen] = useState(false);

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

  const WafCardWrapper = ({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) => (
    <div className="relative group">
      {!isElite && (
        <div 
          className="absolute inset-0 z-10 cursor-pointer flex items-center justify-center bg-black/5 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity" 
          onClick={() => setUpgradeDialogOpen(true)}
        >
          <div className="bg-purple-600 text-white px-4 py-2 rounded-full flex items-center gap-2 shadow-xl shadow-purple-500/20">
            <Diamond className="h-4 w-4" />
            <span className="font-bold text-sm">ELITE ONLY</span>
          </div>
        </div>
      )}
      <div className={!isElite ? "filter blur-[1px] grayscale pointer-events-none" : ""}>
        {children}
      </div>
    </div>
  );

  return (
    <div className="p-6 space-y-6 max-w-4xl" data-testid="page-integrations">
      <Dialog open={upgradeDialogOpen} onOpenChange={setUpgradeDialogOpen}>
        <DialogContent className="sm:max-w-md bg-black/95 border-purple-500/30">
          <DialogHeader>
            <DialogTitle className="text-2xl font-bold flex items-center gap-2 text-purple-400">
              <Diamond className="h-6 w-6" />
              Upgrade to Elite
            </DialogTitle>
            <DialogDescription className="text-lg pt-4 text-gray-300 leading-relaxed">
              Automate your security with WAF Hotfixes. Upgrade to Elite Pack to connect 
              <strong> Cloudflare</strong>, <strong>AWS</strong>, or <strong>Akamai</strong>.
            </DialogDescription>
          </DialogHeader>
          <div className="py-6 space-y-4">
            <div className="p-4 bg-purple-500/10 border border-purple-500/20 rounded-lg">
              <h4 className="font-semibold text-purple-300 mb-2">Why Elite?</h4>
              <ul className="text-sm text-gray-400 space-y-2">
                <li>• Instant exploit blocking via Cloudflare/AWS API</li>
                <li>• Automated rule generation from scan findings</li>
                <li>• Zero-day hotfix deployment</li>
              </ul>
            </div>
            <Button className="w-full bg-purple-600 hover:bg-purple-700 h-12 text-lg font-bold" onClick={() => setUpgradeDialogOpen(false)}>
              Upgrade Now
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <div>
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <Key className="h-6 w-6 text-primary" />
          Integrations Settings
        </h1>
        <p className="text-muted-foreground">
          Connect your WAF services for automated security hotfix deployment
        </p>
      </div>

      <div className="grid gap-6">
        <WafCardWrapper>
          <Card className="border-orange-500/30 bg-gradient-to-br from-orange-500/5 to-transparent">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-orange-100 dark:bg-orange-900 rounded-lg shadow-lg">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/9/94/Cloudflare_Logo.png" alt="Cloudflare" className="h-6 object-contain" />
                  </div>
                  <div>
                    <CardTitle>Cloudflare WAF</CardTitle>
                    <CardDescription>Automated WAF rule deployment to Cloudflare Edge</CardDescription>
                  </div>
                </div>
                {isElite && (cloudflareStatus?.connected ? (
                  <Badge className="bg-green-500">
                    <CheckCircle2 className="h-3 w-3 mr-1" />
                    Connected
                  </Badge>
                ) : (
                  <Badge variant="secondary">
                    <XCircle className="h-3 w-3 mr-1" />
                    Not Connected
                  </Badge>
                ))}
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
                  <Button onClick={handleSaveCloudflare} disabled={saveIntegrationMutation.isPending}>
                    <Shield className="h-4 w-4 mr-2" />
                    Save & Connect
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </WafCardWrapper>

        <WafCardWrapper>
          <Card className="border-yellow-500/30 bg-gradient-to-br from-yellow-500/5 to-transparent">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-slate-100 dark:bg-slate-800 rounded-lg shadow-lg">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/9/93/Amazon_Web_Services_Logo.svg" alt="AWS" className="h-6 object-contain" />
                  </div>
                  <div>
                    <CardTitle>AWS WAF</CardTitle>
                    <CardDescription>Automated rule deployment to AWS Web Application Firewall</CardDescription>
                  </div>
                </div>
                {isElite && (awsStatus?.connected ? (
                  <Badge className="bg-green-500">
                    <CheckCircle2 className="h-3 w-3 mr-1" />
                    Connected
                  </Badge>
                ) : (
                  <Badge variant="secondary">
                    <XCircle className="h-3 w-3 mr-1" />
                    Not Connected
                  </Badge>
                ))}
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
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-3">
                    <div className="space-y-2">
                      <Label htmlFor="aws-access-key">Access Key ID</Label>
                      <Input
                        id="aws-access-key"
                        type={showAwsKey ? "text" : "password"}
                        placeholder="AKIAIOSFODNN7EXAMPLE"
                        value={awsAccessKey}
                        onChange={(e) => setAwsAccessKey(e.target.value)}
                      />
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
                  <Button onClick={handleSaveAws} disabled={saveIntegrationMutation.isPending}>
                    <Shield className="h-4 w-4 mr-2" />
                    Save & Connect
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </WafCardWrapper>
      </div>

      <Separator />

      <Card className="bg-gradient-to-r from-blue-900/10 to-purple-900/10 border-blue-500/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-blue-400" />
            Elite Automated Response Workflow
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3 text-center">
            <div className="p-4 bg-black/20 rounded-lg border border-blue-500/10">
              <div className="text-2xl font-bold text-blue-400 mb-1">Detect</div>
              <p className="text-xs text-gray-400">Agent identifies critical injection or auth flaw</p>
            </div>
            <div className="p-4 bg-black/20 rounded-lg border border-blue-500/10">
              <div className="text-2xl font-bold text-purple-400 mb-1">Analyze</div>
              <p className="text-xs text-gray-400">AI generates optimized payload blocking rules</p>
            </div>
            <div className="p-4 bg-black/20 rounded-lg border border-blue-500/10">
              <div className="text-2xl font-bold text-cyan-400 mb-1">Protect</div>
              <p className="text-xs text-gray-400">Rules are instantly pushed to Cloudflare/AWS edge</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
