import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Shield, Search, AlertTriangle, User, ExternalLink, RefreshCw } from "lucide-react";
import { Progress } from "@/components/ui/progress";

interface LeakedEmail {
  id: string;
  email: string;
  breachNames: string;
  riskLevel: "high" | "medium" | "low";
  leakedAt: string;
}

interface RadarData {
  id: string;
  targetDomain: string;
  riskScore: number;
  totalLeakedEmails: number;
  status: "pending" | "in_progress" | "completed" | "failed";
  lastScannedAt: string;
  leaks: LeakedEmail[];
}

export function EmployeeRiskRadar() {
  const [domain, setDomain] = useState("");
  
  const { data: radarResponse, isLoading } = useQuery<{ success: boolean; data: RadarData | { status: string } }>({
    queryKey: ["/api/employee-radar"],
  });

  const scanMutation = useMutation({
    mutationFn: async (domain: string) => {
      const res = await apiRequest("POST", "/api/employee-radar/scan", { domain });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/employee-radar"] });
    },
  });

  const radarData = radarResponse?.success && "id" in radarResponse.data ? radarResponse.data as RadarData : null;
  const isNoData = !radarData || (radarResponse?.success && "status" in radarResponse.data && radarResponse.data.status === "no_data");

  const getRiskColor = (score: number) => {
    if (score >= 70) return "text-red-500";
    if (score >= 40) return "text-yellow-500";
    return "text-green-500";
  };

  const getSeverityBadge = (level: string) => {
    switch (level) {
      case "high": return <Badge variant="destructive" className="bg-red-500/20 text-red-500 border-red-500/50">CRITICAL</Badge>;
      case "medium": return <Badge variant="outline" className="text-yellow-500 border-yellow-500/50">ELEVATED</Badge>;
      default: return <Badge variant="secondary">MONITORED</Badge>;
    }
  };

  return (
    <Card className="border-purple-500/30 bg-black/40 backdrop-blur-sm">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-purple-500" />
            <CardTitle>Employee Risk Radar</CardTitle>
            <Badge className="bg-purple-500/20 text-purple-400 border-purple-500/50 ml-2">ELITE ONLY</Badge>
          </div>
          <div className="flex gap-2">
            <Input 
              placeholder="target.com" 
              className="w-48 h-8 bg-black/50 border-purple-500/30" 
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
            />
            <Button 
              size="sm" 
              className="h-8 bg-purple-600 hover:bg-purple-700"
              onClick={() => domain && scanMutation.mutate(domain)}
              disabled={scanMutation.isPending || !domain}
            >
              {scanMutation.isPending ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4 mr-1" />}
              Scan
            </Button>
          </div>
        </div>
        <CardDescription>
          Identify leaked employee credentials and assess human-factor risk across your domain.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isNoData ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <User className="h-12 w-12 text-muted-foreground/30 mb-2" />
            <p className="text-sm text-muted-foreground">No domain analysis found. Enter a domain to start intelligence gathering.</p>
          </div>
        ) : radarData.status === "in_progress" ? (
          <div className="py-8 space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span className="animate-pulse">Harvesting leaked emails from OSINT sources...</span>
              <span>Scanning...</span>
            </div>
            <Progress value={45} className="h-2 bg-purple-900/20" indicatorClassName="bg-purple-500" />
          </div>
        ) : (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-lg bg-purple-500/5 border border-purple-500/10">
                <p className="text-xs text-purple-400 font-medium uppercase tracking-wider mb-1">Human Factor Risk</p>
                <p className={`text-3xl font-bold ${getRiskColor(radarData.riskScore)}`}>{radarData.riskScore}%</p>
                <div className="mt-2 h-1 w-full bg-black/30 rounded-full overflow-hidden">
                  <div className={`h-full ${radarData.riskScore > 50 ? 'bg-red-500' : 'bg-green-500'}`} style={ { width: `${radarData.riskScore}%` } }></div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-purple-500/5 border border-purple-500/10">
                <p className="text-xs text-purple-400 font-medium uppercase tracking-wider mb-1">Leaked Identities</p>
                <p className="text-3xl font-bold text-white">{radarData.totalLeakedEmails}</p>
                <p className="text-xs text-muted-foreground mt-1">Found across known data breaches</p>
              </div>
              <div className="p-4 rounded-lg bg-purple-500/5 border border-purple-500/10">
                <p className="text-xs text-purple-400 font-medium uppercase tracking-wider mb-1">Analysis Target</p>
                <p className="text-3xl font-bold text-white truncate">{radarData.targetDomain}</p>
                <p className="text-xs text-muted-foreground mt-1">Last scanned: {new Date(radarData.lastScannedAt).toLocaleDateString()}</p>
              </div>
            </div>

            <div className="space-y-3">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                Compromised Employee Intelligence
              </h4>
              <div className="rounded-md border border-purple-500/20 overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-purple-900/10">
                    <tr className="border-b border-purple-500/20">
                      <th className="text-left p-3 font-medium text-purple-300">Employee Email</th>
                      <th className="text-left p-3 font-medium text-purple-300">Source Breaches</th>
                      <th className="text-center p-3 font-medium text-purple-300">Risk Level</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-purple-500/10">
                    {radarData.leaks.map((leak) => (
                      <tr key={leak.id} className="hover:bg-purple-500/5 transition-colors">
                        <td className="p-3 font-mono text-xs">{leak.email}</td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {leak.breachNames.split(',').map((b, idx) => (
                              <span key={idx} className="px-2 py-0.5 rounded-full bg-black/40 border border-purple-500/20 text-[10px]">
                                {b.trim()}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="p-3 text-center">
                          {getSeverityBadge(leak.riskLevel)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            
            <div className="flex justify-center">
              <p className="text-[10px] text-muted-foreground italic">
                "Your employees' stolen credentials are the easiest way into your company. We monitor them 24/7."
              </p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
