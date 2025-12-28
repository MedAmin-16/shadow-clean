import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AlertTriangle, ChevronDown, Link2, AlertCircle, DollarSign, Scale, Download } from "lucide-react";
import { useState } from "react";

interface AttackChain {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium";
  vulnerabilities: string[];
  description: string;
  impact: string;
  reasoning: string;
  exploitPath: string;
  businessImpact: string;
  estimatedLossMin: number;
  estimatedLossMax: number;
  complianceRisks: string[];
  executiveSummary: string;
}

interface AttackChainsCardProps {
  chains: AttackChain[];
  isLoading?: boolean;
  scanId?: string;
}

const severityColors = {
  critical: "bg-red-100 text-red-800 border-red-300",
  high: "bg-orange-100 text-orange-800 border-orange-300",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-300",
};

const severityBgColors = {
  critical: "bg-red-50 border-red-200",
  high: "bg-orange-50 border-orange-200",
  medium: "bg-yellow-50 border-yellow-200",
};

const businessImpactBadgeColors = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-yellow-600 text-white",
};

function formatCurrency(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(value);
}

export function AttackChainsCard({ chains, isLoading = false, scanId }: AttackChainsCardProps) {
  const [expandedChain, setExpandedChain] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState(false);

  const handleExportReport = async () => {
    if (!scanId) return;
    
    try {
      setIsExporting(true);
      const response = await fetch(`/api/executive-report/${scanId}`, {
        method: "GET",
      });

      if (!response.ok) {
        throw new Error("Failed to generate report");
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `executive-risk-report-${scanId.substring(0, 8)}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Error exporting report:", error);
      alert("Failed to export report. Please try again.");
    } finally {
      setIsExporting(false);
    }
  };

  if (isLoading) {
    return (
      <Card className="border-gray-200">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-600" />
            Enterprise Risk Management
          </CardTitle>
          <CardDescription>Analyzing critical vulnerability chains...</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-20 bg-gray-100 rounded animate-pulse" />
        </CardContent>
      </Card>
    );
  }

  if (!chains || chains.length === 0) {
    return (
      <Card className="border-gray-200 bg-green-50 border-green-200">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-green-600" />
            Enterprise Risk Management
          </CardTitle>
          <CardDescription>No critical attack chains identified</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-green-700 font-medium">✓ Your systems are secure from known vulnerability chains.</p>
        </CardContent>
      </Card>
    );
  }

  const criticalCount = chains.filter(c => c.severity === "critical").length;
  const highCount = chains.filter(c => c.severity === "high").length;
  const totalPotentialLoss = chains.reduce((sum, c) => sum + c.estimatedLossMax, 0);

  return (
    <Card className="border-red-300 bg-red-50">
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2 text-red-900">
            <AlertTriangle className="w-5 h-5 text-red-600" />
            Enterprise Risk Management: Vulnerability Chains
          </CardTitle>
          <CardDescription className="text-red-800 mt-2">
            {chains.length} critical vulnerability chains identified
            {criticalCount > 0 && (
              <span className="ml-3 font-semibold text-red-700">
                {criticalCount} CRITICAL
              </span>
            )}
            {highCount > 0 && (
              <span className="ml-3 font-semibold text-orange-700">
                {highCount} HIGH
              </span>
            )}
          </CardDescription>
        </div>
        {scanId && (
          <Button
            onClick={handleExportReport}
            disabled={isExporting}
            className="bg-blue-600 hover:bg-blue-700 text-white flex items-center gap-2 whitespace-nowrap"
            size="sm"
          >
            <Download className="w-4 h-4" />
            {isExporting ? "Exporting..." : "Export Report"}
          </Button>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Financial Impact Summary */}
        <div className="bg-white border border-red-200 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <DollarSign className="w-5 h-5 text-red-600" />
            <h3 className="font-semibold text-red-900">Potential Financial Exposure</h3>
          </div>
          <div className="text-lg font-bold text-red-700">
            {formatCurrency(chains.reduce((sum, c) => sum + c.estimatedLossMin, 0))} - {formatCurrency(totalPotentialLoss)}
          </div>
          <p className="text-xs text-red-600 mt-2">
            Based on industry averages for data breach recovery, regulatory fines, and customer churn.
          </p>
        </div>

        {/* Attack Chains */}
        <div className="space-y-3">
          {chains.map((chain) => (
            <div
              key={chain.id}
              className={`border rounded-lg p-4 cursor-pointer transition-all ${
                severityBgColors[chain.severity]
              } ${expandedChain === chain.id ? "ring-2 ring-red-500" : ""}`}
              onClick={() => setExpandedChain(expandedChain === chain.id ? null : chain.id)}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <span className="font-semibold text-sm">{chain.name}</span>
                    <Badge className={`${businessImpactBadgeColors[chain.severity]} text-xs font-bold`}>
                      {chain.businessImpact}
                    </Badge>
                  </div>
                  <p className="text-xs text-gray-600 mb-2">{chain.description}</p>
                </div>
                <ChevronDown
                  className={`w-4 h-4 text-gray-500 transition-transform flex-shrink-0 mt-1 ${
                    expandedChain === chain.id ? "rotate-180" : ""
                  }`}
                />
              </div>

              {expandedChain === chain.id && (
                <div className="mt-4 space-y-4 border-t border-gray-300 pt-4">
                  {/* Executive Summary */}
                  <div className="bg-white p-3 rounded border-l-4 border-red-600">
                    <p className="text-sm font-semibold text-gray-800 mb-2">Executive Summary</p>
                    <p className="text-sm text-gray-700 leading-relaxed">{chain.executiveSummary}</p>
                  </div>

                  {/* Financial Impact */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-white p-3 rounded">
                      <p className="text-xs font-semibold text-gray-600 mb-1">Estimated Loss (Low)</p>
                      <p className="text-sm font-bold text-red-700">{formatCurrency(chain.estimatedLossMin)}</p>
                    </div>
                    <div className="bg-white p-3 rounded">
                      <p className="text-xs font-semibold text-gray-600 mb-1">Estimated Loss (High)</p>
                      <p className="text-sm font-bold text-red-700">{formatCurrency(chain.estimatedLossMax)}</p>
                    </div>
                  </div>

                  {/* Compliance Risks */}
                  {chain.complianceRisks.length > 0 && (
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Scale className="w-4 h-4 text-red-600" />
                        <p className="text-xs font-semibold text-gray-700">Regulatory & Compliance Risks</p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {chain.complianceRisks.map((risk, idx) => (
                          <Badge key={idx} variant="outline" className="bg-red-100 text-red-800 border-red-300 text-xs">
                            {risk}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Technical Analysis */}
                  <div>
                    <p className="text-xs font-semibold text-gray-700 mb-2">Technical Analysis</p>
                    <p className="text-xs text-gray-600 mb-3">{chain.reasoning}</p>
                  </div>

                  {/* Exploitation Path */}
                  <div>
                    <p className="text-xs font-semibold text-gray-700 mb-2">Attack Sequence</p>
                    <pre className="text-xs bg-gray-900 text-gray-100 p-3 rounded overflow-x-auto whitespace-pre-wrap break-words font-mono">
                      {chain.exploitPath}
                    </pre>
                  </div>

                  {/* Contributing Vulnerabilities */}
                  <div>
                    <p className="text-xs font-semibold text-gray-700 mb-2">
                      Contributing Vulnerabilities ({chain.vulnerabilities.length})
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {chain.vulnerabilities.map((vulnId, idx) => (
                        <Badge key={idx} variant="secondary" className="text-xs">
                          Vuln #{idx + 1}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Executive Action Items */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-start gap-2">
            <AlertCircle className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-blue-900 mb-2">Immediate Action Required</p>
              <ul className="text-sm text-blue-800 space-y-1">
                <li>• Schedule emergency security review with your team</li>
                <li>• Brief leadership on financial and regulatory exposure</li>
                <li>• Prioritize remediation of chains marked CRITICAL</li>
                <li>• Consider cyber insurance coverage review</li>
                <li>• Notify board/audit committee of findings</li>
              </ul>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
