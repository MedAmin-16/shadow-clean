import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, ChevronDown, Link2 } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";

interface AttackChain {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium";
  vulnerabilities: string[];
  description: string;
  impact: string;
  reasoning: string;
  exploitPath: string;
}

interface AttackChainsCardProps {
  chains: AttackChain[];
  isLoading?: boolean;
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

export function AttackChainsCard({ chains, isLoading = false }: AttackChainsCardProps) {
  const [expandedChain, setExpandedChain] = useState<string | null>(null);

  if (isLoading) {
    return (
      <Card className="border-gray-200">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="w-5 h-5 text-purple-600" />
            AI Attack Chains
          </CardTitle>
          <CardDescription>Analyzing vulnerability correlations...</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-20 bg-gray-100 rounded animate-pulse" />
        </CardContent>
      </Card>
    );
  }

  if (!chains || chains.length === 0) {
    return (
      <Card className="border-gray-200">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="w-5 h-5 text-purple-600" />
            AI Attack Chains
          </CardTitle>
          <CardDescription>No attack chains identified in current scan</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-gray-500">Good news! No vulnerability chains were detected.</p>
        </CardContent>
      </Card>
    );
  }

  const criticalCount = chains.filter(c => c.severity === "critical").length;
  const highCount = chains.filter(c => c.severity === "high").length;

  return (
    <Card className="border-gray-200">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Link2 className="w-5 h-5 text-purple-600" />
          AI Attack Chains
        </CardTitle>
        <CardDescription>
          Found {chains.length} potential attack chains
          {criticalCount > 0 && (
            <span className="ml-2 text-red-600 font-semibold">
              {criticalCount} critical
            </span>
          )}
          {highCount > 0 && (
            <span className="ml-2 text-orange-600 font-semibold">
              {highCount} high
            </span>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {chains.map((chain) => (
          <div
            key={chain.id}
            className={`border rounded-lg p-4 cursor-pointer transition-all ${
              severityBgColors[chain.severity]
            } ${expandedChain === chain.id ? "ring-2 ring-purple-400" : ""}`}
            onClick={() => setExpandedChain(expandedChain === chain.id ? null : chain.id)}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="font-semibold text-sm">{chain.name}</span>
                  <Badge variant="outline" className={severityColors[chain.severity]}>
                    {chain.severity.toUpperCase()}
                  </Badge>
                </div>
                <p className="text-xs text-gray-600 mb-2">{chain.description}</p>
              </div>
              <ChevronDown
                className={`w-4 h-4 text-gray-500 transition-transform flex-shrink-0 ${
                  expandedChain === chain.id ? "rotate-180" : ""
                }`}
              />
            </div>

            {expandedChain === chain.id && (
              <div className="mt-4 space-y-3 border-t pt-3">
                <div>
                  <p className="text-xs font-semibold text-gray-700 mb-1">Impact:</p>
                  <p className="text-xs text-gray-600">{chain.impact}</p>
                </div>

                <div>
                  <p className="text-xs font-semibold text-gray-700 mb-1">AI Analysis:</p>
                  <p className="text-xs text-gray-600">{chain.reasoning}</p>
                </div>

                <div>
                  <p className="text-xs font-semibold text-gray-700 mb-1">Exploitation Path:</p>
                  <pre className="text-xs bg-gray-100 p-2 rounded overflow-x-auto text-gray-700 whitespace-pre-wrap break-words">
                    {chain.exploitPath}
                  </pre>
                </div>

                <div>
                  <p className="text-xs font-semibold text-gray-700 mb-1">
                    Contributing Vulnerabilities:
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {chain.vulnerabilities.map((vulnId, idx) => (
                      <Badge key={idx} variant="secondary" className="text-xs">
                        #{(idx + 1).toString()}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}

        <div className="bg-blue-50 border border-blue-200 rounded p-3 mt-4">
          <p className="text-xs text-blue-800">
            <strong>💡 Pro Tip:</strong> Attack chains show how multiple vulnerabilities can be
            combined for a more severe impact. Fix critical and high severity chains first to
            prevent complete system compromise.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
