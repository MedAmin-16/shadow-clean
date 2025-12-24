import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, Filter, X, ChevronDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "./SeverityBadge";

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface VulnerabilityDetail {
  id: string;
  title: string;
  severity: Severity;
  cvss?: number;
  url?: string;
  payload?: string;
  responseSnippet?: string;
  description?: string;
  remediationCode?: string;
  timestamp?: string;
  tool?: string;
}

interface ScanResultsPageProps {
  vulnerabilities: VulnerabilityDetail[];
}

function getSeverityColor(severity: Severity): string {
  const colors: Record<Severity, string> = {
    critical: "bg-red-500/20 text-red-300 border-red-500/40",
    high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
    medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
    low: "bg-blue-500/20 text-blue-300 border-blue-500/40",
    info: "bg-green-500/20 text-green-300 border-green-500/40",
  };
  return colors[severity];
}

function getSeverityCvssRange(severity: Severity): string {
  const ranges: Record<Severity, string> = {
    critical: "CVSS 9.0-10.0",
    high: "CVSS 7.0-8.9",
    medium: "CVSS 4.0-6.9",
    low: "CVSS 0.1-3.9",
    info: "CVSS 0.0",
  };
  return ranges[severity];
}

function SeveritySummaryBar({ vulnerabilities }: { vulnerabilities: VulnerabilityDetail[] }) {
  const counts = {
    critical: vulnerabilities.filter(v => v.severity === "critical").length,
    high: vulnerabilities.filter(v => v.severity === "high").length,
    medium: vulnerabilities.filter(v => v.severity === "medium").length,
    low: vulnerabilities.filter(v => v.severity === "low").length,
    info: vulnerabilities.filter(v => v.severity === "info").length,
  };

  const severityIcons: Record<Severity, string> = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🔵",
    info: "🟢",
  };

  return (
    <div className="bg-gradient-to-r from-black/40 to-black/20 border border-white/10 rounded-lg p-4 mb-6">
      <div className="flex flex-wrap gap-4 items-center justify-start">
        <span className="text-sm font-semibold text-gray-300">Summary:</span>
        {(Object.keys(counts) as Severity[]).map((severity) => (
          counts[severity] > 0 && (
            <div key={severity} className="flex items-center gap-2 px-3 py-2 bg-white/5 rounded-lg border border-white/10">
              <span className="text-lg">{severityIcons[severity]}</span>
              <span className="text-sm font-medium">{counts[severity]} {severity.charAt(0).toUpperCase() + severity.slice(1)}</span>
            </div>
          )
        ))}
        <div className="ml-auto">
          <span className="text-sm text-gray-400">Total: {vulnerabilities.length} findings</span>
        </div>
      </div>
    </div>
  );
}

function VulnerabilityDetailModal({ 
  vuln, 
  onClose 
}: { 
  vuln: VulnerabilityDetail; 
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
      <Card className="w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-black border-white/20">
        <CardHeader className="flex flex-row items-start justify-between gap-4 pb-4">
          <div className="flex-1">
            <CardTitle className="text-lg">{vuln.title}</CardTitle>
            <p className="text-xs text-gray-400 mt-2">{vuln.description}</p>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Severity & CVSS */}
          <div className="flex items-center gap-3 p-3 bg-white/5 rounded-lg border border-white/10">
            <SeverityBadge severity={vuln.severity} />
            <span className="text-sm text-gray-300">{getSeverityCvssRange(vuln.severity)}</span>
            {vuln.cvss && <span className="text-sm font-mono text-cyan-300">Score: {vuln.cvss}</span>}
          </div>

          {/* Proof of Concept */}
          <div className="space-y-3">
            <h4 className="font-semibold text-sm text-white flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Proof of Concept
            </h4>

            {/* URL */}
            {vuln.url && (
              <div className="p-3 bg-black/50 border border-white/10 rounded-lg">
                <p className="text-xs text-gray-400 mb-1">Target URL:</p>
                <p className="text-sm font-mono text-cyan-300 break-all">{vuln.url}</p>
              </div>
            )}

            {/* Payload */}
            {vuln.payload && (
              <div className="p-3 bg-black/50 border border-white/10 rounded-lg">
                <p className="text-xs text-gray-400 mb-1">Payload Used:</p>
                <code className="text-sm font-mono text-orange-300 block overflow-x-auto whitespace-pre">
                  {vuln.payload}
                </code>
              </div>
            )}

            {/* Response Snippet */}
            {vuln.responseSnippet && (
              <div className="p-3 bg-black/50 border border-white/10 rounded-lg">
                <p className="text-xs text-gray-400 mb-1">Server Response:</p>
                <code className="text-sm font-mono text-green-300 block overflow-x-auto whitespace-pre-wrap break-words">
                  {vuln.responseSnippet}
                </code>
              </div>
            )}
          </div>

          {/* Remediation */}
          {vuln.remediationCode && (
            <div className="space-y-2">
              <h4 className="font-semibold text-sm text-white">Remediation</h4>
              <div className="p-3 bg-black/50 border border-green-500/30 rounded-lg">
                <code className="text-sm font-mono text-green-300 block overflow-x-auto whitespace-pre">
                  {vuln.remediationCode}
                </code>
              </div>
            </div>
          )}

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-3 pt-4 border-t border-white/10">
            {vuln.tool && (
              <div>
                <p className="text-xs text-gray-400">Detection Tool</p>
                <p className="text-sm text-white font-mono">{vuln.tool}</p>
              </div>
            )}
            {vuln.timestamp && (
              <div>
                <p className="text-xs text-gray-400">Found At</p>
                <p className="text-sm text-white">{vuln.timestamp}</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function VulnerabilityRow({ 
  vuln, 
  onClick 
}: { 
  vuln: VulnerabilityDetail; 
  onClick: () => void;
}) {
  const severityGradient: Record<Severity, string> = {
    critical: "from-red-600/10 to-red-500/5 border-red-500/20 hover:border-red-500/40",
    high: "from-orange-600/10 to-orange-500/5 border-orange-500/20 hover:border-orange-500/40",
    medium: "from-yellow-600/10 to-yellow-500/5 border-yellow-500/20 hover:border-yellow-500/40",
    low: "from-blue-600/10 to-blue-500/5 border-blue-500/20 hover:border-blue-500/40",
    info: "from-green-600/10 to-green-500/5 border-green-500/20 hover:border-green-500/40",
  };

  return (
    <button
      onClick={onClick}
      className={`w-full text-left p-4 bg-gradient-to-br ${severityGradient[vuln.severity]} border rounded-lg hover:shadow-lg transition-all duration-200 group`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2">
            <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5" />
            <h4 className="font-semibold text-sm text-white truncate">{vuln.title}</h4>
          </div>
          {vuln.url && <p className="text-xs text-gray-400 font-mono truncate ml-7">{vuln.url}</p>}
        </div>
        <div className="flex flex-col items-end gap-2 flex-shrink-0">
          <SeverityBadge severity={vuln.severity} />
          <span className="text-xs text-gray-500 whitespace-nowrap">{getSeverityCvssRange(vuln.severity)}</span>
        </div>
      </div>
    </button>
  );
}

export function ScanResultsPage({ vulnerabilities }: ScanResultsPageProps) {
  const [showCriticalOnly, setShowCriticalOnly] = useState(false);
  const [expandedVuln, setExpandedVuln] = useState<VulnerabilityDetail | null>(null);

  const filteredVulnerabilities = useMemo(() => {
    if (showCriticalOnly) {
      return vulnerabilities.filter(v => v.severity === "critical" || v.severity === "high");
    }
    return vulnerabilities;
  }, [vulnerabilities, showCriticalOnly]);

  // Group by severity
  const groupedVulnerabilities = useMemo(() => {
    const groups: Record<Severity, VulnerabilityDetail[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: [],
    };
    
    filteredVulnerabilities.forEach(v => {
      groups[v.severity].push(v);
    });
    
    return groups;
  }, [filteredVulnerabilities]);

  return (
    <div className="space-y-6">
      {/* Header with Filter */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white">Scan Results</h1>
          <p className="text-sm text-gray-400 mt-1">
            {vulnerabilities.length} total findings | {filteredVulnerabilities.length} displayed
          </p>
        </div>
        <Button
          onClick={() => setShowCriticalOnly(!showCriticalOnly)}
          variant={showCriticalOnly ? "default" : "outline"}
          className="gap-2"
        >
          <Filter className="h-4 w-4" />
          {showCriticalOnly ? "Showing Critical & High" : "Show All"}
        </Button>
      </div>

      {/* Severity Summary Bar */}
      <SeveritySummaryBar vulnerabilities={vulnerabilities} />

      {/* Vulnerability Groups */}
      <div className="space-y-6">
        {(Object.keys(groupedVulnerabilities) as Severity[]).map((severity) => {
          const vulns = groupedVulnerabilities[severity];
          if (vulns.length === 0) return null;

          return (
            <div key={severity} className="space-y-3">
              <div className="flex items-center gap-3">
                <Badge className={`px-3 py-1 ${getSeverityColor(severity)}`}>
                  {severity.toUpperCase()} ({vulns.length})
                </Badge>
                <span className="text-xs text-gray-500">{getSeverityCvssRange(severity)}</span>
              </div>
              <div className="space-y-2">
                {vulns.map((vuln) => (
                  <VulnerabilityRow
                    key={vuln.id}
                    vuln={vuln}
                    onClick={() => setExpandedVuln(vuln)}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* Empty State */}
      {vulnerabilities.length === 0 && (
        <div className="text-center py-12">
          <AlertTriangle className="h-12 w-12 mx-auto text-gray-600 mb-4" />
          <p className="text-gray-400">No vulnerabilities found</p>
        </div>
      )}

      {/* Detail Modal */}
      {expandedVuln && (
        <VulnerabilityDetailModal
          vuln={expandedVuln}
          onClose={() => setExpandedVuln(null)}
        />
      )}
    </div>
  );
}
