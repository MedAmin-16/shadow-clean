import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "./SeverityBadge";
import { 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Shield, 
  Lock, 
  Globe, 
  Server,
  ChevronDown,
  ChevronRight
} from "lucide-react";
import { useState } from "react";

interface ScanReport {
  securityScore: number;
  tls: {
    valid: boolean;
    protocol: string;
    expiresIn: string;
  };
  headers: {
    contentSecurityPolicy: boolean;
    xFrameOptions: boolean;
    xContentTypeOptions: boolean;
    strictTransportSecurity: boolean;
  };
  vulnerabilities: Array<{
    id: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    description: string;
  }>;
  recommendations: string[];
}

interface ScanReportViewerProps {
  report: ScanReport;
}

export function ScanReportViewer({ report }: ScanReportViewerProps) {
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    tls: true,
    headers: true,
    vulnerabilities: true,
    recommendations: true,
  });

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const getScoreColor = (s: number) => {
    if (s >= 80) return "text-green-500";
    if (s >= 60) return "text-yellow-500";
    if (s >= 40) return "text-orange-500";
    return "text-red-500";
  };

  const CheckItem = ({ label, passed }: { label: string; passed: boolean }) => (
    <div className="flex items-center justify-between py-2">
      <span className="text-sm">{label}</span>
      {passed ? (
        <CheckCircle2 className="h-4 w-4 text-green-500" />
      ) : (
        <XCircle className="h-4 w-4 text-red-500" />
      )}
    </div>
  );

  const SectionHeader = ({ 
    icon: Icon, 
    title, 
    section, 
    badge 
  }: { 
    icon: typeof Shield; 
    title: string; 
    section: string;
    badge?: React.ReactNode;
  }) => (
    <button
      onClick={() => toggleSection(section)}
      className="flex items-center justify-between w-full p-4 text-left hover-elevate"
      data-testid={`button-toggle-${section}`}
    >
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 text-primary" />
        <span className="font-medium">{title}</span>
        {badge}
      </div>
      {expandedSections[section] ? (
        <ChevronDown className="h-4 w-4 text-muted-foreground" />
      ) : (
        <ChevronRight className="h-4 w-4 text-muted-foreground" />
      )}
    </button>
  );

  return (
    <div className="space-y-4" data-testid="scan-report-viewer">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            Scan Report
          </CardTitle>
          <div className={`text-4xl font-bold ${getScoreColor(report.securityScore)}`}>
            {report.securityScore}/100
          </div>
        </CardHeader>
      </Card>

      <Card>
        <SectionHeader 
          icon={Lock} 
          title="TLS / HTTPS" 
          section="tls"
          badge={
            <Badge variant="outline" className={report.tls.valid ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500"}>
              {report.tls.valid ? "Valid" : "Invalid"}
            </Badge>
          }
        />
        {expandedSections.tls && (
          <CardContent className="pt-0">
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Protocol</span>
                <span className="font-mono">{report.tls.protocol}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Certificate Expires</span>
                <span>{report.tls.expiresIn}</span>
              </div>
            </div>
          </CardContent>
        )}
      </Card>

      <Card>
        <SectionHeader 
          icon={Globe} 
          title="Security Headers" 
          section="headers"
          badge={
            <Badge variant="outline" className="bg-muted">
              {Object.values(report.headers).filter(Boolean).length}/{Object.keys(report.headers).length} passed
            </Badge>
          }
        />
        {expandedSections.headers && (
          <CardContent className="pt-0 divide-y">
            <CheckItem label="Content-Security-Policy" passed={report.headers.contentSecurityPolicy} />
            <CheckItem label="X-Frame-Options" passed={report.headers.xFrameOptions} />
            <CheckItem label="X-Content-Type-Options" passed={report.headers.xContentTypeOptions} />
            <CheckItem label="Strict-Transport-Security" passed={report.headers.strictTransportSecurity} />
          </CardContent>
        )}
      </Card>

      <Card>
        <SectionHeader 
          icon={AlertTriangle} 
          title="Vulnerabilities" 
          section="vulnerabilities"
          badge={
            <Badge variant="outline" className={report.vulnerabilities.length > 0 ? "bg-red-500/10 text-red-500" : "bg-green-500/10 text-green-500"}>
              {report.vulnerabilities.length} found
            </Badge>
          }
        />
        {expandedSections.vulnerabilities && (
          <CardContent className="pt-0 space-y-3">
            {report.vulnerabilities.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No vulnerabilities detected</p>
            ) : (
              report.vulnerabilities.map((vuln) => (
                <div key={vuln.id} className="p-3 bg-muted/50 rounded-md">
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={vuln.severity} />
                    <span className="font-medium text-sm">{vuln.title}</span>
                  </div>
                  <p className="text-sm text-muted-foreground">{vuln.description}</p>
                </div>
              ))
            )}
          </CardContent>
        )}
      </Card>

      <Card>
        <SectionHeader 
          icon={Server} 
          title="Recommendations" 
          section="recommendations"
          badge={
            <Badge variant="outline" className="bg-muted">
              {report.recommendations.length} items
            </Badge>
          }
        />
        {expandedSections.recommendations && (
          <CardContent className="pt-0">
            <ul className="space-y-2">
              {report.recommendations.map((rec, idx) => (
                <li key={idx} className="flex items-start gap-2 text-sm">
                  <span className="text-primary font-medium">{idx + 1}.</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        )}
      </Card>
    </div>
  );
}
