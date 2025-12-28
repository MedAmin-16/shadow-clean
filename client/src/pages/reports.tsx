import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScanReportViewer } from "@/components/ScanReportViewer";
import { Search, Download, FileText, Calendar, ChevronRight, Inbox } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import type { Report } from "@shared/schema";

export default function ReportsPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedReport, setSelectedReport] = useState<string | null>(null);

  const { data: reports = [] } = useQuery<Report[]>({
    queryKey: ["/api/reports"],
  });

  const { data: selectedReportData } = useQuery<Report>({
    queryKey: ["/api/reports", selectedReport],
    enabled: !!selectedReport,
  });

  const filteredReports = reports.filter((r) =>
    r.projectName.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const getScoreColor = (s: number) => {
    if (s >= 80) return "bg-green-500/10 text-green-500 border-green-500/20";
    if (s >= 60) return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
    if (s >= 40) return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    return "bg-red-500/10 text-red-500 border-red-500/20";
  };

  if (selectedReport) {
    const selectedReportInfo = reports.find(r => r.id === selectedReport);
    const hasDetails = selectedReportData?.details;
    
    const reportDetails = hasDetails ? {
      securityScore: selectedReportData.details!.securityScore,
      tls: selectedReportData.details!.tls || { valid: true, protocol: "TLS 1.3", expiresIn: "N/A" },
      headers: selectedReportData.details!.headers || { contentSecurityPolicy: false, xFrameOptions: false, xContentTypeOptions: false, strictTransportSecurity: false },
      vulnerabilities: selectedReportData.details!.vulnerabilities,
      recommendations: selectedReportData.details!.recommendations,
    } : {
      securityScore: selectedReportInfo?.score || 0,
      tls: { valid: true, protocol: "TLS 1.3", expiresIn: "N/A" },
      headers: { contentSecurityPolicy: false, xFrameOptions: false, xContentTypeOptions: false, strictTransportSecurity: false },
      vulnerabilities: [],
      recommendations: ["Run a full scan to generate detailed vulnerability analysis"],
    };
    
    return (
      <div className="p-6 space-y-6" data-testid="page-report-details">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            onClick={() => setSelectedReport(null)}
            data-testid="button-back-to-reports"
          >
            Back to Reports
          </Button>
        </div>
        <ScanReportViewer report={reportDetails} />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="page-reports">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Reports</h1>
          <p className="text-muted-foreground">View and export security reports</p>
        </div>
        <Button variant="outline" data-testid="button-export-all" disabled={reports.length === 0}>
          <Download className="h-4 w-4 mr-2" />
          Export All
        </Button>
      </div>

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search reports..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-9"
          data-testid="input-search-reports"
        />
      </div>

      <div className="space-y-4">
        {filteredReports.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 border border-dashed rounded-xl bg-black/20">
            <div className="p-4 rounded-full bg-muted mb-4">
              <Inbox className="h-8 w-8 text-muted-foreground" />
            </div>
            <h3 className="text-lg font-medium mb-1">No reports found</h3>
            <p className="text-muted-foreground mb-4 text-center max-w-xs">Run your first scan to generate comprehensive security reports.</p>
          </div>
        ) : (
          filteredReports.map((report) => (
            <Card
              key={report.id}
              className="hover-elevate cursor-pointer"
              data-testid={`card-report-${report.id}`}
              onClick={() => setSelectedReport(report.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-4 flex-1 min-w-0">
                    <div className="p-2 rounded-md bg-muted">
                      <FileText className="h-5 w-5 text-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium">{report.projectName}</p>
                      <div className="flex items-center gap-2 mt-1 text-sm text-muted-foreground">
                        <Calendar className="h-3.5 w-3.5" />
                        <span>{report.date}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <Badge variant="outline" className={getScoreColor(report.score)}>
                      Score: {report.score}
                    </Badge>
                    {report.vulnerabilities > 0 && (
                      <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20">
                        {report.vulnerabilities} issues
                      </Badge>
                    )}
                    <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
