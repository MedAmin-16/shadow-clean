import { ScanReportViewer } from "../ScanReportViewer";

// todo: remove mock functionality
const mockReport = {
  securityScore: 74,
  tls: {
    valid: true,
    protocol: "TLS 1.3",
    expiresIn: "89 days",
  },
  headers: {
    contentSecurityPolicy: false,
    xFrameOptions: true,
    xContentTypeOptions: true,
    strictTransportSecurity: false,
  },
  vulnerabilities: [
    {
      id: "1",
      title: "Missing Content-Security-Policy",
      severity: "medium" as const,
      description: "The Content-Security-Policy header is not set, which could allow XSS attacks.",
    },
    {
      id: "2",
      title: "Missing HSTS Header",
      severity: "medium" as const,
      description: "Strict-Transport-Security header is not configured.",
    },
  ],
  recommendations: [
    "Implement a Content-Security-Policy header to prevent XSS attacks",
    "Enable Strict-Transport-Security (HSTS) with a minimum of 1 year max-age",
    "Consider implementing subresource integrity for external scripts",
    "Review and update rate limiting configurations",
  ],
};

export default function ScanReportViewerExample() {
  return <ScanReportViewer report={mockReport} />;
}
