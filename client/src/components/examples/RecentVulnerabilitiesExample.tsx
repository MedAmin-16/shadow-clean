import { RecentVulnerabilities } from "../RecentVulnerabilities";

// todo: remove mock functionality
const mockVulnerabilities = [
  {
    id: "1",
    title: "SQL Injection in Login Form",
    severity: "critical" as const,
    affectedAsset: "api.example.com/auth/login",
    cveId: "CVE-2024-1234",
  },
  {
    id: "2",
    title: "Missing Content-Security-Policy Header",
    severity: "medium" as const,
    affectedAsset: "app.example.com",
  },
  {
    id: "3",
    title: "Outdated TLS Version",
    severity: "high" as const,
    affectedAsset: "api.example.com",
    cveId: "CVE-2024-5678",
  },
];

export default function RecentVulnerabilitiesExample() {
  return (
    <RecentVulnerabilities
      vulnerabilities={mockVulnerabilities}
      onViewAll={() => console.log("View all clicked")}
    />
  );
}
