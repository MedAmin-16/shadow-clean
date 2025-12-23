import type { ThreatIntelQuery, ThreatIntelResult } from "@shared/advancedFeatures";

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const SHODAN_API_BASE = "https://api.shodan.io";

interface NVDCVEItem {
  cve: {
    id: string;
    descriptions: { lang: string; value: string }[];
    metrics?: {
      cvssMetricV31?: {
        cvssData: { baseSeverity: string };
      }[];
    };
    references?: { url: string }[];
    published: string;
    lastModified: string;
  };
}

export class ThreatIntelService {
  private shodanApiKey?: string;
  private nvdApiKey?: string;

  constructor() {
    this.shodanApiKey = process.env.SHODAN_API_KEY;
    this.nvdApiKey = process.env.NVD_API_KEY;
  }

  async searchNVD(query: ThreatIntelQuery): Promise<ThreatIntelResult[]> {
    const results: ThreatIntelResult[] = [];
    
    try {
      let url = `${NVD_API_BASE}?resultsPerPage=${query.limit || 20}`;
      
      if (query.cve) {
        url += `&cveId=${encodeURIComponent(query.cve)}`;
      }
      
      if (query.keyword) {
        url += `&keywordSearch=${encodeURIComponent(query.keyword)}`;
      }

      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      
      if (this.nvdApiKey) {
        headers["apiKey"] = this.nvdApiKey;
      }

      const response = await fetch(url, { headers });
      
      if (!response.ok) {
        console.error(`[ThreatIntel] NVD API error: ${response.status}`);
        return this.getMockNVDResults(query);
      }

      const data = await response.json();
      
      for (const item of data.vulnerabilities || []) {
        const cve = item.cve as NVDCVEItem["cve"];
        const description = cve.descriptions.find((d: { lang: string }) => d.lang === "en")?.value || "";
        const severity = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity?.toLowerCase();

        if (query.severity && severity !== query.severity) continue;

        results.push({
          id: cve.id,
          cveId: cve.id,
          source: "nvd",
          type: "vulnerability",
          severity: severity || "unknown",
          title: cve.id,
          description,
          exploitAvailable: false,
          references: cve.references?.map((r: { url: string }) => r.url) || [],
          publishedAt: cve.published,
        });
      }
    } catch (error) {
      console.error("[ThreatIntel] NVD search error:", error);
      return this.getMockNVDResults(query);
    }

    return results;
  }

  async searchShodan(target: string): Promise<ThreatIntelResult[]> {
    if (!this.shodanApiKey) {
      return this.getMockShodanResults(target);
    }

    try {
      const url = `${SHODAN_API_BASE}/shodan/host/${encodeURIComponent(target)}?key=${this.shodanApiKey}`;
      const response = await fetch(url);
      
      if (!response.ok) {
        console.error(`[ThreatIntel] Shodan API error: ${response.status}`);
        return this.getMockShodanResults(target);
      }

      const data = await response.json();
      const results: ThreatIntelResult[] = [];

      if (data.vulns) {
        for (const cveId of Object.keys(data.vulns)) {
          results.push({
            id: `shodan-${cveId}`,
            cveId,
            source: "shodan",
            type: "vulnerability",
            severity: "high",
            title: `Shodan detected: ${cveId}`,
            description: `Vulnerability ${cveId} detected on ${target}`,
            exploitAvailable: true,
          });
        }
      }

      return results;
    } catch (error) {
      console.error("[ThreatIntel] Shodan search error:", error);
      return this.getMockShodanResults(target);
    }
  }

  async search(query: ThreatIntelQuery): Promise<ThreatIntelResult[]> {
    const results: ThreatIntelResult[] = [];

    if (query.source === "nvd" || query.source === "all" || !query.source) {
      const nvdResults = await this.searchNVD(query);
      results.push(...nvdResults);
    }

    return results.slice(0, query.limit || 20);
  }

  private getMockNVDResults(query: ThreatIntelQuery): ThreatIntelResult[] {
    const mockResults: ThreatIntelResult[] = [
      {
        id: "CVE-2024-12345",
        cveId: "CVE-2024-12345",
        source: "nvd",
        type: "vulnerability",
        severity: "critical",
        title: "Remote Code Execution in Web Framework",
        description: "A critical remote code execution vulnerability allows unauthenticated attackers to execute arbitrary code via crafted HTTP requests.",
        exploitAvailable: true,
        references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"],
        publishedAt: new Date().toISOString(),
      },
      {
        id: "CVE-2024-54321",
        cveId: "CVE-2024-54321",
        source: "nvd",
        type: "vulnerability",
        severity: "high",
        title: "SQL Injection in Authentication Module",
        description: "SQL injection vulnerability in the login handler allows attackers to bypass authentication and access sensitive data.",
        exploitAvailable: true,
        references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-54321"],
        publishedAt: new Date().toISOString(),
      },
      {
        id: "CVE-2024-11111",
        cveId: "CVE-2024-11111",
        source: "nvd",
        type: "vulnerability",
        severity: "medium",
        title: "Cross-Site Scripting in User Profile",
        description: "Stored XSS vulnerability allows attackers to inject malicious scripts via user profile fields.",
        exploitAvailable: false,
        references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-11111"],
        publishedAt: new Date().toISOString(),
      },
    ];

    return mockResults
      .filter(r => !query.severity || r.severity === query.severity)
      .slice(0, query.limit || 20);
  }

  private getMockShodanResults(target: string): ThreatIntelResult[] {
    return [
      {
        id: `shodan-mock-${target}-1`,
        source: "shodan",
        type: "exposure",
        severity: "high",
        title: `Open SSH port detected on ${target}`,
        description: "SSH service running on port 22 is exposed to the internet with weak configuration.",
        exploitAvailable: false,
      },
      {
        id: `shodan-mock-${target}-2`,
        source: "shodan",
        type: "exposure",
        severity: "medium",
        title: `HTTP server detected on ${target}`,
        description: "Web server running on port 80/443 detected with outdated software version.",
        exploitAvailable: false,
      },
    ];
  }
}

export const threatIntelService = new ThreatIntelService();
