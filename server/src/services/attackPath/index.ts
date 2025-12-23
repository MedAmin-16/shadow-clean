import type { AttackGraph, AttackGraphNode, AttackGraphEdge } from "@shared/advancedFeatures";
import type { ScannerFindings, EnhancedScannerFindings, ExploiterFindings } from "@shared/schema";

export class AttackPathService {
  generateAttackGraph(
    scannerFindings: ScannerFindings | EnhancedScannerFindings,
    exploiterFindings?: ExploiterFindings,
    target?: string
  ): AttackGraph {
    const nodes: AttackGraphNode[] = [];
    const edges: AttackGraphEdge[] = [];
    const criticalPaths: string[][] = [];

    const entryNodeId = "entry-point";
    nodes.push({
      id: entryNodeId,
      type: "asset",
      label: target || "Target System",
      metadata: { isEntryPoint: true },
    });

    const vulnerabilities = scannerFindings.vulnerabilities || [];
    const exploitAttempts = exploiterFindings?.exploitAttempts || [];

    const vulnNodes: Map<string, AttackGraphNode> = new Map();
    
    for (const vuln of vulnerabilities) {
      const vulnNodeId = `vuln-${vuln.id}`;
      const vulnNode: AttackGraphNode = {
        id: vulnNodeId,
        type: "vulnerability",
        label: vuln.title,
        severity: vuln.severity === "info" ? "low" : vuln.severity,
        metadata: {
          cve: vuln.cve,
          port: vuln.port,
          service: vuln.service,
          description: vuln.description,
        },
      };
      nodes.push(vulnNode);
      vulnNodes.set(vuln.id, vulnNode);

      edges.push({
        id: `edge-entry-${vuln.id}`,
        source: entryNodeId,
        target: vulnNodeId,
        type: "exploits",
        probability: this.getSeverityProbability(vuln.severity),
        label: "Can exploit",
      });
    }

    const attackTechniqueNodes: Map<string, AttackGraphNode> = new Map();
    
    for (const attempt of exploitAttempts) {
      const techNodeId = `tech-${attempt.technique.replace(/\s+/g, "-").toLowerCase()}`;
      
      if (!attackTechniqueNodes.has(techNodeId)) {
        const techNode: AttackGraphNode = {
          id: techNodeId,
          type: "attack_technique",
          label: attempt.technique,
          severity: attempt.success ? "high" : "medium",
          metadata: {
            success: attempt.success,
            evidence: attempt.evidence,
          },
        };
        nodes.push(techNode);
        attackTechniqueNodes.set(techNodeId, techNode);
      }

      const vulnEntries = Array.from(vulnNodes.entries());
      for (let i = 0; i < vulnEntries.length; i++) {
        const [vulnId, vulnNode] = vulnEntries[i];
        if (attempt.vulnerability.toLowerCase().includes(vulnId.toLowerCase()) ||
            vulnNode.label.toLowerCase().includes(attempt.vulnerability.toLowerCase())) {
          edges.push({
            id: `edge-${vulnId}-${techNodeId}`,
            source: `vuln-${vulnId}`,
            target: techNodeId,
            type: "enables",
            probability: attempt.success ? 0.9 : 0.3,
            label: attempt.success ? "Successfully exploited" : "Attempted",
          });
          break;
        }
      }
    }

    const impactNodes: AttackGraphNode[] = [
      { id: "impact-data-breach", type: "impact", label: "Data Breach", severity: "critical" },
      { id: "impact-system-compromise", type: "impact", label: "System Compromise", severity: "critical" },
      { id: "impact-lateral-movement", type: "impact", label: "Lateral Movement", severity: "high" },
      { id: "impact-privilege-escalation", type: "impact", label: "Privilege Escalation", severity: "high" },
      { id: "impact-denial-of-service", type: "impact", label: "Denial of Service", severity: "medium" },
    ];

    for (const impactNode of impactNodes) {
      nodes.push(impactNode);
    }

    const techEntries = Array.from(attackTechniqueNodes.entries());
    for (let i = 0; i < techEntries.length; i++) {
      const [techNodeId, techNode] = techEntries[i];
      const techLabel = techNode.label.toLowerCase();
      
      if (techLabel.includes("sql") || techLabel.includes("injection") || techLabel.includes("data")) {
        edges.push({
          id: `edge-${techNodeId}-data-breach`,
          source: techNodeId,
          target: "impact-data-breach",
          type: "leads_to",
          probability: 0.8,
        });
      }
      
      if (techLabel.includes("rce") || techLabel.includes("shell") || techLabel.includes("code")) {
        edges.push({
          id: `edge-${techNodeId}-compromise`,
          source: techNodeId,
          target: "impact-system-compromise",
          type: "leads_to",
          probability: 0.9,
        });
      }
      
      if (techLabel.includes("privilege") || techLabel.includes("escalat")) {
        edges.push({
          id: `edge-${techNodeId}-priv-esc`,
          source: techNodeId,
          target: "impact-privilege-escalation",
          type: "leads_to",
          probability: 0.7,
        });
      }
    }

    const finalVulnEntries = Array.from(vulnNodes.entries());
    for (let i = 0; i < finalVulnEntries.length; i++) {
      const [vulnId, vulnNode] = finalVulnEntries[i];
      if (vulnNode.severity === "critical") {
        edges.push({
          id: `edge-vuln-${vulnId}-compromise`,
          source: `vuln-${vulnId}`,
          target: "impact-system-compromise",
          type: "leads_to",
          probability: 0.6,
        });
      }
    }

    const pathsFound = this.findCriticalPaths(nodes, edges, entryNodeId);
    criticalPaths.push(...pathsFound);

    const maxDepth = this.calculateMaxDepth(edges, entryNodeId);

    return {
      nodes,
      edges,
      criticalPaths,
      summary: {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        criticalPathCount: criticalPaths.length,
        maxAttackDepth: maxDepth,
        highestRiskPath: criticalPaths[0] || [],
      },
    };
  }

  private getSeverityProbability(severity: string): number {
    switch (severity) {
      case "critical": return 0.9;
      case "high": return 0.7;
      case "medium": return 0.5;
      case "low": return 0.3;
      default: return 0.1;
    }
  }

  private findCriticalPaths(
    nodes: AttackGraphNode[],
    edges: AttackGraphEdge[],
    startNodeId: string
  ): string[][] {
    const paths: string[][] = [];
    const impactNodes = nodes.filter(n => n.type === "impact").map(n => n.id);
    
    const adjacencyList = new Map<string, { target: string; probability: number }[]>();
    for (const edge of edges) {
      if (!adjacencyList.has(edge.source)) {
        adjacencyList.set(edge.source, []);
      }
      adjacencyList.get(edge.source)!.push({
        target: edge.target,
        probability: edge.probability || 0.5,
      });
    }

    const dfs = (currentNode: string, currentPath: string[], visited: Set<string>) => {
      if (impactNodes.includes(currentNode)) {
        paths.push([...currentPath]);
        return;
      }

      const neighbors = adjacencyList.get(currentNode) || [];
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor.target)) {
          visited.add(neighbor.target);
          currentPath.push(neighbor.target);
          dfs(neighbor.target, currentPath, visited);
          currentPath.pop();
          visited.delete(neighbor.target);
        }
      }
    };

    const visited = new Set<string>([startNodeId]);
    dfs(startNodeId, [startNodeId], visited);

    return paths
      .sort((a, b) => {
        const aHasCritical = a.some(nodeId => 
          nodes.find(n => n.id === nodeId)?.severity === "critical"
        );
        const bHasCritical = b.some(nodeId => 
          nodes.find(n => n.id === nodeId)?.severity === "critical"
        );
        if (aHasCritical && !bHasCritical) return -1;
        if (!aHasCritical && bHasCritical) return 1;
        return b.length - a.length;
      })
      .slice(0, 5);
  }

  private calculateMaxDepth(edges: AttackGraphEdge[], startNodeId: string): number {
    const adjacencyList = new Map<string, string[]>();
    for (const edge of edges) {
      if (!adjacencyList.has(edge.source)) {
        adjacencyList.set(edge.source, []);
      }
      adjacencyList.get(edge.source)!.push(edge.target);
    }

    let maxDepth = 0;
    const queue: { node: string; depth: number }[] = [{ node: startNodeId, depth: 0 }];
    const visited = new Set<string>();

    while (queue.length > 0) {
      const { node, depth } = queue.shift()!;
      if (visited.has(node)) continue;
      visited.add(node);
      
      maxDepth = Math.max(maxDepth, depth);
      
      const neighbors = adjacencyList.get(node) || [];
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          queue.push({ node: neighbor, depth: depth + 1 });
        }
      }
    }

    return maxDepth;
  }
}

export const attackPathService = new AttackPathService();
