import { db } from "../../db";
import { employeeRiskRadarTable, leakedEmailsTable } from "@shared/schema";
import { eq } from "drizzle-orm";

export class EmployeeRiskRadarService {
  async performRadarScan(userId: string, targetDomain: string) {
    logger.info(`Starting Employee Risk Radar scan for ${targetDomain}`);
    
    // Create scan record
    const [radarScan] = await db.insert(employeeRiskRadarTable).values({
      userId,
      targetDomain,
      status: "in_progress",
    }).returning();

    try {
      // Logic: In a real scenario, we'd call OSINT APIs like Hunter.io or similar.
      // For this implementation, we'll simulate the smart correlation logic.
      const simulatedLeaks = this.simulateLeakDiscovery(targetDomain);
      
      let totalRiskScore = 0;
      
      for (const leak of simulatedLeaks) {
        await db.insert(leakedEmailsTable).values({
          radarId: radarScan.id,
          email: leak.email,
          breachNames: leak.breaches.join(", "),
          riskLevel: leak.riskLevel,
          leakedAt: new Date(),
        });
        
        totalRiskScore += leak.riskLevel === "high" ? 25 : leak.riskLevel === "medium" ? 10 : 5;
      }

      const finalRiskScore = Math.min(100, totalRiskScore);

      await db.update(employeeRiskRadarTable)
        .set({
          status: "completed",
          riskScore: finalRiskScore,
          totalLeakedEmails: simulatedLeaks.length,
          lastScannedAt: new Date(),
        })
        .where(eq(employeeRiskRadarTable.id, radarScan.id));

      return { radarScanId: radarScan.id, riskScore: finalRiskScore };
    } catch (error) {
      console.error(`Radar scan failed: ${error}`);
      await db.update(employeeRiskRadarTable)
        .set({ status: "failed" })
        .where(eq(employeeRiskRadarTable.id, radarScan.id));
      throw error;
    }
  }

  private simulateLeakDiscovery(domain: string) {
    const prefixes = ["admin", "ceo", "finance", "hr", "it_support", "dev"];
    const commonBreaches = ["LinkedIn 2016 Leak", "Canva 2019 Leak", "Adobe 2013 Leak", "Dropbox 2012 Leak", "Zynga 2019 Leak"];
    
    const leakCount = Math.floor(Math.random() * 5) + 3;
    const leaks = [];

    for (let i = 0; i < leakCount; i++) {
      const prefix = prefixes[i % prefixes.length];
      const email = `${prefix.charAt(0)}***@${domain}`;
      const breachCount = Math.floor(Math.random() * 2) + 1;
      const selectedBreaches = [];
      
      for (let j = 0; j < breachCount; j++) {
        selectedBreaches.push(commonBreaches[Math.floor(Math.random() * commonBreaches.length)]);
      }

      leaks.push({
        email,
        breaches: selectedBreaches,
        riskLevel: breachCount > 1 ? "high" : "medium"
      });
    }

    return leaks;
  }

  async getRadarData(userId: string) {
    const radars = await db.select().from(employeeRiskRadarTable)
      .where(eq(employeeRiskRadarTable.userId, userId))
      .orderBy(employeeRiskRadarTable.createdAt);
    
    if (radars.length === 0) return null;
    
    const latestRadar = radars[radars.length - 1];
    const leaks = await db.select().from(leakedEmailsTable)
      .where(eq(leakedEmailsTable.radarId, latestRadar.id));
      
    return {
      ...latestRadar,
      leaks
    };
  }
}

export const employeeRiskRadarService = new EmployeeRiskRadarService();
