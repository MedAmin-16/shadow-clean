import { Pool } from "pg";
import type { SandboxConfig } from "@shared/advancedFeatures";

export class SandboxService {
  private pool: Pool;

  constructor() {
    this.pool = new Pool({
      connectionString: process.env.DATABASE_URL,
    });
  }

  async createSandbox(config: SandboxConfig): Promise<{ schemaName: string; success: boolean }> {
    const schemaName = `sandbox_${config.scanId.replace(/-/g, "_").substring(0, 20)}_${Date.now()}`;
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      await client.query(`CREATE SCHEMA IF NOT EXISTS ${schemaName}`);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${schemaName}.scan_data (
          id SERIAL PRIMARY KEY,
          data_type VARCHAR(50) NOT NULL,
          content JSONB,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${schemaName}.vulnerability_analysis (
          id SERIAL PRIMARY KEY,
          vuln_id VARCHAR(100) NOT NULL,
          analysis_type VARCHAR(50),
          result JSONB,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS ${schemaName}.exploit_tests (
          id SERIAL PRIMARY KEY,
          technique VARCHAR(100),
          target_vuln VARCHAR(100),
          success BOOLEAN DEFAULT FALSE,
          evidence TEXT,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `);

      await client.query("COMMIT");

      console.log(`[Sandbox] Created sandbox schema: ${schemaName}`);

      return { schemaName, success: true };
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("[Sandbox] Error creating sandbox:", error);
      throw error;
    } finally {
      client.release();
    }
  }

  async insertScanData(schemaName: string, dataType: string, content: unknown): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${schemaName}.scan_data (data_type, content) VALUES ($1, $2)`,
      [dataType, JSON.stringify(content)]
    );
  }

  async insertVulnerabilityAnalysis(
    schemaName: string,
    vulnId: string,
    analysisType: string,
    result: unknown
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${schemaName}.vulnerability_analysis (vuln_id, analysis_type, result) VALUES ($1, $2, $3)`,
      [vulnId, analysisType, JSON.stringify(result)]
    );
  }

  async insertExploitTest(
    schemaName: string,
    technique: string,
    targetVuln: string,
    success: boolean,
    evidence?: string
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${schemaName}.exploit_tests (technique, target_vuln, success, evidence) VALUES ($1, $2, $3, $4)`,
      [technique, targetVuln, success, evidence]
    );
  }

  async getSandboxData(schemaName: string): Promise<{
    scanData: unknown[];
    vulnerabilityAnalysis: unknown[];
    exploitTests: unknown[];
  }> {
    const [scanData, vulnAnalysis, exploitTests] = await Promise.all([
      this.pool.query(`SELECT * FROM ${schemaName}.scan_data ORDER BY created_at DESC`),
      this.pool.query(`SELECT * FROM ${schemaName}.vulnerability_analysis ORDER BY created_at DESC`),
      this.pool.query(`SELECT * FROM ${schemaName}.exploit_tests ORDER BY created_at DESC`),
    ]);

    return {
      scanData: scanData.rows,
      vulnerabilityAnalysis: vulnAnalysis.rows,
      exploitTests: exploitTests.rows,
    };
  }

  async cleanupSandbox(schemaName: string): Promise<void> {
    try {
      await this.pool.query(`DROP SCHEMA IF EXISTS ${schemaName} CASCADE`);
      console.log(`[Sandbox] Cleaned up schema: ${schemaName}`);
    } catch (error) {
      console.error(`[Sandbox] Error cleaning up schema ${schemaName}:`, error);
    }
  }

  async cleanupExpiredSandboxes(maxAgeHours: number = 24): Promise<number> {
    const client = await this.pool.connect();
    let cleanedCount = 0;

    try {
      const result = await client.query(`
        SELECT schema_name 
        FROM information_schema.schemata 
        WHERE schema_name LIKE 'sandbox_%'
      `);

      for (const row of result.rows) {
        const schemaName = row.schema_name;
        const timestampMatch = schemaName.match(/_(\d+)$/);
        
        if (timestampMatch) {
          const createdAt = parseInt(timestampMatch[1], 10);
          const ageHours = (Date.now() - createdAt) / (1000 * 60 * 60);
          
          if (ageHours > maxAgeHours) {
            await this.cleanupSandbox(schemaName);
            cleanedCount++;
          }
        }
      }
    } finally {
      client.release();
    }

    return cleanedCount;
  }
}

export const sandboxService = new SandboxService();
