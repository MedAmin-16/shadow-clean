import { type User, type InsertUser, type DbScan as Scan, type InsertScan, type Project, type InsertProject, type Activity, type Report, type UserSettings, type UserCredits, type PlanLevel, users, shadowlogicVulnerabilitiesTable, shadowlogicDiscoveriesTable } from "@shared/schema";
import { randomUUID } from "crypto";
import { creditService } from "./src/services/creditService";
import { hashPassword } from "./utils/password";
import { db, pool } from "./db";
import { eq } from "drizzle-orm";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  getUserCredits(userId: string): Promise<UserCredits>;
  deductCredits(userId: string, amount: number, options?: { description?: string; agentType?: string; scanId?: string }): Promise<{ success: boolean; newBalance: number; error?: string }>;
  addCredits(userId: string, amount: number): Promise<UserCredits>;
  setUserPlanLevel(userId: string, planLevel: PlanLevel): Promise<UserCredits>;
  
  createScan(scan: InsertScan): Promise<Scan>;
  getScan(id: string): Promise<Scan | undefined>;
  getAllScans(): Promise<Scan[]>;
  updateScan(id: string, updates: Partial<Scan>): Promise<Scan | undefined>;
  deleteScan(id: string): Promise<boolean>;
  
  createProject(project: InsertProject): Promise<Project>;
  getProject(id: string): Promise<Project | undefined>;
  getAllProjects(): Promise<Project[]>;
  updateProject(id: string, updates: Partial<Project>): Promise<Project | undefined>;
  deleteProject(id: string): Promise<boolean>;
  
  addActivity(activity: Omit<Activity, "id" | "timestamp">): Promise<Activity>;
  getActivities(limit?: number): Promise<Activity[]>;
  
  getReports(): Promise<Report[]>;
  getReport(id: string): Promise<Report | undefined>;
  createReportFromScan(scanId: string): Promise<Report | undefined>;
  
  getSettings(userId: string): Promise<UserSettings | undefined>;
  updateSettings(userId: string, settings: Partial<UserSettings>): Promise<UserSettings>;
  
  createApprovalRequest(request: any): Promise<any>;
  getApprovalRequest(id: string): Promise<any | undefined>;
  getApprovalRequestsByScan(scanId: string): Promise<any[]>;
  getPendingApprovalRequests(userId: string): Promise<any[]>;
  updateApprovalRequest(id: string, updates: Partial<any>): Promise<any | undefined>;
  
  // Integration methods
  saveIntegration(userId: string, integrationId: string, credentials: Record<string, string>): Promise<void>;
  getIntegration(userId: string, integrationId: string): Promise<any | undefined>;
  getIntegrations(userId: string): Promise<any[]>;
  deleteIntegration(userId: string, integrationId: string): Promise<void>;
  testIntegration(integrationId: string, config: any): Promise<boolean>;
  updateIntegrationStatus(userId: string, integrationId: string, connected: boolean): Promise<void>;
  
  // ShadowLogic database methods
  insertVulnerability(data: { scanId: string; userId: string; type: string; severity: string; title: string; description: string; url: string; payload?: string; remediation?: string }): Promise<void>;
  insertDiscovery(data: { scanId: string; userId: string; discoveryType: string; url: string; title?: string; method?: string; parameters?: Record<string, unknown> }): Promise<void>;
}

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private scans: Map<string, Scan>;
  private projects: Map<string, Project>;
  private activities: Activity[];
  private reports: Map<string, Report>;
  private settings: Map<string, UserSettings>;
  private credits: Map<string, UserCredits>;
  private approvalRequests: Map<string, any>;
  private integrations: Map<string, any[]>;

  constructor() {
    this.users = new Map();
    this.scans = new Map();
    this.projects = new Map();
    this.activities = [];
    this.reports = new Map();
    this.settings = new Map();
    this.credits = new Map();
    this.approvalRequests = new Map();
    this.integrations = new Map();
    
    this.initializeSampleData();
  }
  
  private initializeSampleData() {
    const sampleProjects: Project[] = [
      { id: "1", name: "Production API", assetCount: 12, lastScanDate: "2 hours ago", securityScore: 74, createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString() },
      { id: "2", name: "Staging Environment", assetCount: 8, lastScanDate: "1 day ago", securityScore: 82, createdAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString() },
      { id: "3", name: "Internal Tools", assetCount: 5, lastScanDate: "3 days ago", securityScore: 91, createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString() },
      { id: "4", name: "Mobile API", assetCount: 6, lastScanDate: "1 week ago", securityScore: 68, createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString() },
      { id: "5", name: "Customer Portal", assetCount: 15, lastScanDate: "4 hours ago", securityScore: 79, createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString() },
      { id: "6", name: "Admin Dashboard", assetCount: 4, lastScanDate: "2 days ago", securityScore: 85, createdAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
    ];
    
    sampleProjects.forEach(p => this.projects.set(p.id, p));
    
    const sampleActivities: Activity[] = [
      { id: "1", type: "scan_completed", message: "Security scan completed for Production API", timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(), projectId: "1" },
      { id: "2", type: "vulnerability_found", message: "Critical vulnerability detected in Mobile API", timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(), projectId: "4" },
      { id: "3", type: "scan_started", message: "New scan initiated for Customer Portal", timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(), projectId: "5" },
      { id: "4", type: "scan_completed", message: "Security report generated for Staging Environment", timestamp: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString() },
      { id: "5", type: "project_created", message: "New project Admin Dashboard created", timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), projectId: "6" },
    ];
    
    this.activities = sampleActivities;
    
    const sampleReports: Report[] = [
      {
        id: "1", projectName: "Production API", scanId: "scan-1", date: "Dec 10, 2024", score: 74, vulnerabilities: 3,
        details: {
          securityScore: 74,
          tls: { valid: true, protocol: "TLS 1.3", expiresIn: "89 days" },
          headers: { contentSecurityPolicy: false, xFrameOptions: true, xContentTypeOptions: true, strictTransportSecurity: false },
          vulnerabilities: [
            { id: "1", title: "Missing Content-Security-Policy", severity: "medium", description: "The Content-Security-Policy header is not set." },
            { id: "2", title: "Missing HSTS Header", severity: "medium", description: "Strict-Transport-Security header is not configured." },
            { id: "3", title: "SQL Injection Vulnerability", severity: "critical", description: "SQL injection detected in the login form." },
          ],
          recommendations: [
            "Implement a Content-Security-Policy header to prevent XSS attacks",
            "Enable Strict-Transport-Security (HSTS) with a minimum of 1 year max-age",
            "Sanitize all user inputs to prevent SQL injection attacks",
          ],
        }
      },
      { 
        id: "2", projectName: "Staging Environment", scanId: "scan-2", date: "Dec 9, 2024", score: 82, vulnerabilities: 1,
        details: {
          securityScore: 82,
          tls: { valid: true, protocol: "TLS 1.3", expiresIn: "120 days" },
          headers: { contentSecurityPolicy: true, xFrameOptions: true, xContentTypeOptions: true, strictTransportSecurity: false },
          vulnerabilities: [
            { id: "4", title: "Missing HSTS Header", severity: "medium" as const, description: "Strict-Transport-Security header is not configured." },
          ],
          recommendations: ["Enable Strict-Transport-Security (HSTS) with a minimum of 1 year max-age"],
        }
      },
      { 
        id: "3", projectName: "Internal Tools", scanId: "scan-3", date: "Dec 8, 2024", score: 91, vulnerabilities: 0,
        details: {
          securityScore: 91,
          tls: { valid: true, protocol: "TLS 1.3", expiresIn: "200 days" },
          headers: { contentSecurityPolicy: true, xFrameOptions: true, xContentTypeOptions: true, strictTransportSecurity: true },
          vulnerabilities: [],
          recommendations: ["Continue regular security monitoring"],
        }
      },
      { 
        id: "4", projectName: "Customer Portal", scanId: "scan-4", date: "Dec 7, 2024", score: 79, vulnerabilities: 2,
        details: {
          securityScore: 79,
          tls: { valid: true, protocol: "TLS 1.2", expiresIn: "45 days" },
          headers: { contentSecurityPolicy: false, xFrameOptions: true, xContentTypeOptions: true, strictTransportSecurity: true },
          vulnerabilities: [
            { id: "5", title: "Missing Content-Security-Policy", severity: "medium" as const, description: "CSP header is not configured." },
            { id: "6", title: "Outdated TLS Version", severity: "low" as const, description: "Consider upgrading to TLS 1.3." },
          ],
          recommendations: ["Implement Content-Security-Policy header", "Upgrade TLS to version 1.3"],
        }
      },
    ];
    
    sampleReports.forEach(r => this.reports.set(r.id, r));
  }

  async getUser(id: string): Promise<User | undefined> {
    const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return result[0];
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const result = await db.select().from(users).where(eq(users.username, username)).limit(1);
    return result[0];
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const result = await db.select().from(users).where(eq(users.email, email)).limit(1);
    return result[0];
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    // Transaction: create user AND initialize credits together
    // If either fails, both rollback
    const client = await pool.connect();
    
    try {
      await client.query("BEGIN");
      
      // 1. Create user
      const hashedPassword = await hashPassword(insertUser.password_hash);
      const userResult = await client.query(
        `INSERT INTO users (username, email, password_hash, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         RETURNING id, username, email, password_hash, created_at, updated_at`,
        [insertUser.username, insertUser.email, hashedPassword]
      );
      
      if (userResult.rows.length === 0) {
        throw new Error("Failed to create user");
      }
      
      const userId = userResult.rows[0].id;
      
      // 2. Initialize user credits (1000 default)
      // Use ON CONFLICT to handle trigger race condition
      const creditsResult = await client.query(
        `INSERT INTO user_credits (user_id, balance, plan_level, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (user_id) DO NOTHING
         RETURNING *`,
        [userId, 1000, "PRO"]
      );
      
      // creditsResult.rows.length === 0 means trigger already created the record
      // This is acceptable - the credits are initialized either way
      
      // 3. Record initial credit grant transaction
      await client.query(
        `INSERT INTO credit_transactions 
         (user_id, transaction_type, amount, balance_before, balance_after, description, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [userId, "initial_grant", 1000, 0, 1000, "Initial credit grant for new user"]
      );
      
      await client.query("COMMIT");
      
      // Return complete user object matching our User type
      return {
        id: userResult.rows[0].id,
        username: userResult.rows[0].username,
        email: userResult.rows[0].email,
        password_hash: userResult.rows[0].password_hash,
        full_name: null,
        avatar_url: null,
        plan: "PRO",
        status: "active",
        email_verified: false,
        two_factor_enabled: false,
        created_at: userResult.rows[0].created_at,
        updated_at: userResult.rows[0].updated_at,
        last_login: null,
      } as User;
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("[Storage] Transaction error:", error);
      throw error;
    } finally {
      client.release();
    }
  }

  async getUserCredits(userId: string): Promise<UserCredits> {
    return creditService.getUserCredits(userId);
  }

  async deductCredits(userId: string, amount: number, options?: { description?: string; agentType?: string; scanId?: string }): Promise<{ success: boolean; newBalance: number; error?: string }> {
    return creditService.deductCredits(userId, amount, options);
  }

  async addCredits(userId: string, amount: number): Promise<UserCredits> {
    return creditService.addCredits(userId, amount, "purchase");
  }

  async setUserPlanLevel(userId: string, planLevel: PlanLevel): Promise<UserCredits> {
    return creditService.setUserPlanLevel(userId, planLevel);
  }

  async createScan(insertScan: InsertScan & { id?: string }): Promise<Scan> {
    if (!insertScan.userId) {
      throw new Error("User ID is required to create a scan");
    }
    const id = insertScan.id || randomUUID();
    
    // First, persist to PostgreSQL if available
    try {
      const [dbScan] = await db.insert(scansTable).values({
        id,
        target: insertScan.target,
        userId: insertScan.userId,
        status: insertScan.status || "pending",
        scanType: (insertScan.scanType as any) || "standard",
        agentResults: insertScan.agentResults || {},
        startedAt: new Date(),
      }).returning();
      
      // Also update in-memory cache
      const scan: Scan = {
        ...dbScan,
        currentAgent: dbScan.currentAgent || null,
        progress: dbScan.progress || 0,
        error: dbScan.error || null,
      };
      this.scans.set(id, scan);
      return scan;
    } catch (error) {
      console.error("[Storage] Failed to create scan in DB, falling back to memory:", error);
      // Fallback to in-memory only if DB fails
      const scan: Scan = {
        id,
        target: insertScan.target,
        userId: insertScan.userId,
        status: insertScan.status || "pending",
        currentAgent: null,
        progress: 0,
        startedAt: new Date(),
        completedAt: null,
        error: null,
        scanType: (insertScan.scanType as any) || "standard",
        agentResults: insertScan.agentResults || {},
      };
      this.scans.set(id, scan);
      return scan;
    }
  }

  async getScan(id: string): Promise<Scan | undefined> {
    return this.scans.get(id);
  }

  async getAllScans(): Promise<Scan[]> {
    return Array.from(this.scans.values()).sort(
      (a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
    );
  }

  async updateScan(id: string, updates: Partial<Scan>): Promise<Scan | undefined> {
    const scan = this.scans.get(id);
    const updatedScan: Scan = scan ? { ...scan, ...updates } : { id, ...updates } as Scan;
    this.scans.set(id, updatedScan);

    // Persist to PostgreSQL
    try {
      const [updated] = await db.update(scansTable)
        .set(updates)
        .where(eq(scansTable.id, id))
        .returning();
      
      if (updated) {
        const fullScan: Scan = {
          ...updated,
          currentAgent: updated.currentAgent || null,
          progress: updated.progress || 0,
          error: updated.error || null,
        };
        this.scans.set(id, fullScan);
        return fullScan;
      }
    } catch (error) {
      console.error(`[Storage] Failed to update scan ${id} in DB:`, error);
    }
    
    return updatedScan;
  }

  async deleteScan(id: string): Promise<boolean> {
    return this.scans.delete(id);
  }
  
  async createProject(insertProject: InsertProject): Promise<Project> {
    const id = randomUUID();
    const project: Project = {
      id,
      name: insertProject.name,
      assetCount: 0,
      lastScanDate: "Never",
      securityScore: 0,
      createdAt: new Date().toISOString(),
    };
    this.projects.set(id, project);
    
    await this.addActivity({
      type: "project_created",
      message: `New project ${project.name} created`,
      projectId: id,
    });
    
    return project;
  }
  
  async getProject(id: string): Promise<Project | undefined> {
    return this.projects.get(id);
  }
  
  async getAllProjects(): Promise<Project[]> {
    return Array.from(this.projects.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }
  
  async updateProject(id: string, updates: Partial<Project>): Promise<Project | undefined> {
    const project = this.projects.get(id);
    if (!project) return undefined;
    
    const updatedProject: Project = { ...project, ...updates };
    this.projects.set(id, updatedProject);
    return updatedProject;
  }
  
  async deleteProject(id: string): Promise<boolean> {
    return this.projects.delete(id);
  }
  
  async addActivity(activity: Omit<Activity, "id" | "timestamp">): Promise<Activity> {
    const newActivity: Activity = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      ...activity,
    };
    this.activities.unshift(newActivity);
    if (this.activities.length > 100) {
      this.activities = this.activities.slice(0, 100);
    }
    return newActivity;
  }
  
  async getActivities(limit: number = 10): Promise<Activity[]> {
    return this.activities.slice(0, limit);
  }
  
  async getReports(): Promise<Report[]> {
    return Array.from(this.reports.values());
  }
  
  async getReport(id: string): Promise<Report | undefined> {
    return this.reports.get(id);
  }
  
  async createReportFromScan(scanId: string): Promise<Report | undefined> {
    const scan = await this.getScan(scanId);
    if (!scan || scan.status !== "complete") return undefined;
    
    const reporterData = (scan.agentResults as any).reporter?.data;
    const scannerData = (scan.agentResults as any).scanner?.data;
    
    const report: Report = {
      id: randomUUID(),
      projectName: scan.target,
      scanId: scan.id,
      date: new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
      score: reporterData?.securityScore || 0,
      vulnerabilities: reporterData?.totalVulnerabilities || 0,
      details: {
        securityScore: reporterData?.securityScore || 0,
        vulnerabilities: scannerData?.vulnerabilities.map((v: any) => ({
          id: v.id,
          title: v.title,
          severity: v.severity,
          description: v.description,
        })) || [],
        recommendations: reporterData?.recommendations || [],
      }
    };
    
    this.reports.set(report.id, report);
    
    await this.addActivity({
      type: "scan_completed",
      message: `Report generated for ${scan.target}`,
      scanId: scan.id,
    });
    
    return report;
  }
  
  async getSettings(userId: string): Promise<UserSettings | undefined> {
    let settings = this.settings.get(userId);
    if (!settings) {
      settings = {
        userId,
        notifications: {
          email: true,
          criticalAlerts: true,
          weeklyReports: false,
          scanComplete: true,
        },
        profile: {
          name: "John Doe",
          email: "john@company.com",
        },
        company: {
          name: "Acme Inc.",
          website: "https://acme.com",
        },
      };
      this.settings.set(userId, settings);
    }
    return settings;
  }
  
  async updateSettings(userId: string, updates: Partial<UserSettings>): Promise<UserSettings> {
    let settings = await this.getSettings(userId);
    if (!settings) {
      settings = {
        userId,
        notifications: { email: true, criticalAlerts: true, weeklyReports: false, scanComplete: true },
        profile: { name: "User", email: "user@example.com" },
        company: { name: "Company", website: "https://example.com" },
      };
    }
    
    const updatedSettings: UserSettings = {
      ...settings,
      notifications: updates.notifications ? { ...settings.notifications, ...updates.notifications } : settings.notifications,
      profile: updates.profile ? { ...settings.profile, ...updates.profile } : settings.profile,
      company: updates.company ? { ...settings.company, ...updates.company } : settings.company,
    };
    
    this.settings.set(userId, updatedSettings);
    return updatedSettings;
  }

  async createApprovalRequest(request: any): Promise<any> {
    const id = randomUUID();
    const approvalRequest: any = {
      ...request,
      id,
      createdAt: new Date().toISOString(),
    };
    this.approvalRequests.set(id, approvalRequest);
    return approvalRequest;
  }

  async getApprovalRequest(id: string): Promise<any | undefined> {
    return this.approvalRequests.get(id);
  }

  async getApprovalRequestsByScan(scanId: string): Promise<any[]> {
    return Array.from(this.approvalRequests.values()).filter(r => r.scanId === scanId);
  }

  async getPendingApprovalRequests(userId: string): Promise<any[]> {
    return Array.from(this.approvalRequests.values()).filter(
      r => r.userId === userId && r.status === "pending"
    );
  }

  async updateApprovalRequest(id: string, updates: Partial<any>): Promise<any | undefined> {
    const request = this.approvalRequests.get(id);
    if (!request) return undefined;
    
    const updated: any = { ...request, ...updates };
    this.approvalRequests.set(id, updated);
    return updated;
  }

  async insertVulnerability(data: { scanId: string; userId: string; type: string; severity: string; title: string; description: string; url: string; payload?: string; remediation?: string }): Promise<void> {
    try {
      await db.insert(shadowlogicVulnerabilitiesTable).values({
        scanId: data.scanId,
        userId: data.userId,
        severity: data.severity,
        title: data.title,
        description: data.description,
        detectedAt: new Date(),
      });
      console.log(`[DB] Vulnerability inserted: ${data.type} on ${data.url}`);
    } catch (error) {
      console.error("[DB] Failed to insert vulnerability:", error);
    }
  }

  async insertDiscovery(data: { scanId: string; userId: string; discoveryType: string; url: string; title?: string; method?: string; parameters?: Record<string, unknown> }): Promise<void> {
    try {
      await db.insert(shadowlogicDiscoveriesTable).values({
        shadowlogicScanId: data.scanId,
        discoveryType: data.discoveryType,
        details: { url: data.url, title: data.title, method: data.method, parameters: data.parameters },
        discoveredAt: new Date(),
      });
      console.log(`[DB] Discovery inserted: ${data.discoveryType} - ${data.url}`);
    } catch (error) {
      console.error("[DB] Failed to insert discovery:", error);
    }
  }

  async saveIntegration(userId: string, integrationId: string, credentials: Record<string, string>): Promise<void> {
    if (!this.integrations.has(userId)) {
      this.integrations.set(userId, []);
    }
    const userIntegrations = this.integrations.get(userId) || [];
    const existing = userIntegrations.findIndex(i => i.id === integrationId);
    if (existing >= 0) {
      userIntegrations[existing] = { id: integrationId, config: credentials, connected: false, lastTested: null };
    } else {
      userIntegrations.push({ id: integrationId, config: credentials, connected: false, lastTested: null });
    }
    this.integrations.set(userId, userIntegrations);
  }

  async getIntegration(userId: string, integrationId: string): Promise<any | undefined> {
    const userIntegrations = this.integrations.get(userId) || [];
    return userIntegrations.find(i => i.id === integrationId);
  }

  async getIntegrations(userId: string): Promise<any[]> {
    return this.integrations.get(userId) || [];
  }

  async deleteIntegration(userId: string, integrationId: string): Promise<void> {
    const userIntegrations = this.integrations.get(userId) || [];
    const filtered = userIntegrations.filter(i => i.id !== integrationId);
    this.integrations.set(userId, filtered);
  }

  async testIntegration(integrationId: string, config: any): Promise<boolean> {
    // Simple test - in production would call actual API
    return !!(config && (config.apiKey || config.accessKeyId));
  }

  async updateIntegrationStatus(userId: string, integrationId: string, connected: boolean): Promise<void> {
    const userIntegrations = this.integrations.get(userId) || [];
    const integration = userIntegrations.find(i => i.id === integrationId);
    if (integration) {
      integration.connected = connected;
      integration.lastTested = new Date().toISOString();
    }
  }
}

export const storage = new MemStorage();
