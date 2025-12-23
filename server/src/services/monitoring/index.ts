import type { InsertMonitoringSchedule } from "@shared/advancedFeatures";
import type { PlanLevel } from "@shared/schema";

export interface MonitoringSchedule {
  id: number;
  userId: string;
  projectId?: string;
  target: string;
  frequency: "daily" | "weekly" | "monthly";
  enabled: boolean;
  lastRunAt?: Date;
  nextRunAt?: Date;
  config?: {
    notifyOnChanges?: boolean;
    emailRecipients?: string[];
    scanDepth?: "quick" | "standard" | "comprehensive";
  };
  createdAt: Date;
}

export interface MonitoringResult {
  scheduleId: number;
  scanId?: string;
  status: "success" | "failed" | "running";
  changesDetected: boolean;
  newVulnerabilities: number;
  resolvedVulnerabilities: number;
  summary?: {
    previousScore?: number;
    currentScore?: number;
    scoreDelta?: number;
    criticalChanges?: string[];
  };
  runAt: Date;
}

const schedules: Map<number, MonitoringSchedule> = new Map();
const results: Map<number, MonitoringResult[]> = new Map();
let scheduleIdCounter = 1;

export class MonitoringService {
  getAllowedFrequency(planLevel: PlanLevel): ("daily" | "weekly" | "monthly")[] {
    switch (planLevel) {
      case "ELITE":
        return ["daily", "weekly", "monthly"];
      case "PRO":
        return ["weekly", "monthly"];
      case "STANDARD":
      default:
        return [];
    }
  }

  canCreateSchedule(planLevel: PlanLevel, frequency: "daily" | "weekly" | "monthly"): boolean {
    const allowed = this.getAllowedFrequency(planLevel);
    return allowed.includes(frequency);
  }

  async createSchedule(
    userId: string,
    data: InsertMonitoringSchedule,
    planLevel: PlanLevel
  ): Promise<MonitoringSchedule> {
    if (!this.canCreateSchedule(planLevel, data.frequency)) {
      throw new Error(`${data.frequency} monitoring is not available on your plan. Please upgrade.`);
    }

    const schedule: MonitoringSchedule = {
      id: scheduleIdCounter++,
      userId,
      projectId: data.projectId,
      target: data.target,
      frequency: data.frequency,
      enabled: true,
      nextRunAt: this.calculateNextRun(data.frequency),
      config: data.config,
      createdAt: new Date(),
    };

    schedules.set(schedule.id, schedule);
    results.set(schedule.id, []);

    console.log(`[Monitoring] Created schedule ${schedule.id} for ${data.target} (${data.frequency})`);

    return schedule;
  }

  async getUserSchedules(userId: string): Promise<MonitoringSchedule[]> {
    return Array.from(schedules.values()).filter(s => s.userId === userId);
  }

  async getSchedule(scheduleId: number): Promise<MonitoringSchedule | undefined> {
    return schedules.get(scheduleId);
  }

  async updateSchedule(
    scheduleId: number,
    updates: Partial<Pick<MonitoringSchedule, "enabled" | "frequency" | "config">>
  ): Promise<MonitoringSchedule | undefined> {
    const schedule = schedules.get(scheduleId);
    if (!schedule) return undefined;

    if (updates.enabled !== undefined) schedule.enabled = updates.enabled;
    if (updates.frequency) {
      schedule.frequency = updates.frequency;
      schedule.nextRunAt = this.calculateNextRun(updates.frequency);
    }
    if (updates.config) schedule.config = { ...schedule.config, ...updates.config };

    schedules.set(scheduleId, schedule);
    return schedule;
  }

  async deleteSchedule(scheduleId: number): Promise<boolean> {
    const deleted = schedules.delete(scheduleId);
    results.delete(scheduleId);
    return deleted;
  }

  async getScheduleResults(scheduleId: number, limit: number = 10): Promise<MonitoringResult[]> {
    const scheduleResults = results.get(scheduleId) || [];
    return scheduleResults.slice(-limit);
  }

  async runScheduledScan(scheduleId: number): Promise<MonitoringResult> {
    const schedule = schedules.get(scheduleId);
    if (!schedule) {
      throw new Error("Schedule not found");
    }

    const result: MonitoringResult = {
      scheduleId,
      status: "running",
      changesDetected: false,
      newVulnerabilities: 0,
      resolvedVulnerabilities: 0,
      runAt: new Date(),
    };

    const scheduleResults = results.get(scheduleId) || [];

    try {
      await new Promise(resolve => setTimeout(resolve, 1000));

      const changesDetected = Math.random() > 0.7;
      const newVulns = changesDetected ? Math.floor(Math.random() * 3) : 0;
      const resolvedVulns = changesDetected ? Math.floor(Math.random() * 2) : 0;

      result.status = "success";
      result.changesDetected = changesDetected;
      result.newVulnerabilities = newVulns;
      result.resolvedVulnerabilities = resolvedVulns;
      result.summary = {
        previousScore: 75 + Math.floor(Math.random() * 20),
        currentScore: 70 + Math.floor(Math.random() * 25),
        scoreDelta: resolvedVulns - newVulns,
        criticalChanges: changesDetected 
          ? ["New SQL injection detected", "SSL certificate expires in 7 days"]
          : [],
      };

      schedule.lastRunAt = new Date();
      schedule.nextRunAt = this.calculateNextRun(schedule.frequency);
      schedules.set(scheduleId, schedule);

    } catch (error) {
      result.status = "failed";
      console.error(`[Monitoring] Scan failed for schedule ${scheduleId}:`, error);
    }

    scheduleResults.push(result);
    results.set(scheduleId, scheduleResults.slice(-100));

    return result;
  }

  async getDueSchedules(): Promise<MonitoringSchedule[]> {
    const now = new Date();
    return Array.from(schedules.values())
      .filter(s => s.enabled && s.nextRunAt && s.nextRunAt <= now);
  }

  async processDueSchedules(): Promise<{ processed: number; failed: number }> {
    const dueSchedules = await this.getDueSchedules();
    let processed = 0;
    let failed = 0;

    for (const schedule of dueSchedules) {
      try {
        await this.runScheduledScan(schedule.id);
        processed++;
      } catch (error) {
        failed++;
        console.error(`[Monitoring] Failed to process schedule ${schedule.id}:`, error);
      }
    }

    return { processed, failed };
  }

  private calculateNextRun(frequency: "daily" | "weekly" | "monthly"): Date {
    const now = new Date();
    
    switch (frequency) {
      case "daily":
        return new Date(now.getTime() + 24 * 60 * 60 * 1000);
      case "weekly":
        return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      case "monthly":
        return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      default:
        return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    }
  }
}

export const monitoringService = new MonitoringService();
