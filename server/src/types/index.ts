import type { Request } from "express";

export interface ApiKey {
  id: string;
  key: string;
  userId: string;
  name: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  isActive: boolean;
}

export interface ScanJob {
  id: string;
  target: string;
  options: Record<string, unknown>;
  userId: string;
  status: "pending" | "running" | "completed" | "failed";
  result: Record<string, unknown> | null;
  error: string | null;
  createdAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
}

export interface ScanReport {
  id: string;
  jobId: string;
  userId: string;
  target: string;
  result: Record<string, unknown>;
  pdfPath: string | null;
  createdAt: Date;
}

export interface AuthenticatedRequest extends Request {
  apiKey?: ApiKey;
  userId?: string;
}

export interface ScanJobData {
  target: string;
  options: Record<string, unknown>;
  userId: string;
  jobId: string;
}

export interface NotificationPayload {
  jobId: string;
  userId: string;
  target: string;
  status: "completed" | "failed";
  result?: Record<string, unknown>;
  error?: string;
}

export interface EmailOptions {
  to: string;
  subject: string;
  html: string;
}
