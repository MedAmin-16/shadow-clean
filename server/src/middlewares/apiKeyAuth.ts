import type { Response, NextFunction } from "express";
import type { AuthenticatedRequest, ApiKey } from "../types";
import { log } from "../../index";
import { randomUUID } from "crypto";

const apiKeys = new Map<string, ApiKey>();
const invalidAttempts: { key: string; ip: string; timestamp: Date }[] = [];

export function generateApiKey(userId: string, name: string): ApiKey {
  const key = `stk_${randomUUID().replace(/-/g, "")}`;
  const apiKey: ApiKey = {
    id: randomUUID(),
    key,
    userId,
    name,
    createdAt: new Date(),
    lastUsedAt: null,
    isActive: true,
  };
  apiKeys.set(key, apiKey);
  return apiKey;
}

export function revokeApiKey(keyId: string): boolean {
  const entries = Array.from(apiKeys.entries());
  for (const [key, apiKey] of entries) {
    if (apiKey.id === keyId) {
      apiKey.isActive = false;
      apiKeys.set(key, apiKey);
      return true;
    }
  }
  return false;
}

export function getApiKeysByUser(userId: string): ApiKey[] {
  return Array.from(apiKeys.values()).filter((k) => k.userId === userId);
}

export function getInvalidAttempts(limit = 100): typeof invalidAttempts {
  return invalidAttempts.slice(-limit);
}

export async function apiKeyAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const apiKeyHeader = req.headers["x-api-key"] as string | undefined;

  if (!apiKeyHeader) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Missing x-api-key header",
    });
    return;
  }

  const apiKey = apiKeys.get(apiKeyHeader);

  if (!apiKey) {
    invalidAttempts.push({
      key: apiKeyHeader.substring(0, 10) + "...",
      ip: req.ip || "unknown",
      timestamp: new Date(),
    });
    log(`Invalid API key attempt from ${req.ip}: ${apiKeyHeader.substring(0, 10)}...`, "security");
    
    res.status(401).json({
      error: "Unauthorized",
      message: "Invalid API key",
    });
    return;
  }

  if (!apiKey.isActive) {
    log(`Revoked API key used: ${apiKey.id} by user ${apiKey.userId}`, "security");
    res.status(401).json({
      error: "Unauthorized",
      message: "API key has been revoked",
    });
    return;
  }

  apiKey.lastUsedAt = new Date();
  apiKeys.set(apiKeyHeader, apiKey);

  req.apiKey = apiKey;
  req.userId = apiKey.userId;

  next();
}

export async function optionalApiKeyAuth(
  req: AuthenticatedRequest,
  _res: Response,
  next: NextFunction
): Promise<void> {
  const apiKeyHeader = req.headers["x-api-key"] as string | undefined;

  if (apiKeyHeader) {
    const apiKey = apiKeys.get(apiKeyHeader);
    if (apiKey && apiKey.isActive) {
      apiKey.lastUsedAt = new Date();
      apiKeys.set(apiKeyHeader, apiKey);
      req.apiKey = apiKey;
      req.userId = apiKey.userId;
    }
  }

  next();
}
