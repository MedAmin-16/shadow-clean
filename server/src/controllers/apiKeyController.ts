import type { Request, Response } from "express";
import { generateApiKey, revokeApiKey, getApiKeysByUser, getInvalidAttempts } from "../middlewares/apiKeyAuth";
import { createLogger } from "../utils/logger";

const logger = createLogger("api-key");

export async function createApiKey(req: Request, res: Response): Promise<void> {
  try {
    const { userId, name } = req.body;

    if (!userId || !name) {
      res.status(400).json({ error: "userId and name are required" });
      return;
    }

    const apiKey = generateApiKey(userId, name);
    logger.info(`API key created for user ${userId}: ${apiKey.id}`);

    res.status(201).json({
      id: apiKey.id,
      key: apiKey.key,
      name: apiKey.name,
      createdAt: apiKey.createdAt,
      message: "Store this key securely. It will not be shown again.",
    });
  } catch (error) {
    logger.error("Error creating API key", { error: String(error) });
    res.status(500).json({ error: "Failed to create API key" });
  }
}

export async function listApiKeys(req: Request, res: Response): Promise<void> {
  try {
    const { userId } = req.params;

    if (!userId) {
      res.status(400).json({ error: "userId is required" });
      return;
    }

    const keys = getApiKeysByUser(userId);

    res.json(
      keys.map((k) => ({
        id: k.id,
        name: k.name,
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt,
        isActive: k.isActive,
        keyPreview: k.key.substring(0, 10) + "...",
      }))
    );
  } catch (error) {
    logger.error("Error listing API keys", { error: String(error) });
    res.status(500).json({ error: "Failed to list API keys" });
  }
}

export async function deleteApiKey(req: Request, res: Response): Promise<void> {
  try {
    const { keyId } = req.params;

    const revoked = revokeApiKey(keyId);

    if (!revoked) {
      res.status(404).json({ error: "API key not found" });
      return;
    }

    logger.info(`API key revoked: ${keyId}`);
    res.json({ message: "API key revoked successfully" });
  } catch (error) {
    logger.error("Error revoking API key", { error: String(error) });
    res.status(500).json({ error: "Failed to revoke API key" });
  }
}

export async function getSecurityLogs(req: Request, res: Response): Promise<void> {
  try {
    const limit = parseInt(req.query.limit as string) || 100;
    const attempts = getInvalidAttempts(limit);

    res.json({
      invalidAttempts: attempts,
      count: attempts.length,
    });
  } catch (error) {
    logger.error("Error fetching security logs", { error: String(error) });
    res.status(500).json({ error: "Failed to fetch security logs" });
  }
}
