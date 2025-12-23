import rateLimit from "express-rate-limit";
import type { Request, Response } from "express";

export const scanRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: "Too many requests",
    message: "Rate limit exceeded. Please try again later.",
    retryAfter: 15 * 60,
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    const apiKey = req.headers["x-api-key"] as string;
    if (apiKey) return apiKey;
    return "global";
  },
  handler: (_req: Request, res: Response) => {
    res.status(429).json({
      error: "Too many requests",
      message: "Rate limit exceeded. Please try again later.",
    });
  },
});

export const strictRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: {
    error: "Too many requests",
    message: "Rate limit exceeded. Please wait before trying again.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});
