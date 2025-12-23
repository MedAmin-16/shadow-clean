import { Queue, QueueEvents } from "bullmq";
import type { ScanJobData } from "../types";
import { createLogger } from "../utils/logger";

const logger = createLogger("queue");

const redisConnection = process.env.REDIS_URL
  ? { url: process.env.REDIS_URL }
  : { host: process.env.REDIS_HOST || "localhost", port: parseInt(process.env.REDIS_PORT || "6379") };

let scanQueue: Queue<ScanJobData> | null = null;
let queueEvents: QueueEvents | null = null;

export async function initScanQueue(): Promise<Queue<ScanJobData> | null> {
  if (!process.env.REDIS_URL && !process.env.REDIS_HOST) {
    logger.warn("Redis not configured. Job queue disabled. Set REDIS_URL or REDIS_HOST to enable.");
    return null;
  }

  try {
    scanQueue = new Queue<ScanJobData>("scanQueue", {
      connection: redisConnection,
      defaultJobOptions: {
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 50 },
        attempts: 3,
        backoff: {
          type: "exponential",
          delay: 1000,
        },
      },
    });

    queueEvents = new QueueEvents("scanQueue", { connection: redisConnection });

    await scanQueue.waitUntilReady();
    logger.info("Scan queue initialized successfully");
    return scanQueue;
  } catch (error) {
    logger.error("Failed to initialize scan queue", { error: String(error) });
    return null;
  }
}

export function getScanQueue(): Queue<ScanJobData> | null {
  return scanQueue;
}

export function getQueueEvents(): QueueEvents | null {
  return queueEvents;
}

export async function addScanJob(data: ScanJobData): Promise<string | null> {
  if (!scanQueue) {
    logger.warn("Queue not available, running scan synchronously");
    return null;
  }

  try {
    const job = await scanQueue.add("scan", data, {
      jobId: data.jobId,
    });
    logger.info(`Scan job added: ${job.id}`);
    return job.id || null;
  } catch (error) {
    logger.error("Failed to add scan job", { error: String(error) });
    return null;
  }
}

export async function getJobStatus(jobId: string): Promise<{ status: string; progress: number; result?: unknown } | null> {
  if (!scanQueue) return null;

  try {
    const job = await scanQueue.getJob(jobId);
    if (!job) return null;

    const state = await job.getState();
    const progress = typeof job.progress === "number" ? job.progress : 0;

    return {
      status: state,
      progress,
      result: job.returnvalue,
    };
  } catch (error) {
    logger.error("Failed to get job status", { error: String(error) });
    return null;
  }
}
