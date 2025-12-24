import { Worker, Job } from "bullmq";
import type { ScanJobData } from "../types";
import { createLogger } from "../utils/logger";
import { runSequentialScan } from "../../agents/sequentialScan";
import { storage } from "../../storage";
import { emitScanCompleted } from "../sockets/socketManager";
import { sendScanCompletedEmail } from "../services/emailService";
import { createReport, generatePdfReport } from "../services/reportService";

const logger = createLogger("worker");

let worker: Worker<ScanJobData> | null = null;

export async function initScanWorker(): Promise<Worker<ScanJobData> | null> {
  if (!process.env.REDIS_URL && !process.env.REDIS_HOST) {
    logger.warn("Redis not configured. Worker disabled.");
    return null;
  }

  const redisConnection = process.env.REDIS_URL
    ? { url: process.env.REDIS_URL }
    : { host: process.env.REDIS_HOST || "localhost", port: parseInt(process.env.REDIS_PORT || "6379") };

  try {
    worker = new Worker<ScanJobData>(
      "scanQueue",
      async (job: Job<ScanJobData>) => {
        const { jobId, target, userId, options } = job.data;
        logger.info(`Processing scan job: ${jobId}`, { target, userId });

        try {
          await job.updateProgress(10);
          await storage.updateScan(jobId, { status: "running" });

          await job.updateProgress(20);
          await runSequentialScan(jobId, target);

          await job.updateProgress(90);
          const scan = await storage.getScan(jobId);

          if (scan) {
            const report = await createReport({
              jobId,
              userId,
              target,
              result: scan.agentResults as Record<string, unknown>,
            });

            if (report) {
              await generatePdfReport(report.id);
            }

            emitScanCompleted({
              jobId,
              userId,
              target,
              status: "completed",
              result: scan.agentResults as Record<string, unknown>,
            });

            if (process.env.SMTP_HOST) {
              const userEmail = options.email as string | undefined;
              if (userEmail) {
                await sendScanCompletedEmail(userEmail, {
                  jobId,
                  target,
                  status: "completed",
                  result: scan.agentResults as Record<string, unknown>,
                });
              }
            }
          }

          await job.updateProgress(100);
          logger.info(`Scan job completed: ${jobId}`);
          return { success: true, scanId: jobId };
        } catch (error) {
          logger.error(`Scan job failed: ${jobId}`, { error: String(error) });
          await storage.updateScan(jobId, { 
            status: "failed", 
            error: String(error) 
          });

          emitScanCompleted({
            jobId,
            userId,
            target,
            status: "failed",
            error: String(error),
          });

          throw error;
        }
      },
      {
        connection: redisConnection,
        concurrency: 5,
      }
    );

    worker.on("completed", (job) => {
      logger.info(`Job ${job.id} completed`);
    });

    worker.on("failed", (job, error) => {
      logger.error(`Job ${job?.id} failed`, { error: error.message });
    });

    logger.info("Scan worker initialized");
    return worker;
  } catch (error) {
    logger.error("Failed to initialize scan worker", { error: String(error) });
    return null;
  }
}

export function getWorker(): Worker<ScanJobData> | null {
  return worker;
}
