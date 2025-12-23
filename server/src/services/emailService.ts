import nodemailer from "nodemailer";
import type { Transporter } from "nodemailer";
import type { EmailOptions } from "../types";
import { createLogger } from "../utils/logger";

const logger = createLogger("email");

let transporter: Transporter | null = null;

export function initEmailService(): Transporter | null {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;

  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    logger.warn("SMTP not configured. Email notifications disabled.");
    return null;
  }

  try {
    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: parseInt(SMTP_PORT || "587"),
      secure: SMTP_PORT === "465",
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
      },
    });

    logger.info("Email service initialized");
    return transporter;
  } catch (error) {
    logger.error("Failed to initialize email service", { error: String(error) });
    return null;
  }
}

export async function sendEmail(options: EmailOptions): Promise<boolean> {
  if (!transporter) {
    logger.warn("Email service not configured");
    return false;
  }

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: options.to,
      subject: options.subject,
      html: options.html,
    });
    logger.info(`Email sent to ${options.to}`);
    return true;
  } catch (error) {
    logger.error("Failed to send email", { error: String(error), to: options.to });
    return false;
  }
}

export async function sendScanCompletedEmail(
  to: string,
  data: { jobId: string; target: string; status: string; result?: Record<string, unknown> }
): Promise<boolean> {
  const statusColor = data.status === "completed" ? "#22c55e" : "#ef4444";
  const statusText = data.status === "completed" ? "Completed Successfully" : "Failed";

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white; padding: 24px; }
        .header h1 { margin: 0; font-size: 24px; }
        .content { padding: 24px; }
        .status { display: inline-block; padding: 6px 12px; border-radius: 4px; background: ${statusColor}; color: white; font-weight: 600; }
        .details { background: #f8fafc; padding: 16px; border-radius: 6px; margin: 16px 0; }
        .details p { margin: 8px 0; }
        .footer { padding: 16px 24px; background: #f8fafc; text-align: center; color: #64748b; font-size: 14px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Scan Report</h1>
        </div>
        <div class="content">
          <p>Your security scan has finished processing.</p>
          <p><span class="status">${statusText}</span></p>
          <div class="details">
            <p><strong>Target:</strong> ${data.target}</p>
            <p><strong>Job ID:</strong> ${data.jobId}</p>
            <p><strong>Status:</strong> ${data.status}</p>
          </div>
          <p>View the full report in your dashboard.</p>
        </div>
        <div class="footer">
          <p>ShadowTwin Security Scanner</p>
        </div>
      </div>
    </body>
    </html>
  `;

  return sendEmail({
    to,
    subject: `Scan ${statusText}: ${data.target}`,
    html,
  });
}
