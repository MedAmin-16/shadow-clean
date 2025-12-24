import type { Scan, EnhancedVulnerability } from "@shared/schema";

interface NotificationConfig {
  telegramBotToken?: string;
  telegramChatId?: string;
  discordWebhookUrl?: string;
  slackWebhookUrl?: string;
}

export class NotificationService {
  private config: NotificationConfig;

  constructor(config?: NotificationConfig) {
    this.config = config || {
      telegramBotToken: process.env.TELEGRAM_BOT_TOKEN,
      telegramChatId: process.env.TELEGRAM_CHAT_ID,
      discordWebhookUrl: process.env.DISCORD_WEBHOOK_URL,
      slackWebhookUrl: process.env.SLACK_WEBHOOK_URL,
    };
  }

  async notifyCriticalVulnerability(
    scan: Scan,
    vulnerability: EnhancedVulnerability,
    target: string
  ): Promise<void> {
    const message = `
🚨 CRITICAL VULNERABILITY DETECTED 🚨
Target: ${target}
Scan ID: ${scan.id}
Vulnerability: ${vulnerability.title}
Severity: ${vulnerability.severity.toUpperCase()}
OWASP: ${vulnerability.owaspCategory || "N/A"}
Description: ${vulnerability.description}
CVE: ${vulnerability.cve || "N/A"}
    `.trim();

    // Send to Discord
    if (this.config.discordWebhookUrl) {
      await this.sendDiscordNotification(message, vulnerability.severity);
    }

    // Send to Telegram
    if (this.config.telegramBotToken && this.config.telegramChatId) {
      await this.sendTelegramNotification(message);
    }

    // Send to Slack
    if (this.config.slackWebhookUrl) {
      await this.sendSlackNotification(message, vulnerability.severity);
    }
  }

  async notifyScanComplete(
    scan: Scan,
    vulnerabilityCount: number,
    criticalCount: number,
    target: string
  ): Promise<void> {
    const message = `
✅ SCAN COMPLETE
Target: ${target}
Scan ID: ${scan.id}
Total Vulnerabilities: ${vulnerabilityCount}
Critical: ${criticalCount}
Duration: ${scan.completedAt ? Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000) : 0}s
    `.trim();

    if (this.config.discordWebhookUrl) {
      await this.sendDiscordNotification(message, "info");
    }

    if (this.config.telegramBotToken && this.config.telegramChatId) {
      await this.sendTelegramNotification(message);
    }
  }

  private async sendDiscordNotification(message: string, severity: string): Promise<void> {
    if (!this.config.discordWebhookUrl) return;

    try {
      const color =
        severity === "critical"
          ? 15158332
          : severity === "high"
            ? 16711680
            : severity === "medium"
              ? 16776960
              : 65280;

      await fetch(this.config.discordWebhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          embeds: [
            {
              title: "ShadowTwin Security Alert",
              description: message,
              color: color,
              timestamp: new Date().toISOString(),
            },
          ],
        }),
      });
    } catch (error) {
      console.error("Discord notification failed:", error);
    }
  }

  private async sendTelegramNotification(message: string): Promise<void> {
    if (!this.config.telegramBotToken || !this.config.telegramChatId) return;

    try {
      await fetch(
        `https://api.telegram.org/bot${this.config.telegramBotToken}/sendMessage`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: this.config.telegramChatId,
            text: message,
            parse_mode: "HTML",
          }),
        }
      );
    } catch (error) {
      console.error("Telegram notification failed:", error);
    }
  }

  private async sendSlackNotification(message: string, severity: string): Promise<void> {
    if (!this.config.slackWebhookUrl) return;

    try {
      const color =
        severity === "critical"
          ? "danger"
          : severity === "high"
            ? "warning"
            : severity === "medium"
              ? "#ff9900"
              : "good";

      await fetch(this.config.slackWebhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attachments: [
            {
              color: color,
              title: "ShadowTwin Security Alert",
              text: message,
              ts: Math.floor(Date.now() / 1000),
            },
          ],
        }),
      });
    } catch (error) {
      console.error("Slack notification failed:", error);
    }
  }
}

export const notificationService = new NotificationService();
