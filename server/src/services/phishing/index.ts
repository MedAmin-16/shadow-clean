import type { 
  PhishingTemplate, 
  PhishingCampaignRequest, 
  PhishingCampaignStats,
  InsertPhishingCampaign 
} from "@shared/advancedFeatures";

export interface PhishingCampaign {
  id: number;
  userId: string;
  name: string;
  templateType: string;
  status: "draft" | "scheduled" | "running" | "completed";
  targetEmails: string[];
  scheduledAt?: Date;
  startedAt?: Date;
  completedAt?: Date;
  config?: {
    customSubject?: string;
    customSenderName?: string;
    landingPageUrl?: string;
  };
  createdAt: Date;
}

export interface PhishingResult {
  id: number;
  campaignId: number;
  targetEmail: string;
  emailSent: boolean;
  emailOpened: boolean;
  linkClicked: boolean;
  credentialsSubmitted: boolean;
  reported: boolean;
  sentAt?: Date;
  openedAt?: Date;
  clickedAt?: Date;
  submittedAt?: Date;
  reportedAt?: Date;
}

const PHISHING_TEMPLATES: PhishingTemplate[] = [
  {
    id: "it-password-reset",
    name: "IT Department Password Reset",
    type: "credential_harvest",
    subject: "Action Required: Password Reset",
    senderName: "IT Security Team",
    previewText: "Your password will expire in 24 hours. Reset now to avoid access disruption.",
    difficulty: "easy",
  },
  {
    id: "hr-document-share",
    name: "HR Document Sharing",
    type: "credential_harvest",
    subject: "Important: Updated Employee Handbook",
    senderName: "Human Resources",
    previewText: "Please review the updated employee handbook and acknowledge receipt.",
    difficulty: "medium",
  },
  {
    id: "ceo-urgent-request",
    name: "CEO Urgent Request",
    type: "credential_harvest",
    subject: "Urgent: Need your help with something",
    senderName: "CEO Office",
    previewText: "I need you to help me with a quick task. Are you available?",
    difficulty: "hard",
  },
  {
    id: "invoice-payment",
    name: "Invoice Payment Reminder",
    type: "credential_harvest",
    subject: "Invoice #INV-2024-8734 - Payment Overdue",
    senderName: "Accounts Payable",
    previewText: "Your invoice is overdue. Please review and process payment immediately.",
    difficulty: "medium",
  },
  {
    id: "security-training",
    name: "Mandatory Security Training",
    type: "awareness",
    subject: "Complete Your Annual Security Training",
    senderName: "Security Awareness Team",
    previewText: "This is a simulated phishing email. Click here to learn more about phishing protection.",
    difficulty: "easy",
  },
  {
    id: "package-delivery",
    name: "Package Delivery Notification",
    type: "malware_download",
    subject: "Your Package is Ready for Pickup",
    senderName: "Shipping Department",
    previewText: "Track your package or download shipping label. Delivery scheduled for today.",
    difficulty: "easy",
  },
];

const campaigns: Map<number, PhishingCampaign> = new Map();
const campaignResults: Map<number, Map<string, PhishingResult>> = new Map();
let campaignIdCounter = 1;
let resultIdCounter = 1;

export class PhishingService {
  getTemplates(): PhishingTemplate[] {
    return PHISHING_TEMPLATES;
  }

  getTemplate(templateId: string): PhishingTemplate | undefined {
    return PHISHING_TEMPLATES.find(t => t.id === templateId);
  }

  async createCampaign(
    userId: string,
    data: InsertPhishingCampaign
  ): Promise<PhishingCampaign> {
    const campaign: PhishingCampaign = {
      id: campaignIdCounter++,
      userId,
      name: data.name,
      templateType: data.templateType,
      status: data.scheduledAt ? "scheduled" : "draft",
      targetEmails: data.targetEmails,
      scheduledAt: data.scheduledAt ? new Date(data.scheduledAt) : undefined,
      config: data.config,
      createdAt: new Date(),
    };

    campaigns.set(campaign.id, campaign);
    campaignResults.set(campaign.id, new Map());

    for (const email of data.targetEmails) {
      const result: PhishingResult = {
        id: resultIdCounter++,
        campaignId: campaign.id,
        targetEmail: email,
        emailSent: false,
        emailOpened: false,
        linkClicked: false,
        credentialsSubmitted: false,
        reported: false,
      };
      campaignResults.get(campaign.id)!.set(email, result);
    }

    console.log(`[Phishing] Created campaign ${campaign.id}: ${campaign.name}`);

    return campaign;
  }

  async getCampaign(campaignId: number): Promise<PhishingCampaign | undefined> {
    return campaigns.get(campaignId);
  }

  async getUserCampaigns(userId: string): Promise<PhishingCampaign[]> {
    return Array.from(campaigns.values()).filter(c => c.userId === userId);
  }

  async launchCampaign(campaignId: number): Promise<PhishingCampaign> {
    const campaign = campaigns.get(campaignId);
    if (!campaign) {
      throw new Error("Campaign not found");
    }

    if (campaign.status === "running" || campaign.status === "completed") {
      throw new Error("Campaign already launched");
    }

    campaign.status = "running";
    campaign.startedAt = new Date();

    const resultsMap = campaignResults.get(campaignId)!;
    const entries = Array.from(resultsMap.entries());
    for (let i = 0; i < entries.length; i++) {
      const [email, result] = entries[i];
      result.emailSent = true;
      result.sentAt = new Date();
      resultsMap.set(email, result);
    }

    campaigns.set(campaignId, campaign);

    console.log(`[Phishing] Launched campaign ${campaignId}`);

    this.simulateResults(campaignId);

    return campaign;
  }

  private async simulateResults(campaignId: number): Promise<void> {
    const resultsMap = campaignResults.get(campaignId);
    if (!resultsMap) return;

    await new Promise(resolve => setTimeout(resolve, 2000));

    const simEntries = Array.from(resultsMap.entries());
    for (let i = 0; i < simEntries.length; i++) {
      const [email, result] = simEntries[i];
      if (Math.random() > 0.3) {
        result.emailOpened = true;
        result.openedAt = new Date();

        if (Math.random() > 0.5) {
          result.linkClicked = true;
          result.clickedAt = new Date();

          if (Math.random() > 0.7) {
            result.credentialsSubmitted = true;
            result.submittedAt = new Date();
          }
        }
      }

      if (Math.random() > 0.85) {
        result.reported = true;
        result.reportedAt = new Date();
      }

      resultsMap.set(email, result);
    }

    const campaign = campaigns.get(campaignId);
    if (campaign) {
      campaign.status = "completed";
      campaign.completedAt = new Date();
      campaigns.set(campaignId, campaign);
    }
  }

  async getCampaignResults(campaignId: number): Promise<PhishingResult[]> {
    const resultsMap = campaignResults.get(campaignId);
    if (!resultsMap) return [];
    return Array.from(resultsMap.values());
  }

  async getCampaignStats(campaignId: number): Promise<PhishingCampaignStats> {
    const results = await this.getCampaignResults(campaignId);
    
    const totalTargets = results.length;
    const emailsSent = results.filter(r => r.emailSent).length;
    const emailsOpened = results.filter(r => r.emailOpened).length;
    const linksClicked = results.filter(r => r.linkClicked).length;
    const credentialsSubmitted = results.filter(r => r.credentialsSubmitted).length;
    const reported = results.filter(r => r.reported).length;

    return {
      campaignId,
      totalTargets,
      emailsSent,
      emailsOpened,
      linksClicked,
      credentialsSubmitted,
      reported,
      openRate: totalTargets > 0 ? (emailsOpened / totalTargets) * 100 : 0,
      clickRate: emailsOpened > 0 ? (linksClicked / emailsOpened) * 100 : 0,
      submissionRate: linksClicked > 0 ? (credentialsSubmitted / linksClicked) * 100 : 0,
      reportRate: totalTargets > 0 ? (reported / totalTargets) * 100 : 0,
    };
  }

  async recordInteraction(
    campaignId: number,
    email: string,
    action: "opened" | "clicked" | "submitted" | "reported"
  ): Promise<void> {
    const resultsMap = campaignResults.get(campaignId);
    if (!resultsMap) return;

    const result = resultsMap.get(email);
    if (!result) return;

    const now = new Date();

    switch (action) {
      case "opened":
        result.emailOpened = true;
        result.openedAt = now;
        break;
      case "clicked":
        result.linkClicked = true;
        result.clickedAt = now;
        break;
      case "submitted":
        result.credentialsSubmitted = true;
        result.submittedAt = now;
        break;
      case "reported":
        result.reported = true;
        result.reportedAt = now;
        break;
    }

    resultsMap.set(email, result);
  }

  async deleteCampaign(campaignId: number): Promise<boolean> {
    const deleted = campaigns.delete(campaignId);
    campaignResults.delete(campaignId);
    return deleted;
  }
}

export const phishingService = new PhishingService();
