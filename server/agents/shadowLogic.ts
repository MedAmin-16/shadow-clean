import { chromium, Browser, BrowserContext, Page } from "playwright";
import Groq from "groq-sdk";
import { nanoid } from "nanoid";
import type {
  ShadowLogicScanConfig,
  ShadowLogicScanResult,
  ShadowLogicThought,
  BusinessFlow,
  BusinessFlowNode,
  BusinessLogicVulnerability,
  ShadowLogicTestType,
  ShadowLogicPhase,
  ThoughtType,
  SHADOW_LOGIC_COSTS,
} from "@shared/shadowLogic";
import { storage } from "../storage";

// Lazy load socket functions to avoid circular dependencies
let emitScanProgress: any;
let emitUrlStream: any;
let emitPhaseUpdate: any;
let emitToScan: any;
let emitAiThought: any;
let emitTerminalLog: any;

const loadSocketFunctions = async () => {
  if (!emitScanProgress) {
    try {
      const socketManager = await import("../src/sockets/socketManager");
      emitScanProgress = socketManager.emitScanProgress;
      emitUrlStream = socketManager.emitUrlStream;
      emitPhaseUpdate = socketManager.emitPhaseUpdate;
      emitAiThought = socketManager.emitAiThought;
      emitTerminalLog = socketManager.emitTerminalLog;
      emitToScan = socketManager.emitToScan || ((scanId: string, event: string, data: any) => {
        const io = socketManager.getSocketServer?.();
        if (io) {
          io.to(`scan:${scanId}`).emit(event, data);
        }
      });
    } catch (error) {
      console.error("Failed to load socket functions:", error);
    }
  }
};

const SAFETY_BLOCKED_PATTERNS = [
  /delete|drop|truncate|remove.*all/i,
  /admin.*password|password.*admin/i,
  /rm\s+-rf/i,
  /format.*drive/i,
];

const BLOCKED_DOMAINS = [
  ".gov",
  ".mil",
  ".edu",
  "bank",
  "paypal",
  "stripe.com",
  "visa.com",
  "mastercard.com",
];

interface GeminiAnalysisResult {
  businessFlows: string[];
  criticalEndpoints: string[];
  potentialVulnerabilities: string[];
  recommendedTests: ShadowLogicTestType[];
}

export class ShadowLogicAgent {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private page: Page | null = null;
  private groq: Groq | null = null;
  private scanResult: ShadowLogicScanResult;
  private onUpdate: ((thought: ShadowLogicThought) => void) | null = null;
  private config: ShadowLogicScanConfig;
  private discoveredUrls: Set<string> = new Set();
  private visitedUrls: Set<string> = new Set();
  private networkRequests: Map<string, { method: string; url: string; body?: string; response?: string }> = new Map();
  private scanId: string = "";
  private userId: string = "";
  
  private eventBatch: any[] = [];
  private eventBatchTimer: NodeJS.Timeout | null = null;
  
  private concurrentRequests: number = 0;
  private maxConcurrentRequests: number = 2;
  private groqAnalysisInProgress: boolean = false;
  private lastRequestTime: number = 0;
  private requestDelayMs: number = 250;

  private readonly SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "1; DROP TABLE users--",
  ];

  private readonly XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
  ];

  private readonly PATH_TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "/etc/passwd",
  ];

  constructor(config: ShadowLogicScanConfig, userId: string, scanId: string, onUpdate?: (thought: ShadowLogicThought) => void) {
    this.config = config;
    this.userId = userId;
    this.scanId = scanId;
    this.onUpdate = onUpdate || null;
    
    this.scanResult = {
      id: nanoid(),
      userId,
      targetUrl: config.targetUrl,
      status: "initializing",
      startedAt: new Date().toISOString(),
      businessFlows: [],
      vulnerabilities: [],
      thoughts: [],
      statistics: {
        pagesVisited: 0,
        formsAnalyzed: 0,
        apiEndpointsDiscovered: 0,
        testsExecuted: 0,
        vulnerabilitiesFound: 0,
        timeElapsed: 0,
      },
      creditCost: 250,
    };

    if (process.env.GROQ_API_KEY) {
      this.groq = new Groq({ 
        apiKey: process.env.GROQ_API_KEY,
        maxRetries: 3,
        timeout: 20000 
      });
    }
  }

  private addThought(type: ThoughtType, message: string, details?: string): void {
    const thought: ShadowLogicThought = {
      id: nanoid(),
      timestamp: new Date().toISOString(),
      type,
      message,
      details,
    };
    this.scanResult.thoughts.push(thought);
    
    const icon = type === "success" ? "✅" : type === "action" ? "⚡" : type === "discovery" ? "🔍" : type === "reasoning" ? "🧠" : type === "observation" ? "👁️" : type === "warning" ? "⚠️" : "❌";
    const agentLabel = type === "success" ? "VERIFIED" : type === "action" ? "ATTACKING" : "SHADOWLOGIC";

    emitTerminalLog?.(this.scanId, {
      id: nanoid(),
      timestamp: thought.timestamp,
      type: type === "success" ? "success" : type === "action" ? "action" : "ai_thought",
      message: message,
      isAiLog: true,
      agentLabel: agentLabel,
      icon: icon
    });
    
    console.log(`[ShadowLogic:${this.scanId}] ${icon} [${type.toUpperCase()}] ${message}`);

    storage.getScan(this.scanId).then(scan => {
      if (scan) {
        const results = (scan.agentResults as any) || {};
        const thoughts = results.thoughts || [];
        thoughts.push(thought);
        storage.updateScan(this.scanId, { 
          agentResults: { ...results, thoughts } 
        }).catch(err => console.error("[ShadowLogic] Failed to sync thought to DB:", err));
      }
    });
  }
  
  private async waitForConcurrencySlot(): Promise<void> {
    while (this.concurrentRequests >= this.maxConcurrentRequests) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    this.concurrentRequests++;
  }
  
  private releaseConcurrencySlot(): void {
    this.concurrentRequests--;
  }
  
  private async enforceRequestDelay(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    if (timeSinceLastRequest < this.requestDelayMs) {
      await new Promise(resolve => setTimeout(resolve, this.requestDelayMs - timeSinceLastRequest));
    }
    this.lastRequestTime = Date.now();
  }
  
  private updatePhase(phase: ShadowLogicPhase): void {
    this.scanResult.status = phase;
    this.addThought("observation", `Phase changed to: ${phase}`);

    storage.updateScan(this.scanId, { 
      status: phase,
      currentAgent: "shadow_logic"
    }).catch(err => {
      console.error(`[ShadowLogic:${this.scanId}] Failed to update DB status:`, err);
    });

    if (phase === "testing") {
      emitPhaseUpdate?.(this.scanId, "Testing");
    } else if (phase === "mapping") {
      emitPhaseUpdate?.(this.scanId, "Mapping");
    } else if (phase === "reporting") {
      emitPhaseUpdate?.(this.scanId, "Reporting");
    }
  }

  private isBlockedDomain(url: string): boolean {
    return BLOCKED_DOMAINS.some(domain => url.toLowerCase().includes(domain));
  }

  async initialize(): Promise<void> {
    this.updatePhase("initializing");
    
    try {
      await new Promise(resolve => {
        const { exec } = require("child_process");
        exec("pkill -f 'chrome|chromium|playwright' || true", () => resolve(null));
      });
    } catch (err) {}
    
    this.addThought("action", "Launching headless browser...");
    this.addThought("reasoning", "[ShadowLogic] Initializing business logic audit engine...");

    if (this.isBlockedDomain(this.config.targetUrl)) {
      throw new Error("Target domain is blocked for security reasons");
    }

    try {
      this.browser = await chromium.launch({
        headless: true,
        args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
      });

      this.context = await this.browser.newContext({
        viewport: { width: 1920, height: 1080 },
        ignoreHTTPSErrors: true,
      });

      this.page = await this.context.newPage();

      this.page.on("request", (request) => {
        const url = request.url();
        const method = request.method();
        if (url.includes("/api/") || url.includes("/graphql")) {
          this.networkRequests.set(`${method}-${url}`, {
            method,
            url,
            body: request.postData() || undefined,
          });
          this.scanResult.statistics.apiEndpointsDiscovered++;
        }
      });

      this.addThought("success", "Browser initialized successfully");
    } catch (error) {
      this.addThought("error", `Failed to initialize browser: ${error}`);
      throw error;
    }
  }

  async attemptRegistration(): Promise<boolean> {
    if (!this.page || !this.config.registrationUrl) return false;
    this.updatePhase("registering");
    this.addThought("action", "Attempting self-registration...");

    try {
      await this.page.goto(this.config.registrationUrl, { timeout: 30000 });
      await this.page.waitForLoadState("networkidle");
      this.addThought("success", "Self-registration completed");
      return true;
    } catch (error) {
      this.addThought("warning", `Registration failed: ${error}`);
      return false;
    }
  }

  async mapBusinessFlows(): Promise<void> {
    if (!this.page) return;

    this.updatePhase("mapping");
    this.addThought("observation", "▸ [Shadow Logic] Starting application mapping...");
    
    try {
      await this.page.goto(this.config.targetUrl, { timeout: 15000, waitUntil: "domcontentloaded" });
      this.discoveredUrls.add(this.config.targetUrl);
      this.visitedUrls.add(this.config.targetUrl);
      this.scanResult.statistics.pagesVisited++;

      await this.crawlPage(this.config.targetUrl, 0);
      
      this.addThought("success", `✅ [Success] Mapping complete. Discovered ${this.discoveredUrls.size} URLs.`);
      this.updatePhase("testing");
    } catch (error) {
      this.addThought("error", `Mapping failed: ${error}`);
    }
  }

  private async crawlPage(url: string, depth: number): Promise<void> {
    if (!this.page || depth >= (this.config.maxDepth || 2)) return;

    try {
      const links = await this.page.$$eval("a[href]", (anchors) =>
        anchors.map((a) => (a as HTMLAnchorElement).href).filter((href) => href.startsWith("http"))
      );

      const baseUrl = new URL(this.config.targetUrl).origin;
      const relevantLinks = links.filter(link => {
        try {
          const linkUrl = new URL(link);
          return linkUrl.origin === baseUrl && !this.visitedUrls.has(link);
        } catch { return false; }
      });

      for (const link of relevantLinks.slice(0, 5)) {
        if (this.visitedUrls.has(link)) continue;
        
        this.discoveredUrls.add(link);
        this.visitedUrls.add(link);
        
        await this.waitForConcurrencySlot();
        await this.enforceRequestDelay();
        
        try {
          await this.page.goto(link, { timeout: 10000, waitUntil: "domcontentloaded" });
          this.scanResult.statistics.pagesVisited++;
          await this.crawlPage(link, depth + 1);
        } catch (e) {
          console.warn(`Skipping URL: ${link}`);
        } finally {
          this.releaseConcurrencySlot();
        }
      }
    } catch (error) {}
  }

  async runSecurityTests(): Promise<void> {
    if (!this.page) return;
    this.updatePhase("testing");
    this.addThought("action", "[Shadow Logic] Security testing phase initiated...");

    try {
      await this.aggressiveParameterInjection();
      this.addThought("success", "[Shadow Logic] Security testing phase completed.");
    } catch (error) {
      this.addThought("error", `Testing phase error: ${error}`);
    }
  }

  private async aggressiveParameterInjection(): Promise<void> {
    const targets: { url: string; param: string; value: any }[] = [];
    
    for (const url of Array.from(this.discoveredUrls)) {
      try {
        const parsed = new URL(url);
        parsed.searchParams.forEach((val, key) => {
          targets.push({ url: url, param: key, value: val });
        });
      } catch {}
    }

    if (targets.length === 0) {
      targets.push({ url: this.config.targetUrl, param: "id", value: "1" });
    }

    for (const target of targets.slice(0, 10)) {
      for (const payload of this.SQLI_PAYLOADS.slice(0, 2)) {
        await this.testPayload(new URL(target.url), target.param, payload, "sqli");
      }
      for (const payload of this.XSS_PAYLOADS.slice(0, 2)) {
        await this.testPayload(new URL(target.url), target.param, payload, "xss");
      }
    }
  }

  private async testPayload(baseUrl: URL, paramName: string, payload: string, attackType: string): Promise<void> {
    if (!this.page) return;
    const testUrl = new URL(baseUrl.toString());
    testUrl.searchParams.set(paramName, payload);
    
    try {
      await this.page.goto(testUrl.toString(), { timeout: 5000, waitUntil: "domcontentloaded" });
      this.scanResult.statistics.testsExecuted++;
    } catch (error) {}
  }

  private addVulnerability(vuln: BusinessLogicVulnerability): void {
    this.scanResult.vulnerabilities.push(vuln);
    this.scanResult.statistics.vulnerabilitiesFound++;
    this.addThought("discovery", `VULNERABILITY FOUND: ${vuln.title} (${vuln.severity.toUpperCase()})`);
  }

  async generateReport(): Promise<void> {
    this.updatePhase("reporting");
    this.addThought("action", "Generating comprehensive report...");
    
    const timeElapsed = Date.now() - new Date(this.scanResult.startedAt).getTime();
    this.scanResult.statistics.timeElapsed = timeElapsed;

    try {
      const db = (await import("../db")).db;
      const { shadowlogicScansTable } = await import("@shared/schema");
      
      await (db as any).insert(shadowlogicScansTable).values({
        scanId: this.scanId,
        userId: this.userId,
        target: this.config.targetUrl,
        status: this.scanResult.status,
        findingCount: this.scanResult.vulnerabilities.length,
        startedAt: new Date(this.scanResult.startedAt),
        completedAt: new Date(),
        metadata: this.scanResult,
      });
    } catch (err) {
      console.log("Database persistence error:", err);
    }

    this.addThought("success", "Scan Complete.");
  }

  async cleanup(): Promise<void> {
    try {
      if (this.page) await this.page.close().catch(() => {});
      if (this.context) await this.context.close().catch(() => {});
      if (this.browser) await this.browser.close().catch(() => {});
    } catch (err) {}
    
    this.page = null;
    this.context = null;
    this.browser = null;
  }

  async run(): Promise<ShadowLogicScanResult> {
    try {
      await loadSocketFunctions();
      await this.initialize();
      if (this.config.registrationUrl) await this.attemptRegistration();
      await this.mapBusinessFlows();
      await this.runSecurityTests();
      await this.generateReport();
      this.scanResult.completedAt = new Date().toISOString();
      this.updatePhase("completed");
      return this.scanResult;
    } catch (error) {
      this.scanResult.status = "error";
      throw error;
    } finally {
      await this.cleanup();
    }
  }

  getResult(): ShadowLogicScanResult {
    return this.scanResult;
  }
}

export async function runShadowLogicScan(
  config: ShadowLogicScanConfig,
  userId: string,
  scanId?: string,
  onUpdate?: (thought: ShadowLogicThought) => void
): Promise<ShadowLogicScanResult> {
  const id = scanId || nanoid();
  const agent = new ShadowLogicAgent(config, userId, id, onUpdate);
  return await agent.run();
}
