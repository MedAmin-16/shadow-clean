import OpenAI from "openai";
import type { RemediationRequest, AIRemediationResult } from "@shared/advancedFeatures";

export class RemediationService {
  private openai?: OpenAI;

  constructor() {
    if (process.env.OPENAI_API_KEY) {
      this.openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    }
  }

  async generateRemediation(request: RemediationRequest): Promise<AIRemediationResult> {
    if (!this.openai) {
      return this.getMockRemediation(request);
    }

    try {
      const prompt = this.buildRemediationPrompt(request);
      
      const response = await this.openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "system",
            content: `You are a security expert providing actionable remediation guidance for vulnerabilities. 
            Provide specific, implementable fixes with code examples when relevant.
            Format your response as JSON with the following structure:
            {
              "suggestion": "Main remediation suggestion",
              "codeSnippet": "Code fix if applicable",
              "configFix": "Configuration changes if applicable",
              "estimatedEffort": "Time estimate (e.g., '2-4 hours')",
              "priority": 1-5 (1 = highest priority),
              "steps": ["Step 1", "Step 2", ...]
            }`,
          },
          { role: "user", content: prompt },
        ],
        response_format: { type: "json_object" },
        max_tokens: 1000,
      });

      const content = response.choices[0]?.message?.content;
      if (!content) {
        return this.getMockRemediation(request);
      }

      const parsed = JSON.parse(content);
      return {
        vulnerabilityId: request.vulnerabilityId,
        suggestion: parsed.suggestion || "Review and fix the vulnerability",
        codeSnippet: parsed.codeSnippet,
        configFix: parsed.configFix,
        estimatedEffort: parsed.estimatedEffort || "2-4 hours",
        priority: parsed.priority || 2,
        steps: parsed.steps || [],
      };
    } catch (error) {
      console.error("[Remediation] AI generation error:", error);
      return this.getMockRemediation(request);
    }
  }

  async generateBatchRemediation(requests: RemediationRequest[]): Promise<AIRemediationResult[]> {
    const results = await Promise.all(
      requests.map(req => this.generateRemediation(req))
    );
    return results.sort((a, b) => a.priority - b.priority);
  }

  private buildRemediationPrompt(request: RemediationRequest): string {
    let prompt = `Provide remediation guidance for the following vulnerability:

Title: ${request.vulnerabilityTitle}
Severity: ${request.severity}
Description: ${request.vulnerabilityDescription}`;

    if (request.technology) {
      prompt += `\nTechnology: ${request.technology}`;
    }

    if (request.affectedCode) {
      prompt += `\n\nAffected Code:\n${request.affectedCode}`;
    }

    return prompt;
  }

  private getMockRemediation(request: RemediationRequest): AIRemediationResult {
    const remediations: Record<string, Partial<AIRemediationResult>> = {
      "SQL Injection": {
        suggestion: "Use parameterized queries or prepared statements to prevent SQL injection attacks.",
        codeSnippet: `// Instead of string concatenation:
// const query = "SELECT * FROM users WHERE id = " + userId;

// Use parameterized queries:
const query = "SELECT * FROM users WHERE id = $1";
const result = await db.query(query, [userId]);`,
        configFix: "Enable SQL injection protection in your WAF configuration.",
        estimatedEffort: "2-4 hours",
        priority: 1,
        steps: [
          "Identify all SQL queries using string concatenation",
          "Replace with parameterized queries",
          "Implement input validation layer",
          "Enable prepared statement caching",
          "Test with SQL injection payloads",
        ],
      },
      "XSS": {
        suggestion: "Implement proper output encoding and Content Security Policy headers.",
        codeSnippet: `// Sanitize user input before rendering
import DOMPurify from 'dompurify';
const sanitized = DOMPurify.sanitize(userInput);

// Or use a templating engine with auto-escaping
res.render('template', { data: escapeHtml(userInput) });`,
        configFix: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`,
        estimatedEffort: "4-8 hours",
        priority: 2,
        steps: [
          "Implement CSP headers",
          "Add output encoding for all user-generated content",
          "Use a sanitization library for HTML content",
          "Enable HttpOnly and Secure flags on cookies",
        ],
      },
      default: {
        suggestion: `Address the ${request.vulnerabilityTitle} vulnerability by implementing security best practices.`,
        estimatedEffort: "4-8 hours",
        priority: 3,
        steps: [
          "Review the vulnerability details",
          "Identify affected code paths",
          "Implement the recommended fix",
          "Test the remediation",
          "Deploy to production",
        ],
      },
    };

    const key = Object.keys(remediations).find(k => 
      request.vulnerabilityTitle.toLowerCase().includes(k.toLowerCase())
    ) || "default";

    const baseRemediation = remediations[key];

    return {
      vulnerabilityId: request.vulnerabilityId,
      suggestion: baseRemediation.suggestion || "",
      codeSnippet: baseRemediation.codeSnippet,
      configFix: baseRemediation.configFix,
      estimatedEffort: baseRemediation.estimatedEffort || "2-4 hours",
      priority: baseRemediation.priority || 3,
      steps: baseRemediation.steps || [],
    };
  }
}

export const remediationService = new RemediationService();
