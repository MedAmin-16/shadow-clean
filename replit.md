# ShadowTwin

## Overview

ShadowTwin is an AI-powered Cybersecurity Digital Twin SaaS platform designed to create digital replicas of company assets (web applications, APIs, cloud infrastructure, network services). It autonomously runs AI-driven security simulations to proactively discover vulnerabilities. The platform employs a multi-agent scanning pipeline for reconnaissance, vulnerability scanning, exploitation testing, and report generation, all managed through a comprehensive dashboard. Its business vision is to provide cutting-edge, proactive cybersecurity, significantly reducing the window of vulnerability for organizations.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
- **Frontend**: React with TypeScript (Vite).
- **Styling**: Tailwind CSS with shadcn/ui components based on Radix UI, supporting light/dark modes.
- **Design System**: Linear/Vercel aesthetic, using Inter font for UI and JetBrains Mono for code.
- **Terminal**: LiveTerminal component with cinematic effects for real-time updates.

### Technical Implementations
- **Backend**: Node.js with Express and TypeScript.
- **API**: RESTful, secured with API key authentication and rate limiting.
- **Real-time**: Socket.io for scan notifications and live terminal output.
- **Job Queue**: BullMQ with Redis for asynchronous job processing.
- **Reporting**: PDFKit for generating detailed compliance reports, mapping findings to OWASP Top 10 (2021).
- **Notification System**: Supports Telegram, Discord, and Slack webhooks for critical alerts.
- **Data Layer**: PostgreSQL database with Drizzle ORM and Zod validation, deployed on Neon.
- **Monorepo Structure**: Shared types between frontend and backend for full type safety.
- **Security Features**: Admin panel isolation, brute-force protection, target blacklisting (e.g., .gov, .mil, .edu), bcrypt password hashing, pipeline timeouts, and strict user attribution.
- **AI Integration**: Groq SDK for ultra-fast AI analysis (llama-3.3-70b-versatile) and Google Generative AI as a fallback.

### Feature Specifications
The core system follows a 7-phase professional penetration testing methodology with recursive swarm logic:
1.  **Reconnaissance**: Discover subdomains and live assets using tools like Assetfinder and HTTPx.
2.  **Attack Surface Mapping**: Crawl URLs, identify tech stack, and discover parameters using Katana, GAU, WhatWeb, Arjun, and ParamSpider.
3.  **SQL Injection Testing**: Automated SQLMap scans on URLs with query parameters.
4.  **Command Injection Testing**: Automated Commix scans on URLs with command-like parameters.
5.  **Vulnerability Analysis**: Scan for vulnerabilities, leaked secrets, and sensitive files using Nuclei, FFuf, and TruffleHog.
6.  **Targeted Exploitation**: Comprehensive XSS testing with Dalfox.
7.  **Reporting & Compliance**: Map findings to OWASP Top 10 and generate executive and technical reports.

The system implements recursive scanning across the entire infrastructure, where phases 2-4 loop through every discovered subdomain in parallel batches, aggregating all findings into a unified report.

### System Design Choices
- **14-Agent Ultimate Arsenal**: All advanced scanning tools are integrated and active.
- **Unified Plan Tiers**: PRO and ELITE tiers have been merged into a single ultimate PRO version.
- **Zero False Positives**: Focus on high-confidence vulnerability validation (85%+).

## External Dependencies

### Scanning Tools
-   **Vulnerability Scanners**: Nuclei, Dalfox, Commix, SQLMap.
-   **Reconnaissance**: Katana, HTTPx, Subfinder, FFuf, GAU, Assetfinder, HTTPProbe, WhatWeb, Waybackurls, Arjun, ParamSpider, Kiterunner.
-   **Secret Detection**: TruffleHog.

### Database
-   **PostgreSQL**: Primary database.
-   **Drizzle Kit**: For database migrations.

### AI/LLM
-   **Groq SDK**: For AI analysis.
-   **Google Generative AI**: For AI analysis fallback.

### UI Framework
-   **Radix UI**: Headless components.
-   **shadcn/ui**: Pre-styled components.
-   **Lucide React**: Icon library.

### Build & Development
-   **Vite**: Frontend build.
-   **esbuild**: Server-side bundling.

### Data Fetching
-   **TanStack Query**: Async state management.

### Security & Automation
-   **Playwright**: Browser automation.
-   **bcrypt**: Password hashing.
-   **passport**: Authentication framework.

### Fonts
-   **Inter**: UI font.
-   **JetBrains Mono**: Code font.