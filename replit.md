# ShadowTwin

## Overview

ShadowTwin is an AI-powered Cybersecurity Digital Twin SaaS platform. It creates complete digital replicas of company assets (web applications, APIs, cloud infrastructure, network services) and runs autonomous AI-driven security simulations to discover vulnerabilities before attackers do.

The platform features a multi-agent scanning pipeline that performs reconnaissance, vulnerability scanning, exploitation testing, and report generation. The frontend provides a dashboard for managing projects, monitoring scans, viewing vulnerabilities, and generating compliance reports.

## Recent Changes (December 24, 2025 - PROFESSIONAL PENTESTING METHODOLOGY IMPLEMENTED)

### ✨ PRO PACK MERGED WITH ELITE - NOW THE ULTIMATE VERSION

**COMPLETED: Complete tool arsenal integration into PRO Pack**

#### All 14 Advanced Agents Now in PRO:
1. **AGENT-01**: Network Reconnaissance (Nmap)
2. **AGENT-02**: Subdomain Enumeration (Assetfinder)
3. **AGENT-03**: Web Crawler & Spider (Katana)
4. **AGENT-04**: Vulnerability Scanner (Nuclei)
5. **AGENT-05**: XSS Exploitation (Dalfox)
6. **AGENT-06**: Command Injection (Commix)
7. **AGENT-07**: Parameter Discovery (Arjun)
8. **AGENT-08**: Database Exploitation (SQLMap Level 3)
9. **AGENT-09**: URL History Mining (Waybackurls)
10. **AGENT-10**: HTTP Probing (HTTPProbe)
11. **AGENT-11**: Technology Detection (WhatWeb)
12. **AGENT-12**: Directory Fuzzing (FFuf)
13. **AGENT-13**: Hidden Parameters (ParamSpider)
14. **AGENT-14**: Archive History (GAU)

#### Additional Infrastructure:
- **Secret Scanning**: TruffleHog for credential detection + JS file analysis
- **Notification System**: Telegram, Discord, Slack webhook alerts for critical vulnerabilities
- **Cleanup Automation**: RAM management and stalled process cleanup script
- **OWASP Mapping**: All vulnerabilities mapped to OWASP Top 10 (2021) categories
- **Tool Installation**: Go tools installation script for easy deployment

**Key Features**:
- ✓ ALL 14 agents active for PRO Pack scans
- ✓ Dalfox (XSS), Commix (RCE), TruffleHog (Secrets) integrated
- ✓ Real binaries installed (Nuclei, Katana, HTTPx, Subfinder, FFuf, GAU)
- ✓ Notification service supports Discord, Telegram, Slack
- ✓ Automatic cleanup script kills stalled processes
- ✓ OWASP compliance categories on all findings
- ✓ NO difference between PRO and ELITE - merged into one ultimate tier

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React with TypeScript using Vite as the build tool
- **Routing**: Wouter for client-side routing (lightweight alternative to React Router)
- **State Management**: TanStack React Query for server state and caching
- **UI Components**: shadcn/ui component library built on Radix UI primitives
- **Styling**: Tailwind CSS with CSS custom properties for theming (light/dark mode support)
- **Design System**: Following Linear/Vercel aesthetic with Inter font for UI and JetBrains Mono for code
- **Terminal Component**: LiveTerminal with cinematic effects (typewriter, blinking cursor)

### Backend Architecture
- **Runtime**: Node.js with Express and TypeScript
- **API Pattern**: RESTful API endpoints under `/api/*` prefix
- **Build System**: esbuild for server bundling, Vite for client bundling
- **Development**: tsx for TypeScript execution in development
- **Rate Limiting**: express-rate-limit on all scan endpoints (100 req/15min)
- **Authentication**: API key-based auth via x-api-key header
- **Job Queue**: BullMQ with Redis (optional - falls back to synchronous processing)
- **Real-time**: Socket.io for scan completion notifications and live terminal updates
- **Email**: Nodemailer for scan completion emails (requires SMTP config)
- **Reports**: PDFKit for generating downloadable PDF reports
- **Notifications**: Telegram, Discord, Slack webhooks for critical vulnerabilities

### Multi-Agent Scanning Pipeline - 5-PHASE PROFESSIONAL PENTESTING METHODOLOGY

The core security scanning system now follows a **STRICT, PROFESSIONAL PENTESTING METHODOLOGY** with 5 sequential phases:

**PHASE 1: RECONNAISSANCE (Broad Search)**
- Tools: Assetfinder, Subfinder, HTTProbe, TheHarvester
- Purpose: Discover all subdomains and identify live (active) assets
- Agent: Recon Agent

**PHASE 2: ATTACK SURFACE MAPPING (Narrowing Down)**
- Tools: Katana, GAU, WhatWeb, Arjun, ParamSpider
- Purpose: Crawl all URLs, identify tech stack, discover hidden parameters
- Part of: Scanner Agent

**PHASE 3: VULNERABILITY ANALYSIS (Scanning)**
- Tools: Nuclei, FFuf, TruffleHog
- Purpose: Scan for vulnerabilities, leaked secrets, sensitive files (.env, .git, config)
- Part of: Scanner Agent

**PHASE 4: TARGETED EXPLOITATION (Deep Dive)**
- Tools: SQLMap (Level 3/Risk 2), Dalfox (XSS), Commix (Command Injection)
- Purpose: Trigger conditional exploitation based on discovered vulnerabilities
- Agent: Exploiter Agent

**PHASE 5: REPORTING & COMPLIANCE**
- Purpose: Map all findings to OWASP Top 10, generate Executive Summary and Technical Remediation
- Agent: Reporter Agent

**Supporting Agents (ELITE only)**:
5. **RL Exploiter Agent**: Reinforcement learning-based exploitation with Q-learning
6. **Prophet Agent**: Causal inference engine with root cause analysis
7. **Autonomous Defense Agent**: WAF/Firewall hotfix integration
8. **ShadowLogic™ Agent**: Autonomous AI-powered business logic vulnerability auditor using Groq

Each phase executes sequentially with strict tool specifications. All agents run asynchronously and update scan progress in real-time with cinematic terminal effects.

### RECURSIVE SWARM LOGIC (CRITICAL UPDATE)

**The system now implements TRUE RECURSIVE SCANNING ACROSS THE ENTIRE INFRASTRUCTURE:**

1. **Phase 1: RECONNAISSANCE** discovers all live subdomains via HTTProbe
2. **Phases 2-4 RECURSIVELY LOOP** through EVERY subdomain discovered:
   - Phase 2-3 (Attack Surface Mapping + Vulnerability Analysis) runs on EACH subdomain
   - Phase 4 (Targeted Exploitation) runs on EACH subdomain
3. **CONCURRENCY CONTROL**: Scans 3-5 subdomains at a time to prevent RAM exhaustion
4. **UNIFIED AGGREGATION**: All findings from all subdomains are collected and organized by subdomain
5. **UNIFIED REPORT**: Final report shows all vulnerabilities across the entire infrastructure, organized by subdomain

**Example Flow**:
- Phase 1: Discovers `main.com`, `api.main.com`, `admin.main.com`, `cdn.main.com` (4 subdomains)
- Phases 2-4 Loop Iteration 1: Scans `main.com`, `api.main.com`, `admin.main.com` (batch of 3)
- Phases 2-4 Loop Iteration 2: Scans `cdn.main.com` (remaining batch)
- Final Report: Single PDF/JSON with findings organized by subdomain + overall risk assessment

This is what makes it a true **Agent Swarm** - the entire infrastructure is attacked in parallel batches with full coordination.

### Data Layer
- **ORM**: Drizzle ORM with PostgreSQL dialect
- **Schema**: Defined in `shared/schema.ts` with Zod validation
- **Database**: PostgreSQL (Neon-backed on Replit)
- **Storage Abstraction**: Interface-based storage pattern

### Project Structure
```
client/           # React frontend application
  src/
    components/   # Reusable UI components (including LiveTerminal with cinematic effects)
    pages/        # Route page components
    hooks/        # Custom React hooks
    lib/          # Utilities and query client
server/           # Express backend
  agents/         # Security scanning agent implementations (14-Agent Swarm)
  src/
    controllers/  # Request handlers for API endpoints
    middlewares/  # Rate limiting, API key auth
    services/     # Email, PDF report generation, threat intel, notifications
    sockets/      # Socket.io real-time notifications
    utils/        # Logger, target blacklist
shared/           # Shared types and database schema
reports/          # Generated PDF reports (auto-created)
bin/              # Security tools and scripts
```

### Environment Variables
```
# Required
DATABASE_URL      # PostgreSQL connection string

# Required - AI/LLM Features
GROQ_API_KEY      # Groq API key for ultra-fast AI analysis (llama-3.3-70b-versatile)

# Required - Admin Panel Access
ADMIN_EMAIL       # Email address for admin authentication
ADMIN_PASSWORD_HASH  # Bcrypt hash (12 rounds) of admin password

# Optional - Job Queue (enables background processing)
REDIS_URL         # Redis connection URL for BullMQ
REDIS_HOST        # Redis host
REDIS_PORT        # Redis port (default: 6379)

# Optional - Email Notifications
SMTP_HOST         # SMTP server hostname
SMTP_PORT         # SMTP port (default: 587)
SMTP_USER         # SMTP username
SMTP_PASS         # SMTP password
SMTP_FROM         # From email address

# Optional - Webhook Notifications
TELEGRAM_BOT_TOKEN    # Telegram bot token for alerts
TELEGRAM_CHAT_ID      # Telegram chat ID for receiving alerts
DISCORD_WEBHOOK_URL   # Discord webhook for critical vulnerability alerts
SLACK_WEBHOOK_URL     # Slack webhook for alerts
```

### Security Features
- **Admin Panel Isolation**: Separate `/admin` interface with isolated authentication
- **Admin Brute Force Protection**: 5 max attempts before 15-minute lockout
- **Target Blacklist**: Government (.gov, .mil), financial, and educational (.edu) domains blocked
- **Password Security**: All passwords hashed using bcrypt with 12 salt rounds
- **Pipeline Timeouts**: 30-minute global timeout, 10-minute per-agent timeout
- **Strict User Attribution**: All scans require authenticated users
- **Rate Limiting**: 100 req/15min on all scan endpoints
- **Zero False Positives**: Strict 85%+ confidence scoring for vulnerability validation
- **OWASP Top 10 Mapping**: All findings categorized against OWASP Top 10 (2021)

### Key Design Decisions
- **Monorepo structure**: Single repository with shared types between frontend and backend
- **Type safety**: Full TypeScript coverage with shared schema definitions
- **Component architecture**: Presentational components with cinematic UI effects
- **14-Agent Ultimate Arsenal**: All advanced scanning tools available in both PRO and ELITE
- **Groq Integration**: Ultra-fast AI analysis with llama-3.3-70b-versatile model
- **Path aliases**: `@/` for client source, `@shared/` for shared code
- **Unified Plan Tiers**: PRO and ELITE merged - PRO is now the ultimate version

## Build & Deployment Status

✅ **Production Build Successful**
- Frontend: 2.51 KB HTML, 85.71 KB CSS (gzip), 531.89 KB JS (gzip)
- Server: 1.7 MB bundled
- All TypeScript compilation successful
- Database schema deployed
- App running on port 5000
- All 14 security tools operational

## External Dependencies

### Scanning Tools (All 14 agents)
- **Nuclei**: CVE scanning with templates
- **Katana**: Web crawler and spider
- **HTTPx**: HTTP client and port scanner
- **Subfinder**: Subdomain enumeration
- **FFuf**: Web fuzzer
- **GAU**: Get All URLs from archives
- **Dalfox**: XSS vulnerability scanner
- **Commix**: Command injection tester
- **SQLMap**: SQL injection testing (Level 3)
- **TruffleHog**: Secret detection
- **Assetfinder**: Asset discovery
- **HTTPProbe**: HTTP probing
- **WhatWeb**: Technology identification
- **Waybackurls**: URL archive mining
- **Arjun**: Parameter discovery
- **ParamSpider**: Parameter extraction
- **Kiterunner**: API endpoint detection

### Database
- **PostgreSQL**: Primary database (Neon-backed)
- **Drizzle Kit**: Database migrations and schema management

### AI/LLM
- **Groq SDK**: Ultra-fast AI analysis using llama-3.3-70b-versatile
- **Google Generative AI**: Fallback for ShadowLogic when needed

### UI Framework
- **Radix UI**: Headless component primitives
- **shadcn/ui**: Pre-styled components
- **Lucide React**: Icon library

### Build & Development
- **Vite**: Frontend development server and build tool
- **esbuild**: Server-side bundling
- **Replit plugins**: Development banner and error overlay

### Data Fetching
- **TanStack Query**: Async state management and caching

### Security & Scanning
- **Playwright**: Browser automation for business logic testing
- **bcrypt**: Password hashing
- **passport**: Authentication framework

### Fonts (Google Fonts)
- Inter: Primary UI font
- JetBrains Mono: Monospace for code/technical content
