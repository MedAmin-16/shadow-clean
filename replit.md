# ShadowTwin

## Overview

ShadowTwin is an AI-powered Cybersecurity Digital Twin SaaS platform. It creates complete digital replicas of company assets (web applications, APIs, cloud infrastructure, network services) and runs autonomous AI-driven security simulations to discover vulnerabilities before attackers do.

The platform features a multi-agent scanning pipeline that performs reconnaissance, vulnerability scanning, exploitation testing, and report generation. The frontend provides a dashboard for managing projects, monitoring scans, viewing vulnerabilities, and generating compliance reports.

## Recent Changes (December 19, 2025 - PRODUCTION DATABASE REBUILD COMPLETE)

### ✅ FULL DATABASE OVERHAUL - 20 PRODUCTION-READY TABLES
**COMPLETED: Clean slate deployment with professional schema**

1. **Auth & Users (3 tables)**:
   - `users`: Core authentication with password_hash, email, plan management
   - `user_credits`: Credit balance tracking (auto-initialized to 1000 credits per user via trigger)
   - `user_integrations`: Third-party API integrations support

2. **Scanning Engine (3 tables)**:
   - `scans`: Main scan results with agent tracking and status
   - `scan_sandboxes`: Isolated sandbox environments for safe testing
   - `monitoring_schedules`: Continuous monitoring configurations

3. **ShadowLogic Core (3 tables)**:
   - `shadowlogic_scans`: Business logic vulnerability scanning
   - `shadowlogic_vulnerabilities`: Findings linked to scan_id and user_id with proper FK
   - `shadowlogic_discoveries`: Detailed discovery metadata

4. **Advanced Modules (4 tables)**:
   - `phishing_campaigns`: Phishing simulation engine
   - `cloud_scan_configs`: AWS/Azure/GCP scanning configurations
   - `threat_intel`: CVE and threat intelligence database
   - `compliance_reports`: ISO/GDPR compliance reporting

5. **Additional Infrastructure (7 tables)**:
   - `credit_transactions`: Full audit trail for credit system
   - `scan_reports`: Individual scan report storage
   - `vulnerabilities`: Centralized vulnerability database
   - `assets`: Asset inventory management
   - `remediation_tracking`: Fix tracking and verification
   - `audit_logs`: System-wide audit trail
   - `admin_sessions`: Admin authentication tracking

**Key Features**:
- ✓ All foreign keys correctly mapped with CASCADE delete
- ✓ Auto-initialization trigger: Every new user gets 1000 STANDARD credits
- ✓ Verified: Backend writes without "Column not found" errors
- ✓ 20 tables total with proper indexing for performance
- ✓ Timestamp tracking (created_at, updated_at) on all tables

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

### Multi-Agent Scanning Pipeline
The core security scanning system uses a 10-agent swarm architecture:

**Core Agents (Runs for all plans)**:
1. **Recon Agent**: Strategic Planning Engine with credit-based gating and tiered LLM access
2. **Scanner Agent**: 10-Agent Swarm with vulnerability identification, PoC and remediation code
3. **Exploiter Agent**: Attempts safe exploitation to validate vulnerabilities
4. **Reporter Agent**: Strategic Intelligence Engine with financial risk quantification

**ELITE Tier Agents** (Level 7+ - run after standard pipeline for ELITE users):
5. **RL Exploiter Agent**: Reinforcement learning-based exploitation with Q-learning
6. **Prophet Agent**: Causal inference engine with root cause analysis
7. **Autonomous Defense Agent**: WAF/Firewall hotfix integration
8. **ShadowLogic™ Agent**: Autonomous AI-powered business logic vulnerability auditor using Groq

Each agent runs asynchronously and updates scan progress in real-time with cinematic terminal effects.

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
  agents/         # Security scanning agent implementations (10-Agent Swarm)
  src/
    controllers/  # Request handlers for API endpoints
    middlewares/  # Rate limiting, API key auth
    services/     # Email, PDF report generation, threat intel
    sockets/      # Socket.io real-time notifications
    utils/        # Logger, target blacklist
shared/           # Shared types and database schema
reports/          # Generated PDF reports (auto-created)
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

### Key Design Decisions
- **Monorepo structure**: Single repository with shared types between frontend and backend
- **Type safety**: Full TypeScript coverage with shared schema definitions
- **Component architecture**: Presentational components with cinematic UI effects
- **10-Agent Swarm**: Parallel security testing across multiple specialized tools
- **Groq Integration**: Ultra-fast AI analysis with llama-3.3-70b-versatile model
- **Path aliases**: `@/` for client source, `@shared/` for shared code

## Build & Deployment Status

✅ **Production Build Successful**
- Frontend: 2.51 KB HTML, 85.71 KB CSS (gzip), 531.89 KB JS (gzip)
- Server: 1.7 MB bundled
- All TypeScript compilation successful
- Database schema deployed
- App running on port 5000

## External Dependencies

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
