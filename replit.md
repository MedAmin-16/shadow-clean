# ShadowTwin - Enterprise Vulnerability Assessment Platform

## Project Overview
ShadowTwin is an advanced security platform designed for enterprise clients (CTOs/CEOs) to assess application security through multiple scanning agents, AI-powered analysis, and business impact reporting.

## Recent Updates (Dec 28, 2025)

### AI Attack Chainer - Enterprise Risk Management Feature
- **Status**: ✅ Complete
- **Scope**: Correlation engine + executive dashboard integration
- **Messaging Shift**: Migrated from "bounty estimates" to "Business Impact Risk" for C-suite audiences

#### Files Created:
1. `server/src/services/attackChainer.ts` - Core correlation engine
2. `server/src/controllers/attackChainerController.ts` - API endpoints
3. `client/src/components/AttackChainsCard.tsx` - Executive dashboard component

#### Key Features:
- **8 Pre-defined Attack Patterns**: Intelligent matching for vulnerability chains
- **Business Impact Ratings**:
  - CRITICAL: Potential Data Breach / Legal Liability ($500K - $50M)
  - HIGH: Service Disruption / Brand Damage ($100K - $3M)
  - MEDIUM: Information Leak / Compliance Risk ($50K - $500K)
- **Regulatory Compliance Tags**: GDPR, CCPA, PCI-DSS, HIPAA, SOC2, ISO27001 violation indicators
- **Financial Loss Estimates**: Based on industry recovery costs and breach notification requirements
- **Executive Summaries**: Business language focusing on customer trust, operational downtime, financial impact
- **Exploitation Paths**: Step-by-step attack sequences for technical teams
- **Compliance Risk Indicators**: Automatic detection of regulatory violations

#### API Routes:
- `GET /api/attack-chains/:scanId` - Fetch vulnerability chains for completed scans
- `POST /api/attack-chains/correlate` - Manual correlation trigger

#### Plan-Based Access:
- Available exclusively for PRO and ELITE users
- Gated by `visual_attack_path` feature

#### Dashboard Integration:
- Displays after scan completion
- Shows financial exposure and regulatory risks upfront
- Immediate action items for leadership
- Color-coded severity with business impact badges

## Architecture Overview

### Scanning Agents
- **Recon Agent**: Asset discovery and enumeration
- **Scanner Agent**: Vulnerability detection (Nuclei-based)
- **Exploiter Agent**: POC validation
- **RL Exploiter**: Reinforcement learning-based exploitation
- **Prophet Agent**: Threat prediction
- **Shadow Logic**: Business logic vulnerability auditing
- **Reporter Agent**: Report generation
- **Autonomous Defense**: Automated remediation suggestions

### Core Services
- **Credit System**: Token-based cost management
- **Threat Intelligence**: CVE and SHODAN integration
- **Database Sandbox**: Isolated analysis environment
- **Remediation Engine**: AI-powered fix suggestions
- **Compliance Reporting**: Framework-based reports (PCI-DSS, HIPAA, SOC2, GDPR)
- **Phishing Simulation**: Employee security awareness
- **Cloud Security (CSPM)**: AWS/GCP/Azure misconfiguration scanning
- **Attack Chainer**: Vulnerability correlation for business impact

### Database
- PostgreSQL with Drizzle ORM
- 20+ tables for scans, vulnerabilities, assets, compliance, monitoring

## User Tiers
- **STANDARD**: Basic scanning
- **PRO**: Advanced agents, daily monitoring, cloud security
- **ELITE**: All features, priority support, advanced AI

## Tech Stack
- **Frontend**: React + TypeScript + Tailwind CSS + Vite
- **Backend**: Express.js + Node.js + TypeScript
- **Database**: PostgreSQL
- **Real-time**: WebSocket for live scan streaming
- **LLM Integration**: OpenAI GPT-4o, Groq

## Executive Risk Report Feature (Dec 28, 2025)

### One-Click PDF Export for C-Suite
- **Status**: ✅ Complete
- **Plan Access**: ELITE only
- **Files Created**:
  - `server/src/services/executiveReportService.ts` - PDF generation
  - `server/src/controllers/executiveReportController.ts` - API endpoint
  - UI Integration in AttackChainsCard component

### PDF Report Contents:
1. **Executive Summary** - Business impact of vulnerability chains
2. **Financial Exposure** - Total estimated loss range ($XXX,XXX - $X,XXX,XXX)
3. **Regulatory Gaps** - Compliance violations (GDPR, CCPA, PCI-DSS, HIPAA, SOC2, ISO27001)
4. **Critical Risk Factors** - Top 3 chains with business-focused explanations
5. **Recommended Actions** - Board-level action items
6. **Professional Design** - One-page, confidential, Board-ready format

### API Endpoint:
- `GET /api/executive-report/:scanId` - Generate & download PDF (ELITE only)

### Features:
- ✅ Instant PDF generation (no external services)
- ✅ Beautiful professional formatting (PDFKit)
- ✅ Zero technical jargon (business language)
- ✅ One-click download from dashboard
- ✅ ELITE plan gating via requireMinPlan middleware
- ✅ Automatic financial loss calculation
- ✅ Compliance gap summary

## Current Build Status
✅ Build passes successfully
✅ All features compiled and deployed
✅ Executive Report feature complete
✅ Ready for production
