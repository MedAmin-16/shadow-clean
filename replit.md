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

## Elite Shadow Logic AI Terminal (Dec 28, 2025)

### Real-Time AI Thought Process Interface + Pro Hacker Intelligence
- **Status**: ✅ Complete
- **Plan Access**: ELITE only
- **Files Modified**:
  - `client/src/components/ShadowLogicTerminal.tsx` - Elite UI with gold/amber styling
  - `server/agents/shadowLogic.ts` - Pro Hacker Intelligence capabilities

### Elite Terminal Features:
1. **Elite Visual Style**:
   - Gold/Amber color scheme on black background
   - Crown icon branding
   - Professional terminal aesthetic
   - Animated pulsing indicators

2. **Real-Time Metadata Display**:
   - Current Business Workflow being analyzed
   - Active Hypothesis testing
   - Payload generation counter

3. **AI Thought Process Streaming**:
   - Live observation of security scanning
   - Real-time logic analysis
   - Payload testing in action
   - Success/Error indicators with timestamps

4. **Sophisticated Animations**:
   - Pulsing thought indicators
   - Animating CPU icon during analysis
   - Hover effects with glowing borders
   - Smooth transitions between states

5. **WebSocket Integration**:
   - Connects to ShadowLogicAgent for real-time streaming
   - Auto-scrolls to latest AI thoughts
   - Manual scroll override for detailed review
   - Event limiting (last 500 events) for performance

### Pro Hacker Intelligence Capabilities (RUTHLESS):

#### 1. **State Machine Auditing**
   - Maps entire business workflow (Cart → Shipping → Payment)
   - Tests step-skipping by attempting direct access to later stages
   - Detects workflow bypass vulnerabilities
   - Terminal Message: `[Shadow Logic] Hypothesis: Step 2 (Payment) can be bypassed by directly calling Step 3 (Confirmation)... TESTING.`

#### 2. **Advanced Parameter Tampering**
   - Tests negative values in quantity/price fields
   - Tests zero quantities for inventory bypass
   - Null-byte injection in JSON payloads
   - Tests for type coercion bypass
   - Terminal Message: `[Shadow Logic] Injecting null-byte in 'Subscription_Tier' parameter to bypass validation... OBSERVING.`

#### 3. **Context-Aware IDOR (Insecure Direct Object Reference)**
   - Automatically identifies IDs in URLs (uuid, numeric, tokens)
   - Swaps IDs to access other users' data
   - Tests both sequential numeric IDs and UUIDs
   - Terminal Message: `[Shadow Logic] IDOR Hypothesis: ID 'user_42' can be swapped to 'user_43' to access other users' data... TESTING.`

#### 4. **Race Condition Testing**
   - Identifies sensitive endpoints (redeem, withdraw, checkout)
   - Simulates concurrent requests for double-spending attacks
   - Tests for refund loop vulnerabilities
   - Terminal Message: `[Shadow Logic] Race Condition Hypothesis: Can we redeem the same code twice with concurrent requests? ... TESTING.`

#### 5. **Privilege Escalation Logic**
   - Hunts for hidden privilege parameters (is_admin, role, permissions, level)
   - Tests parameter injection in POST/PUT requests
   - Attempts 0xFFFFFFFF privilege bitmask bypass
   - Terminal Message: `[Shadow Logic] Injecting is_admin=true into every POST request... TESTING.`

### Terminal Display:
- Shows all "Hacker Thoughts" in gold/amber terminal format
- Real-time hypothesis generation and testing
- Payload injection tracking
- Business logic vulnerability identification as they occur
- RUTHLESS: If there's a logical flaw, Shadow Logic WILL find it

### Integration:
- Displayed on Shadow Logic scanning page (active tab)
- Shows in dashboard for ELITE users (when scan complete)
- Directly linked to ShadowLogicAgent logs via WebSocket
- Real-time updates during scan execution
- Displays hacker-mindset thoughts with hypothesis testing format

## Hacker Evidence Module - PoC Generation (Dec 28, 2025)

### Forensic Proof for Every Vulnerability
- **Status**: ✅ Complete
- **Plan Access**: ELITE only
- **Files Modified**:
  - `shared/shadowLogic.ts` - Added HackerProof interface
  - `server/src/services/executiveReportService.ts` - Forensic evidence section in PDF
  - `client/src/components/ShadowLogicTerminal.tsx` - Real-time evidence display
  - `server/agents/shadowLogic.ts` - Detailed PoC generation logic

### Evidence Module Features:

#### 1. **Detailed 3-Step PoC Generation**
   - **Step 1**: Original "Normal" request (method, URL, headers, body)
   - **Step 2**: "Malicious" manipulation (what was changed, original vs. injected value)
   - **Step 3**: "Unexpected" response (status code, headers, body, proof indicator)

#### 2. **Technical Artifacts**
   - Complete HTTP request/response headers
   - Full request body (JSON, form-encoded, etc.)
   - Response body with exact server output
   - Status codes and transaction IDs

#### 3. **"Why It Worked" Summary**
   - AI explanation of broken business rule
   - Root cause analysis in plain English
   - Example: "The system failed to validate the price on the server-side, trusting the client-submitted value instead of retrieving the actual item price from the inventory database."

#### 4. **Real-Time Terminal Display**
   - [VERIFIED EXPLOITS] section with lock icon
   - Expandable/collapsible evidence details
   - Step 2 injection shown
   - Step 3 result displayed
   - "Why It Worked" explanation visible
   - 🔐 ShadowTwin Verified Exploit watermark on each proof

#### 5. **Executive PDF Integration**
   - "FORENSIC PROOF - HACKER EVIDENCE" section
   - Detailed PoC for top 2 critical exploits
   - 3-step breakdown for each vulnerability
   - "🔐 ShadowTwin Verified Exploit - Forensically Proven" watermark
   - No developer can argue with HTTP artifacts

#### 6. **Watermark Branding**
   - Every exploit marked: "🔐 ShadowTwin Verified Exploit"
   - Forensic authenticity indicator
   - Professional proof-of-concept presentation

### Impact:
- Turns findings into **forensic proof**
- Eliminates developer objections with HTTP evidence
- Makes vulnerabilities **undeniable**
- ELITE clients see exact exploitation method
- PDF reports include complete technical proof

## Current Build Status
✅ Build passes successfully
✅ All features compiled and deployed
✅ Executive Report feature complete
✅ Elite Shadow Logic AI Terminal complete
✅ Pro Hacker Intelligence capabilities implemented
✅ Hacker Evidence Module - PoC Generation COMPLETE
✅ State Machine Auditing - ACTIVE
✅ Advanced Parameter Tampering - ACTIVE
✅ Context-Aware IDOR Detection - ACTIVE
✅ Race Condition Testing - ACTIVE
✅ Privilege Escalation Hunting - ACTIVE
✅ Real-Time Evidence Display with Watermark - LIVE
✅ Executive PDF with Forensic Proof - ACTIVE
✅ Ready for production - ELITE users get UNDENIABLE proof of every flaw
