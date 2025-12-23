# ShadowTwin Design Guidelines

## Design Approach
**System-Based Approach** drawing from Linear's modern technical aesthetic and Vercel's dashboard patterns. The design emphasizes clarity, trust, and efficiency for security professionals while maintaining visual sophistication.

## Typography System

**Font Families:**
- Primary: Inter (Google Fonts) - entire application
- Monospace: JetBrains Mono (Google Fonts) - code snippets, API endpoints, scan outputs

**Hierarchy:**
- Hero Headline: text-6xl font-bold tracking-tight
- Page Titles: text-4xl font-semibold
- Section Headers: text-2xl font-semibold
- Card Titles: text-lg font-medium
- Body Text: text-base font-normal
- Captions/Labels: text-sm font-medium
- Code/Technical: text-sm font-mono

## Layout System

**Spacing Primitives:**
Use Tailwind units: 2, 4, 6, 8, 12, 16, 20, 24
- Component padding: p-6 or p-8
- Section spacing: space-y-8 or space-y-12
- Card gaps: gap-6
- Large section breaks: py-20 or py-24

**Grid System:**
- Dashboard: 12-column grid with sidebar (16rem fixed width)
- Landing page: max-w-7xl container with px-6
- Content sections: max-w-6xl for readability

## Component Library

### Landing Page Components

**Hero Section (100vh):**
- Full-height split layout with gradient background
- Left: Headline + tagline + dual CTA buttons ("Get Started" primary, "Early Access" secondary)
- Right: Animated dashboard preview mockup or abstract 3D twin visualization
- Include trust indicator: "Trusted by Fortune 500 Security Teams" badge
- Hero image: Abstract cybersecurity visualization or 3D digital twin concept

**Features Section:**
- 3-column grid (lg:grid-cols-3) with icon-free cards
- Each card: Bold number prefix + feature title + 2-line description
- Features: Digital Twin Creation, AI-Powered Simulations, Continuous Monitoring, Vulnerability Discovery, Compliance Reporting, Real-time Alerts

**Platform Preview:**
- Full-width section with dashboard screenshot
- Annotated callouts pointing to key features
- Use browser window frame for context

**Security Standards:**
- 4-column grid showing compliance badges (SOC2, ISO 27001, OWASP, GDPR)
- Minimal icons with certification names

**CTA Section:**
- Centered layout with headline "Start Your Free Security Assessment"
- Email input + button (inline form)
- Subtext: "No credit card required • 14-day trial"

**Footer:**
- 4-column layout: Product, Company, Resources, Legal
- Newsletter signup in separate row above
- Social links + copyright

### Dashboard Components

**Sidebar Navigation:**
- Fixed left sidebar (w-64)
- Logo at top
- Grouped navigation items with icons from Heroicons
- Groups: Overview, Projects, Scans, Reports, Settings
- User profile at bottom with avatar + name

**Top Navigation Bar:**
- Breadcrumb navigation
- Search bar (center)
- Notification bell + user dropdown (right)

**Dashboard Widgets:**
- Security Score Card: Large number (text-5xl) + trend indicator + sparkline chart
- Active Scans: List with status badges (Running/Complete/Failed)
- Recent Vulnerabilities: Table with severity badges (Critical/High/Medium/Low)
- Twin Status: Card with status indicator dot + last scan time

**Project Cards:**
- Grid layout (lg:grid-cols-3)
- Card contains: Project name, asset count, last scan date, security score badge
- Hover state: subtle elevation

**Scan Results View:**
- Split layout: Filters sidebar (w-72) + main content
- Results as expandable accordion items
- Each item: Severity badge + vulnerability title + affected asset + CVE link
- Charts: Use chart.js with minimal styling

**Data Tables:**
- Striped rows for readability
- Sortable column headers
- Inline actions (icon buttons)
- Pagination at bottom

**Forms:**
- Single column layout (max-w-2xl)
- Input groups with labels above
- Helper text below inputs
- Action buttons right-aligned

**Status Badges:**
- Pill-shaped with subtle background
- Variants: Critical, High, Medium, Low, Info, Success
- Small size (px-3 py-1 text-xs)

## Images

**Landing Page:**
- Hero: Large dashboard preview screenshot or 3D abstract security visualization (right side of split hero)
- Platform Preview: Full dashboard screenshot with annotated features
- Optional: Team photos in "About" section if included

**Dashboard:**
- Empty states: Simple illustrations for "No projects yet" or "No scans running"
- User avatars: Circular, 32px or 40px diameter

## Animations

**Minimal Animation Strategy:**
- Page transitions: None (instant navigation)
- Hover states: Subtle scale (hover:scale-105) on cards only
- Loading states: Simple spinner (animate-spin)
- Chart reveals: Fade-in on mount
- NO scroll-triggered animations
- NO complex hero animations

## Accessibility

- All interactive elements minimum 44px touch target
- Form inputs with visible focus states (ring-2)
- ARIA labels on icon-only buttons
- Semantic HTML throughout
- Keyboard navigation support for tables and forms
- High contrast text (meet WCAG AA standards)

## Technical Specifications

**Icons:** Heroicons (via CDN) - use outline variant throughout
**Responsive Breakpoints:** Tailwind defaults (sm, md, lg, xl, 2xl)
**Container Strategy:** max-w-7xl with horizontal padding for landing, fixed sidebar for dashboard