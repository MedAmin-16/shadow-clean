import { useState } from "react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Logo } from "@/components/Logo";
import {
  Shield,
  Zap,
  Eye,
  Target,
  FileCheck,
  Bell,
  ArrowRight,
  CheckCircle2,
} from "lucide-react";

// todo: remove mock functionality
const features = [
  {
    number: "01",
    title: "Digital Twin Creation",
    description: "Create complete digital replicas of your infrastructure for safe security testing.",
  },
  {
    number: "02",
    title: "AI-Powered Simulations",
    description: "Run autonomous attack simulations using advanced AI to discover vulnerabilities.",
  },
  {
    number: "03",
    title: "Continuous Monitoring",
    description: "24/7 monitoring of your assets with real-time threat detection and alerting.",
  },
  {
    number: "04",
    title: "Vulnerability Discovery",
    description: "Automated scanning for OWASP Top-10 and emerging security threats.",
  },
  {
    number: "05",
    title: "Compliance Reporting",
    description: "Generate comprehensive reports for SOC2, ISO 27001, and GDPR compliance.",
  },
  {
    number: "06",
    title: "Real-time Alerts",
    description: "Instant notifications when critical vulnerabilities are detected.",
  },
];

const complianceBadges = [
  { name: "SOC2", icon: Shield },
  { name: "ISO 27001", icon: CheckCircle2 },
  { name: "OWASP", icon: Target },
  { name: "GDPR", icon: FileCheck },
];

export default function LandingPage() {
  const [, setLocation] = useLocation();
  const [email, setEmail] = useState("");

  const handleGetStarted = () => {
    setLocation("/login");
  };

  const handleEarlyAccess = () => {
    console.log("Early access requested for:", email);
    setEmail("");
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="fixed top-0 left-0 right-0 z-50 border-b bg-background/80 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-4">
          <Logo size="md" />
          <div className="flex items-center gap-2">
            <Button variant="ghost" onClick={() => setLocation("/login")} data-testid="button-login">
              Login
            </Button>
            <Button onClick={handleGetStarted} data-testid="button-get-started-header">
              Get Started
            </Button>
          </div>
        </div>
      </header>

      <main>
        <section className="min-h-screen flex items-center pt-16">
          <div className="max-w-7xl mx-auto px-6 py-20 lg:py-24">
            <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
              <div className="space-y-8">
                <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium">
                  <Shield className="h-4 w-4" />
                  Trusted by Fortune 500 Security Teams
                </div>
                <h1 className="text-5xl lg:text-6xl font-bold tracking-tight">
                  Build your Cyber Security{" "}
                  <span className="text-primary">Twin</span>
                </h1>
                <p className="text-xl text-muted-foreground max-w-lg">
                  Predict attacks before they happen. ShadowTwin creates AI-powered digital replicas of your infrastructure for autonomous security testing and vulnerability discovery.
                </p>
                <div className="flex flex-wrap items-center gap-4">
                  <Button size="lg" onClick={handleGetStarted} data-testid="button-get-started-hero">
                    Get Started
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </Button>
                  <Button size="lg" variant="outline" onClick={() => setLocation("/signup")} data-testid="button-early-access">
                    Early Access
                  </Button>
                </div>
              </div>
              <div className="relative">
                <div className="aspect-[4/3] rounded-lg bg-gradient-to-br from-primary/20 via-primary/10 to-background border overflow-hidden">
                  <div className="absolute inset-4 rounded-md bg-card border shadow-lg">
                    <div className="p-4 border-b flex items-center gap-2">
                      <div className="flex gap-1.5">
                        <div className="h-3 w-3 rounded-full bg-red-500" />
                        <div className="h-3 w-3 rounded-full bg-yellow-500" />
                        <div className="h-3 w-3 rounded-full bg-green-500" />
                      </div>
                      <span className="text-xs text-muted-foreground font-mono">dashboard.shadowtwin.io</span>
                    </div>
                    <div className="p-4 space-y-4">
                      <div className="flex items-center justify-between gap-4">
                        <div>
                          <p className="text-xs text-muted-foreground">Security Score</p>
                          <p className="text-3xl font-bold text-green-500">92</p>
                        </div>
                        <div className="h-16 w-32 bg-gradient-to-t from-green-500/20 to-transparent rounded" />
                      </div>
                      <div className="grid grid-cols-3 gap-2">
                        {[1, 2, 3].map((i) => (
                          <div key={i} className="h-12 rounded bg-muted animate-pulse" />
                        ))}
                      </div>
                      <div className="space-y-2">
                        {[1, 2].map((i) => (
                          <div key={i} className="h-8 rounded bg-muted animate-pulse" />
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="absolute -bottom-4 -right-4 h-24 w-24 bg-primary/20 rounded-full blur-2xl" />
                <div className="absolute -top-4 -left-4 h-32 w-32 bg-primary/10 rounded-full blur-3xl" />
              </div>
            </div>
          </div>
        </section>

        <section className="py-20 lg:py-24 bg-muted/30">
          <div className="max-w-7xl mx-auto px-6">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-semibold mb-4">
                Complete Security Platform
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Everything you need to protect your digital assets in one unified platform.
              </p>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {features.map((feature) => (
                <Card key={feature.number} className="hover-elevate" data-testid={`card-feature-${feature.number}`}>
                  <CardContent className="p-6">
                    <span className="text-4xl font-bold text-primary/20">{feature.number}</span>
                    <h3 className="text-lg font-medium mt-2 mb-2">{feature.title}</h3>
                    <p className="text-sm text-muted-foreground">{feature.description}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        <section className="py-20 lg:py-24">
          <div className="max-w-7xl mx-auto px-6">
            <div className="text-center mb-12">
              <h2 className="text-2xl font-semibold mb-4">Security Standards</h2>
              <p className="text-muted-foreground">Compliant with industry-leading security frameworks</p>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              {complianceBadges.map((badge) => (
                <div
                  key={badge.name}
                  className="flex flex-col items-center justify-center p-6 rounded-lg border bg-card"
                  data-testid={`badge-compliance-${badge.name.toLowerCase().replace(/\s+/g, '-')}`}
                >
                  <badge.icon className="h-8 w-8 text-primary mb-2" />
                  <span className="font-medium">{badge.name}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="py-20 lg:py-24 bg-muted/30">
          <div className="max-w-3xl mx-auto px-6 text-center">
            <h2 className="text-4xl font-semibold mb-4">
              Start Your Free Security Assessment
            </h2>
            <p className="text-lg text-muted-foreground mb-8">
              Get a comprehensive security report of your infrastructure in minutes.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 max-w-md mx-auto">
              <Input
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="flex-1"
                data-testid="input-email-cta"
              />
              <Button onClick={handleEarlyAccess} data-testid="button-start-assessment">
                Start Free
                <ArrowRight className="h-4 w-4 ml-2" />
              </Button>
            </div>
            <p className="text-sm text-muted-foreground mt-4">
              No credit card required • 14-day trial
            </p>
          </div>
        </section>
      </main>

      <footer className="border-t py-12">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid md:grid-cols-4 gap-8 mb-8">
            <div>
              <h4 className="font-medium mb-4">Product</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><button className="hover:underline">Features</button></li>
                <li><button className="hover:underline">Pricing</button></li>
                <li><button className="hover:underline">Security</button></li>
                <li><button className="hover:underline">Enterprise</button></li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-4">Company</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><button className="hover:underline">About</button></li>
                <li><button className="hover:underline">Blog</button></li>
                <li><button className="hover:underline">Careers</button></li>
                <li><button className="hover:underline">Contact</button></li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-4">Resources</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><button className="hover:underline">Documentation</button></li>
                <li><button className="hover:underline">API Reference</button></li>
                <li><button className="hover:underline">Status</button></li>
                <li><button className="hover:underline">Changelog</button></li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-4">Legal</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><button className="hover:underline">Privacy</button></li>
                <li><button className="hover:underline">Terms</button></li>
                <li><button className="hover:underline">Cookie Policy</button></li>
                <li><button className="hover:underline">Licenses</button></li>
              </ul>
            </div>
          </div>
          <div className="pt-8 border-t flex flex-wrap items-center justify-between gap-4">
            <Logo size="sm" />
            <p className="text-sm text-muted-foreground">
              © 2024 ShadowTwin. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
