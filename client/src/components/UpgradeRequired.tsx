import { AlertCircle, ArrowUpCircle, Lock, Shield, Zap } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface UpgradeRequiredProps {
  feature: string;
  requiredPlan: "PRO" | "ELITE";
  currentPlan: string;
  description?: string;
  onUpgrade?: () => void;
}

const planDetails = {
  PRO: {
    name: "Pro Plan",
    color: "bg-blue-600",
    icon: Zap,
    features: [
      "Cloud Security Scans",
      "Visual Attack Path",
      "Weekly Monitoring",
      "Exploiter Agent",
      "Prophet Agent",
      "Up to 50 scans/month",
    ],
    price: "$99/month",
  },
  ELITE: {
    name: "Elite Plan",
    color: "bg-purple-600",
    icon: Shield,
    features: [
      "All Pro features",
      "AI Threat Intelligence",
      "Database Sandboxing",
      "AI-Powered Remediation",
      "Compliance Reports (ISO/GDPR)",
      "Phishing Simulation",
      "Daily Monitoring",
      "All 7 Security Agents",
      "Unlimited scans",
    ],
    price: "$299/month",
  },
};

export function UpgradeRequired({
  feature,
  requiredPlan,
  currentPlan,
  description,
  onUpgrade,
}: UpgradeRequiredProps) {
  const plan = planDetails[requiredPlan];
  const PlanIcon = plan.icon;

  return (
    <Card className="border-orange-500/30 bg-gradient-to-br from-orange-500/5 to-transparent">
      <CardHeader>
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-orange-500/10">
            <Lock className="h-6 w-6 text-orange-500" />
          </div>
          <div>
            <CardTitle className="text-xl">Upgrade Required</CardTitle>
            <CardDescription>
              {feature} requires the {plan.name}
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {description && (
          <p className="text-muted-foreground">{description}</p>
        )}

        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <AlertCircle className="h-4 w-4" />
          <span>
            Your current plan: <Badge variant="secondary">{currentPlan}</Badge>
          </span>
        </div>

        <div className={`rounded-lg p-4 ${plan.color}/10 border border-${plan.color}/20`}>
          <div className="flex items-center gap-2 mb-3">
            <PlanIcon className="h-5 w-5" />
            <span className="font-semibold">{plan.name}</span>
            <span className="text-muted-foreground text-sm">{plan.price}</span>
          </div>
          <ul className="space-y-2">
            {plan.features.map((feat, idx) => (
              <li key={idx} className="flex items-center gap-2 text-sm">
                <ArrowUpCircle className="h-3 w-3 text-green-500" />
                {feat}
              </li>
            ))}
          </ul>
        </div>

        <Button 
          className="w-full" 
          size="lg"
          onClick={onUpgrade}
        >
          <ArrowUpCircle className="mr-2 h-4 w-4" />
          Upgrade to {plan.name}
        </Button>
      </CardContent>
    </Card>
  );
}

export function FeatureGate({
  feature,
  requiredPlan,
  currentPlan,
  children,
}: {
  feature: string;
  requiredPlan: "PRO" | "ELITE";
  currentPlan: string;
  children: React.ReactNode;
}) {
  const planHierarchy = { STANDARD: 1, PRO: 2, ELITE: 3 };
  const currentLevel = planHierarchy[currentPlan as keyof typeof planHierarchy] || 1;
  const requiredLevel = planHierarchy[requiredPlan];

  if (currentLevel >= requiredLevel) {
    return <>{children}</>;
  }

  return (
    <UpgradeRequired
      feature={feature}
      requiredPlan={requiredPlan}
      currentPlan={currentPlan}
    />
  );
}

export function LockedFeatureCard({
  title,
  description,
  requiredPlan,
  icon: Icon,
}: {
  title: string;
  description: string;
  requiredPlan: "PRO" | "ELITE";
  icon: React.ComponentType<{ className?: string }>;
}) {
  const plan = planDetails[requiredPlan];

  return (
    <Card className="relative overflow-hidden opacity-75 hover:opacity-90 transition-opacity">
      <div className="absolute inset-0 bg-gradient-to-br from-gray-900/50 to-transparent" />
      <div className="absolute top-2 right-2">
        <Badge variant="outline" className="text-xs">
          <Lock className="h-3 w-3 mr-1" />
          {plan.name}
        </Badge>
      </div>
      <CardHeader className="relative">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gray-500/10">
            <Icon className="h-5 w-5 text-gray-400" />
          </div>
          <div>
            <CardTitle className="text-lg text-gray-400">{title}</CardTitle>
            <CardDescription className="text-gray-500">{description}</CardDescription>
          </div>
        </div>
      </CardHeader>
    </Card>
  );
}
