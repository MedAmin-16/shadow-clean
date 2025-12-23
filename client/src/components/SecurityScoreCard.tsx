import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

interface SecurityScoreCardProps {
  score: number;
  trend: "up" | "down" | "stable";
  trendValue: number;
  lastScan?: string;
}

export function SecurityScoreCard({ score, trend, trendValue, lastScan }: SecurityScoreCardProps) {
  const getScoreColor = (s: number) => {
    if (s >= 80) return "text-green-500";
    if (s >= 60) return "text-yellow-500";
    if (s >= 40) return "text-orange-500";
    return "text-red-500";
  };

  const getTrendIcon = () => {
    if (trend === "up") return <TrendingUp className="h-4 w-4 text-green-500" />;
    if (trend === "down") return <TrendingDown className="h-4 w-4 text-red-500" />;
    return <Minus className="h-4 w-4 text-muted-foreground" />;
  };

  const getTrendColor = () => {
    if (trend === "up") return "text-green-500";
    if (trend === "down") return "text-red-500";
    return "text-muted-foreground";
  };

  return (
    <Card data-testid="card-security-score">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Security Score</CardTitle>
        <div className="flex items-center gap-1">
          {getTrendIcon()}
          <span className={`text-sm ${getTrendColor()}`}>
            {trend === "up" ? "+" : trend === "down" ? "-" : ""}{trendValue}%
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className={`text-5xl font-bold ${getScoreColor(score)}`}>
          {score}
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          out of 100
        </p>
        {lastScan && (
          <p className="text-xs text-muted-foreground mt-2">
            Last scan: {lastScan}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
