import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Folder, Clock, Server } from "lucide-react";

interface ProjectCardProps {
  id: string;
  name: string;
  assetCount: number;
  lastScanDate: string;
  securityScore: number;
  onClick?: () => void;
}

export function ProjectCard({ name, assetCount, lastScanDate, securityScore, onClick }: ProjectCardProps) {
  const getScoreColor = (s: number) => {
    if (s >= 80) return "bg-green-500/10 text-green-500 border-green-500/20";
    if (s >= 60) return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
    if (s >= 40) return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    return "bg-red-500/10 text-red-500 border-red-500/20";
  };

  return (
    <Card 
      className="hover-elevate cursor-pointer transition-all" 
      onClick={onClick}
      data-testid={`card-project-${name.toLowerCase().replace(/\s+/g, '-')}`}
    >
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-base font-medium flex items-center gap-2">
          <Folder className="h-4 w-4 text-primary" />
          {name}
        </CardTitle>
        <Badge variant="outline" className={getScoreColor(securityScore)}>
          {securityScore}/100
        </Badge>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          <span className="flex items-center gap-1">
            <Server className="h-3.5 w-3.5" />
            {assetCount} assets
          </span>
          <span className="flex items-center gap-1">
            <Clock className="h-3.5 w-3.5" />
            {lastScanDate}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
