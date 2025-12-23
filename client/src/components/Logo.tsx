import { Shield } from "lucide-react";

interface LogoProps {
  size?: "sm" | "md" | "lg";
  showText?: boolean;
}

export function Logo({ size = "md", showText = true }: LogoProps) {
  const iconSize = {
    sm: "h-5 w-5",
    md: "h-6 w-6",
    lg: "h-8 w-8",
  }[size];

  const textSize = {
    sm: "text-lg",
    md: "text-xl",
    lg: "text-2xl",
  }[size];

  return (
    <div className="flex items-center gap-2">
      <div className="relative">
        <Shield className={`${iconSize} text-primary`} />
        <div className="absolute inset-0 bg-primary/20 blur-sm rounded-full" />
      </div>
      {showText && (
        <span className={`font-bold ${textSize} tracking-tight`}>
          Shadow<span className="text-primary">Twin</span>
        </span>
      )}
    </div>
  );
}
