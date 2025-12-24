import { useEffect, useState } from "react";

interface TerminalSpinnerProps {
  isActive: boolean;
  toolName?: string;
}

export function TerminalSpinner({ isActive, toolName = "Scanning" }: TerminalSpinnerProps) {
  const [spinnerIndex, setSpinnerIndex] = useState(0);
  
  const spinnerFrames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  const neonGreen = "#00FF00";
  const neonCyan = "#00FFCC";

  useEffect(() => {
    if (!isActive) return;

    const interval = setInterval(() => {
      setSpinnerIndex((prev) => (prev + 1) % spinnerFrames.length);
    }, 80);

    return () => clearInterval(interval);
  }, [isActive]);

  if (!isActive) return null;

  return (
    <span
      style={{
        display: "inline-block",
        color: neonGreen,
        fontWeight: "bold",
        fontFamily: "'Fira Code', monospace",
        marginRight: "0.5rem",
        animation: "pulse 0.5s ease-in-out infinite",
      }}
    >
      {spinnerFrames[spinnerIndex]} {toolName}
    </span>
  );
}
