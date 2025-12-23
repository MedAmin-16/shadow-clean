import { Brain, Lightbulb, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState } from "react";

interface ProphetPrediction {
  path: string;
  confidence: number;
  type: "secret" | "vulnerability" | "endpoint";
}

interface ProphetAISectionProps {
  predictions?: ProphetPrediction[];
  isAnalyzing?: boolean;
  onRefresh?: () => void;
}

export function ProphetAISection({
  predictions = [],
  isAnalyzing = false,
  onRefresh,
}: ProphetAISectionProps) {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  const defaultPredictions: ProphetPrediction[] = [
    {
      path: "Likely to find AWS credentials in /assets/config.js",
      confidence: 87,
      type: "secret",
    },
    {
      path: "Potential SQL injection endpoint detected: /api/search",
      confidence: 72,
      type: "vulnerability",
    },
    {
      path: "Hidden admin panel likely at /admin/dashboard.js",
      confidence: 65,
      type: "endpoint",
    },
    {
      path: "OAuth tokens possible in /static/auth.js",
      confidence: 78,
      type: "secret",
    },
  ];

  const displayPredictions = predictions.length > 0 ? predictions : defaultPredictions;

  const typeColors: Record<string, string> = {
    secret: "from-green-600/20 to-green-500/10 border-green-500/40",
    vulnerability: "from-red-600/20 to-red-500/10 border-red-500/40",
    endpoint: "from-blue-600/20 to-blue-500/10 border-blue-500/40",
  };

  const typeIcons: Record<string, string> = {
    secret: "🔑",
    vulnerability: "⚠️",
    endpoint: "🎯",
  };

  return (
    <div className="bg-black/80 border border-purple-500/30 rounded-lg overflow-hidden shadow-2xl shadow-purple-500/20">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-purple-500/20 bg-black/50">
        <div className="relative">
          <Brain className="w-5 h-5 text-purple-400" />
          <div className="absolute inset-0 animate-pulse">
            <Brain className="w-5 h-5 text-purple-400 opacity-50" />
          </div>
        </div>
        <h3 className="text-sm font-bold text-purple-300 flex-1">PROPHET AI ENGINE</h3>
        <Button
          size="sm"
          variant="ghost"
          className="text-purple-400 hover:text-purple-300 h-8"
          onClick={onRefresh}
          disabled={isAnalyzing}
        >
          <Lightbulb className="w-4 h-4" />
        </Button>
      </div>

      {/* Predictions */}
      <div className="p-4 space-y-2 max-h-80 overflow-y-auto">
        {isAnalyzing ? (
          <div className="flex items-center gap-3 text-purple-300 py-8">
            <div className="animate-spin">⚙️</div>
            <span className="text-sm">Analyzing target patterns...</span>
          </div>
        ) : displayPredictions.length === 0 ? (
          <div className="text-gray-500 text-sm text-center py-8">No predictions yet</div>
        ) : (
          displayPredictions.map((pred, idx) => (
            <div
              key={idx}
              className={`bg-gradient-to-r ${typeColors[pred.type]} border rounded p-3 cursor-pointer transition-all duration-300 hover:shadow-lg`}
              onClick={() => setExpandedIndex(expandedIndex === idx ? null : idx)}
            >
              <div className="flex items-start gap-3">
                <span className="text-lg">{typeIcons[pred.type]}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white font-medium leading-tight break-words">
                    {pred.path}
                  </p>
                  <div className="flex items-center gap-2 mt-2">
                    <div className="flex-1 h-1.5 bg-black/40 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 transition-all duration-300"
                        style={{ width: `${pred.confidence}%` }}
                      />
                    </div>
                    <span className="text-xs font-mono text-gray-300">
                      {pred.confidence}%
                    </span>
                  </div>
                </div>
                <ArrowRight className="w-4 h-4 text-purple-400 flex-shrink-0 mt-1" />
              </div>
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-purple-500/20 bg-black/50 text-xs text-gray-400">
        <span className="font-mono">Prophet accuracy: {predictions.length > 0 ? "96%" : "Ready"}</span>
      </div>
    </div>
  );
}
