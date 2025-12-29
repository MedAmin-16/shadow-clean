import { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { ShadowLogicThought, ThoughtType } from "@shared/shadowLogic";
import { Crown, Cpu, Zap, ChevronDown } from "lucide-react";

interface ShadowLogicTerminalProps {
  thoughts: ShadowLogicThought[];
  isActive: boolean;
  className?: string;
  evidences?: any[];
}

const thoughtStyles: Record<ThoughtType, { icon: string; color: string; bgColor: string; glowColor: string }> = {
  observation: { icon: "👁", color: "text-amber-300", bgColor: "bg-amber-500/15", glowColor: "shadow-amber-500/30" },
  reasoning: { icon: "🧠", color: "text-amber-200", bgColor: "bg-amber-600/20", glowColor: "shadow-amber-400/30" },
  action: { icon: "⚡", color: "text-yellow-300", bgColor: "bg-yellow-500/15", glowColor: "shadow-yellow-500/30" },
  discovery: { icon: "🔍", color: "text-amber-300", bgColor: "bg-amber-500/15", glowColor: "shadow-amber-500/30" },
  warning: { icon: "⚠️", color: "text-orange-300", bgColor: "bg-orange-500/15", glowColor: "shadow-orange-500/30" },
  success: { icon: "✅", color: "text-emerald-400", bgColor: "bg-emerald-500/15", glowColor: "shadow-emerald-500/30" },
  error: { icon: "❌", color: "text-red-400", bgColor: "bg-red-500/15", glowColor: "shadow-red-500/30" },
};

export function ShadowLogicTerminal({ thoughts, isActive, className, evidences = [] }: ShadowLogicTerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [expandedEvidence, setExpandedEvidence] = useState<string | null>(null);
  
  // Memory management: Keep only the last 500 logs to prevent UI crashes
  const filteredThoughts = thoughts.slice(-500);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filteredThoughts, autoScroll]);

  const handleScroll = () => {
    if (scrollRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
      const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
      setAutoScroll(isAtBottom);
    }
  };

  // Extract metadata from thoughts
  const currentWorkflow = thoughts
    .filter(t => t.message.toLowerCase().includes("workflow") || t.message.toLowerCase().includes("login") || t.message.toLowerCase().includes("checkout"))
    .slice(-1)[0]?.message || "Analyzing...";

  const lastHypothesis = thoughts
    .filter(t => t.type === "reasoning")
    .slice(-1)[0]?.message || "Testing business logic...";

  const payloadsGenerated = thoughts.filter(t => t.message.includes("payload") || t.message.includes("request")).length;

  return (
    <Card className={cn("bg-gradient-to-b from-black via-zinc-950 to-black border border-amber-900/40 shadow-2xl shadow-amber-900/20", className)}>
      <CardHeader className="pb-3 flex flex-row items-center justify-between border-b border-amber-900/30">
        <div className="flex items-center gap-4">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500/80 animate-pulse" />
            <div className="w-3 h-3 rounded-full bg-amber-500/80 animate-pulse" style={{animationDelay: "0.2s"}} />
            <div className="w-3 h-3 rounded-full bg-emerald-500/80 animate-pulse" style={{animationDelay: "0.4s"}} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <Crown className="w-4 h-4 text-amber-400" />
              <CardTitle className="text-sm font-mono text-amber-300 tracking-wide">
                ELITE SHADOW LOGIC INTERFACE
              </CardTitle>
            </div>
            <p className="text-xs text-amber-600/80 font-mono mt-1">Real-Time AI Thought Process Analyzer</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isActive && (
            <Badge className="bg-amber-500/30 text-amber-300 border border-amber-500/60 animate-pulse font-mono text-xs">
              ◆ LIVE STREAMING
            </Badge>
          )}
          <Badge variant="outline" className="text-amber-400/70 border-amber-800/50 font-mono text-xs bg-amber-950/30">
            {filteredThoughts.length}/{thoughts.length} events
          </Badge>
        </div>
      </CardHeader>
      
      {/* Metadata Panel */}
      <div className="px-4 py-3 border-b border-amber-900/30 bg-amber-950/10 grid grid-cols-3 gap-4">
        <div className="text-xs">
          <p className="text-amber-600/60 font-mono">WORKFLOW</p>
          <p className="text-amber-300 font-mono text-xs truncate">{currentWorkflow.substring(0, 40)}</p>
        </div>
        <div className="text-xs">
          <p className="text-amber-600/60 font-mono">HYPOTHESIS</p>
          <p className="text-amber-300 font-mono text-xs truncate">{lastHypothesis.substring(0, 40)}</p>
        </div>
        <div className="text-xs">
          <p className="text-amber-600/60 font-mono">PAYLOADS</p>
          <p className="text-amber-300 font-mono">{payloadsGenerated} generated</p>
        </div>
      </div>
      <CardContent className="p-0">
        <ScrollArea
          className="h-96 font-mono text-sm"
          ref={scrollRef}
          onScrollCapture={handleScroll}
        >
          <div className="p-4 space-y-2">
            {filteredThoughts.length === 0 ? (
              <div className="text-amber-700 italic font-mono text-sm">
                ▸ Initializing Shadow Logic AI Engine...
              </div>
            ) : (
              <>
                {thoughts.length > 500 && (
                  <div className="text-orange-600 text-xs italic px-2 py-1 rounded bg-orange-950/40 border border-orange-700/30 font-mono">
                    ⚠ Showing last 500 events ({thoughts.length - 500} older logs hidden)
                  </div>
                )}
                {evidences.length > 0 && (
                  <div className="mb-4 p-2.5 rounded border bg-red-950/30 border-red-700/40">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-lg">🔐</span>
                      <span className="font-bold text-red-400 text-xs uppercase">[VERIFIED EXPLOITS]</span>
                      <Badge className="bg-red-600/30 text-red-300 text-xs">{evidences.length} proof(s)</Badge>
                    </div>
                    {evidences.map((ev: any, i) => (
                      <div key={i} className="mb-2 text-xs text-amber-100">
                        <button
                          onClick={() => setExpandedEvidence(expandedEvidence === `ev${i}` ? null : `ev${i}`)}
                          className="flex items-center gap-2 w-full text-left hover:text-amber-300 p-1"
                        >
                          <ChevronDown className={cn("w-3 h-3 transition-transform", expandedEvidence === `ev${i}` && "rotate-180")} />
                          <span className="font-mono">► Step 1-3 PoC: {ev.title?.substring(0, 50)}</span>
                        </button>
                        {expandedEvidence === `ev${i}` && (
                          <div className="ml-4 mt-1 p-2 bg-amber-950/20 rounded border border-amber-800/20 text-amber-100 font-mono text-xs max-h-48 overflow-y-auto">
                            <p><strong>Step 2 Injection:</strong> {ev.injection}</p>
                            <p className="mt-1"><strong>Step 3 Result:</strong> {ev.result}</p>
                            <p className="mt-1 text-amber-400"><strong>Why:</strong> {ev.whyItWorked?.substring(0, 80)}</p>
                            <p className="mt-2 text-red-400 font-bold">🔐 ShadowTwin Verified Exploit</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                {filteredThoughts.map((thought) => {
                const style = thoughtStyles[thought.type];
                return (
                  <div
                    key={thought.id}
                    className={cn(
                      "flex items-start gap-3 p-2.5 rounded border transition-all hover:shadow-md",
                      style.bgColor,
                      "border-amber-700/20 hover:border-amber-600/40"
                    )}
                  >
                    <span className="text-base flex-shrink-0 animate-pulse">{style.icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={cn("font-bold text-[10px] uppercase tracking-tighter px-1.5 py-0.5 rounded border", style.bgColor, style.color, "border-amber-500/30")}>
                          {thought.type}
                        </span>
                        <span className="text-amber-700/60 text-[10px] font-mono">
                          {new Date(thought.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                      </div>
                      <p className={cn("text-amber-50 break-words text-xs leading-relaxed font-medium", style.color)}>
                        <span className="opacity-50 mr-2">{">>>"}</span>{thought.message}
                      </p>
                      {thought.details && (
                        <pre className="mt-1.5 text-xs text-amber-900 bg-amber-950/40 border border-amber-800/30 rounded p-1.5 overflow-x-auto font-mono">
                          {thought.details}
                        </pre>
                      )}
                    </div>
                  </div>
                );
              })
                }
              </>
            )}
            {isActive && (
              <div className="flex items-center gap-2 text-amber-600 font-mono text-xs">
                <span className="inline-block w-2 h-2 bg-amber-500 rounded-full animate-pulse" />
                <span className="animate-pulse">Analyzing business logic...</span>
                <Cpu className="w-3 h-3 animate-spin text-amber-500" />
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
