import { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { ShadowLogicThought, ThoughtType } from "@shared/shadowLogic";

interface ShadowLogicTerminalProps {
  thoughts: ShadowLogicThought[];
  isActive: boolean;
  className?: string;
}

const thoughtStyles: Record<ThoughtType, { icon: string; color: string; bgColor: string }> = {
  observation: { icon: "👁", color: "text-blue-400", bgColor: "bg-blue-500/10" },
  reasoning: { icon: "🧠", color: "text-purple-400", bgColor: "bg-purple-500/10" },
  action: { icon: "⚡", color: "text-yellow-400", bgColor: "bg-yellow-500/10" },
  discovery: { icon: "🔍", color: "text-cyan-400", bgColor: "bg-cyan-500/10" },
  warning: { icon: "⚠️", color: "text-orange-400", bgColor: "bg-orange-500/10" },
  success: { icon: "✅", color: "text-green-400", bgColor: "bg-green-500/10" },
  error: { icon: "❌", color: "text-red-400", bgColor: "bg-red-500/10" },
};

export function ShadowLogicTerminal({ thoughts, isActive, className }: ShadowLogicTerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  
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

  return (
    <Card className={cn("bg-zinc-950 border-zinc-800", className)}>
      <CardHeader className="pb-2 flex flex-row items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500/80" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
            <div className="w-3 h-3 rounded-full bg-green-500/80" />
          </div>
          <CardTitle className="text-sm font-mono text-zinc-400">
            ShadowLogic Live Terminal
          </CardTitle>
        </div>
        <div className="flex items-center gap-2">
          {isActive && (
            <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/50 animate-pulse">
              LIVE
            </Badge>
          )}
          <Badge variant="outline" className="text-zinc-400 border-zinc-700">
            {filteredThoughts.length}/{thoughts.length} events
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea
          className="h-96 font-mono text-sm"
          ref={scrollRef}
          onScrollCapture={handleScroll}
        >
          <div className="p-4 space-y-2">
            {filteredThoughts.length === 0 ? (
              <div className="text-zinc-600 italic">
                Waiting for ShadowLogic to initialize...
              </div>
            ) : (
              <>
                {thoughts.length > 500 && (
                  <div className="text-yellow-600 text-xs italic px-2 py-1 rounded bg-yellow-500/10">
                    ℹ️ Showing last 500 events ({thoughts.length - 500} older logs hidden)
                  </div>
                )}
                {filteredThoughts.map((thought) => {
                const style = thoughtStyles[thought.type];
                return (
                  <div
                    key={thought.id}
                    className={cn(
                      "flex items-start gap-3 p-2 rounded-md transition-all",
                      style.bgColor
                    )}
                  >
                    <span className="text-base flex-shrink-0">{style.icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={cn("font-semibold text-xs uppercase", style.color)}>
                          {thought.type}
                        </span>
                        <span className="text-zinc-600 text-xs">
                          {new Date(thought.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className={cn("text-zinc-300 break-words", style.color)}>
                        {thought.message}
                      </p>
                      {thought.details && (
                        <pre className="mt-1 text-xs text-zinc-500 overflow-x-auto">
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
              <div className="flex items-center gap-2 text-zinc-600">
                <span className="animate-pulse">_</span>
                <span className="text-xs">Processing...</span>
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
