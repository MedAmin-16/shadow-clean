import { useState, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { 
  Search, 
  Clock, 
  Target, 
  Shield, 
  Bug, 
  FileText, 
  Download, 
  RotateCcw, 
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { format } from "date-fns";
import type { DbScan as Scan } from "@shared/schema";
import { useToast } from "@/hooks/use-toast";

export default function HistoryPage() {
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);
  const { toast } = useToast();

  const { data: scans = [], isLoading } = useQuery<Scan[]>({
    queryKey: ["/api/scans"],
  });

  const rescanMutation = useMutation({
    mutationFn: async (scanId: string) => {
      const response = await apiRequest("POST", `/api/scans/${scanId}/rescan`, {});
      return response.json();
    },
    onSuccess: () => {
      toast({ title: "Re-scan started", description: "The target is being analyzed again." });
      queryClient.invalidateQueries({ queryKey: ["/api/scans"] });
    },
  });

  const exportData = (format: 'json' | 'csv') => {
    window.location.href = `/api/scans/export?format=${format}`;
  };

  const filteredScans = useMemo(() => {
    return scans.filter(scan => {
      const matchesSearch = scan.target.toLowerCase().includes(search.toLowerCase());
      // Severity filtering logic would go here if we had aggregate severity in scan object
      return matchesSearch;
    });
  }, [scans, search]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-8 p-8">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Clock className="h-8 w-8 text-cyan-400" />
            Target History & Evidence Vault
          </h1>
          <p className="text-muted-foreground mt-2 text-lg">
            Archive of all security assessments and vulnerability evidence.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="gap-2 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10">
                <Download className="h-4 w-4" />
                Export Data
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-black border-cyan-500/20 text-cyan-400">
              <DropdownMenuItem onClick={() => exportData('json')} className="hover:bg-cyan-500/10 cursor-pointer">
                Download JSON
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => exportData('csv')} className="hover:bg-cyan-500/10 cursor-pointer">
                Download CSV
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <div className="flex flex-col md:flex-row gap-4 items-center">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input 
            placeholder="Search by target URL (e.g. sbs.gov)..." 
            className="pl-10 bg-black/40 border-cyan-500/20 focus:border-cyan-500/50"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="gap-2 border-cyan-500/20 min-w-[140px]">
              <Filter className="h-4 w-4" />
              {filterSeverity || "All Severities"}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="bg-black border-cyan-500/20 text-cyan-400">
            <DropdownMenuItem onClick={() => setFilterSeverity(null)}>All</DropdownMenuItem>
            <DropdownMenuItem onClick={() => setFilterSeverity("Critical")}>Critical</DropdownMenuItem>
            <DropdownMenuItem onClick={() => setFilterSeverity("High")}>High</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div className="grid gap-4">
        {filteredScans.length === 0 ? (
          <Card className="bg-black/40 border-dashed border-cyan-500/20">
            <CardContent className="flex flex-col items-center justify-center py-12 text-center">
              <Clock className="h-12 w-12 text-muted-foreground/30 mb-4" />
              <p className="text-muted-foreground">No historical records found for this criteria.</p>
            </CardContent>
          </Card>
        ) : (
          filteredScans.map((scan) => (
            <Card key={scan.id} className="bg-black/40 border-cyan-500/10 hover:border-cyan-500/30 transition-all group">
              <CardContent className="p-6">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center gap-3">
                      <Target className="h-5 w-5 text-cyan-400" />
                      <h3 className="text-xl font-mono font-bold text-white group-hover:text-cyan-400 transition-colors">
                        {scan.target}
                      </h3>
                      {scan.status === 'complete' ? (
                        <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/20">
                          <CheckCircle2 className="h-3 w-3 mr-1" /> Complete
                        </Badge>
                      ) : scan.status === 'failed' ? (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20">
                          <AlertTriangle className="h-3 w-3 mr-1" /> Failed
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-cyan-500/10 text-cyan-400 border-cyan-500/20 animate-pulse">
                          Running
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1.5">
                        <Clock className="h-3.5 w-3.5" />
                        {format(new Date(scan.startedAt), "MMM d, yyyy HH:mm")}
                      </span>
                      <span className="flex items-center gap-1.5">
                        <Shield className="h-3.5 w-3.5" />
                        Risk: {scan.status === 'complete' ? 'Assessment Finalized' : 'In Progress'}
                      </span>
                      <span className="flex items-center gap-1.5">
                        <Bug className="h-3.5 w-3.5" />
                        Evidence: Vaulted
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Button 
                      variant="outline" 
                      className="gap-2 border-cyan-500/30 hover:bg-cyan-500/10 text-cyan-400"
                      onClick={() => rescanMutation.mutate(scan.id)}
                      disabled={rescanMutation.isPending}
                    >
                      <RotateCcw className={`h-4 w-4 ${rescanMutation.isPending ? 'animate-spin' : ''}`} />
                      Re-Scan
                    </Button>
                    <Button className="bg-cyan-500 hover:bg-cyan-600 text-black font-bold gap-2">
                      <FileText className="h-4 w-4" />
                      View Details
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
