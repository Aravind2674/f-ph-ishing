import React, { useEffect, useMemo, useState } from "react";
import { ArrowUpDown, ArrowUp, ArrowDown, RefreshCw } from "lucide-react";
import { fetchHistory, type ScanHistoryItem } from "@/api";
import { cn } from "@/lib/utils";
import { resolveSeverity } from "@/lib/severity";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { RiskMeter, SeverityTag } from "@/components/RiskIndicators";

type SortKey = "target" | "timestamp" | "baseline_score" | "ml_score";
type SortDir = "asc" | "desc";

// The severity shown is the headline: the higher-risk band of the URL model and the provider evidence.
const bandOf = (s: ScanHistoryItem): string | null | undefined => s.headline_band ?? s.baseline_label;
const levelOf = (s: ScanHistoryItem) => resolveSeverity(s.baseline_score, bandOf(s)).level;
const fmt100 = (n: number | null | undefined) => (n == null ? "—" : (n * 100).toFixed(0));

export const History: React.FC = () => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [errored, setErrored] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const loadHistory = async () => {
    setLoading(true);
    setErrored(false);
    try {
      setHistory((await fetchHistory()) as ScanHistoryItem[]);
    } catch {
      setErrored(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const highRisk = history.filter((s) => levelOf(s) === "high" || levelOf(s) === "critical").length;
  const uniqueTargets = new Set(history.map((s) => s.target)).size;

  // A missing score sorts last in either direction; it is never treated as 0.
  const sorted = useMemo(() => {
    const value = (s: ScanHistoryItem): string | number | null =>
      sortKey === "target" ? s.target : sortKey === "timestamp" ? new Date(s.timestamp).getTime() : s[sortKey];
    return [...history].sort((a, b) => {
      const x = value(a);
      const y = value(b);
      if (x == null || y == null) return x == null && y == null ? 0 : x == null ? 1 : -1;
      const cmp = typeof x === "string" ? x.localeCompare(String(y)) : x - (y as number);
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [history, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "target" ? "asc" : "desc");
    }
  };

  const SortHead = ({ label, col, align = "left" }: { label: string; col: SortKey; align?: "left" | "right" }) => {
    const activeCol = sortKey === col;
    const Icon = !activeCol ? ArrowUpDown : sortDir === "asc" ? ArrowUp : ArrowDown;
    return (
      <TableHead className={cn(align === "right" && "text-right")} aria-sort={activeCol ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
        <button
          type="button"
          onClick={() => toggleSort(col)}
          className={cn("inline-flex items-center gap-1.5 transition-colors hover:text-foreground", activeCol && "text-foreground", align === "right" && "flex-row-reverse")}
        >
          {label}
          <Icon className="size-3" aria-hidden />
        </button>
      </TableHead>
    );
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-xs text-muted">
          {loading ? "—" : `${history.length} scans · ${highRisk} high risk · ${uniqueTargets} targets`}
        </p>
        <Button variant="outline" size="sm" onClick={loadHistory} disabled={loading}>
          <RefreshCw className={cn("size-3.5", loading && "animate-spin")} aria-hidden />
          Refresh
        </Button>
      </div>

      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <SortHead label="Target" col="target" />
              <TableHead>Type</TableHead>
              <SortHead label="Time" col="timestamp" />
              <SortHead label="URL model" col="ml_score" align="right" />
              <SortHead label="Provider" col="baseline_score" align="right" />
              <TableHead className="text-right">Severity</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              Array.from({ length: 6 }).map((_, i) => (
                <TableRow key={i} className="hover:bg-transparent">
                  <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-14" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                  <TableCell><Skeleton className="ml-auto h-4 w-10" /></TableCell>
                  <TableCell><Skeleton className="ml-auto h-4 w-10" /></TableCell>
                  <TableCell><Skeleton className="ml-auto h-4 w-16" /></TableCell>
                </TableRow>
              ))
            ) : errored ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6} className="py-8 text-center text-sm text-danger">Backend unreachable — start it, then Refresh</TableCell>
              </TableRow>
            ) : sorted.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6} className="py-8 text-center text-sm text-subtle">No scans yet</TableCell>
              </TableRow>
            ) : (
              sorted.map((scan) => (
                <TableRow key={scan.scan_id}>
                  <TableCell className="max-w-[240px] truncate font-mono text-xs text-foreground">{scan.target}</TableCell>
                  <TableCell className="font-mono text-[10px] uppercase tracking-wide2 text-subtle">{scan.target_type}</TableCell>
                  <TableCell className="whitespace-nowrap font-mono text-xs text-muted">
                    {new Date(scan.timestamp || "").toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs text-muted">{fmt100(scan.ml_score)}</TableCell>
                  <TableCell className="text-right font-mono text-xs text-muted">{fmt100(scan.baseline_score)}</TableCell>
                  <TableCell>
                    <div className="flex items-center justify-end gap-2.5">
                      <RiskMeter score={scan.baseline_score} label={bandOf(scan)} />
                      <SeverityTag score={scan.baseline_score} label={bandOf(scan)} showIcon={false} className="w-[62px] justify-end" />
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
};
