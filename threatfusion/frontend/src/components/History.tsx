import React, { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  RefreshCw,
  Inbox,
  Radar,
  ShieldAlert,
  Fingerprint,
} from "lucide-react";
import { fetchHistory, type ScanHistoryItem } from "@/api";
import { cn } from "@/lib/utils";
import { resolveSeverity } from "@/lib/severity";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { RiskMeter, SeverityTag } from "@/components/RiskIndicators";

type SortKey = "target" | "timestamp" | "baseline_score" | "ml_score";
type SortDir = "asc" | "desc";

const finalScore = (s: ScanHistoryItem) => s.ml_score ?? s.baseline_score;

/** A single monochrome KPI tile. */
function Kpi({
  label,
  value,
  icon: Icon,
  hint,
}: {
  label: string;
  value: React.ReactNode;
  icon: typeof Radar;
  hint?: string;
}) {
  return (
    <div className="flex flex-col gap-2 p-4">
      <div className="flex items-center justify-between">
        <span className="tf-eyebrow">{label}</span>
        <Icon className="size-4 text-subtle" />
      </div>
      <span className="font-mono text-2xl font-semibold tabular-nums text-foreground">
        {value}
      </span>
      {hint && <span className="text-xs text-subtle">{hint}</span>}
    </div>
  );
}

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
      const data = await fetchHistory();
      setHistory(data as ScanHistoryItem[]);
    } catch (err) {
      console.error("Failed to fetch history", err);
      setErrored(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  // ── Derived summary metrics (all monochrome) ──────────────────────────
  const total = history.length;
  const highRisk = history.filter((s) => finalScore(s) >= 0.6).length;
  const uniqueTargets = new Set(history.map((s) => s.target)).size;

  // ── Client-side sort ──────────────────────────────────────────────────
  const sorted = useMemo(() => {
    const rows = [...history];
    rows.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "target") {
        cmp = a.target.localeCompare(b.target);
      } else if (sortKey === "timestamp") {
        cmp =
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      } else {
        cmp = (a[sortKey] ?? 0) - (b[sortKey] ?? 0);
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return rows;
  }, [history, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "target" ? "asc" : "desc");
    }
  };

  const SortHead = ({
    label,
    col,
    align = "left",
  }: {
    label: string;
    col: SortKey;
    align?: "left" | "right";
  }) => {
    const activeCol = sortKey === col;
    const Icon = !activeCol ? ArrowUpDown : sortDir === "asc" ? ArrowUp : ArrowDown;
    return (
      <TableHead className={align === "right" ? "text-right" : ""}>
        <button
          onClick={() => toggleSort(col)}
          className={cn(
            "inline-flex items-center gap-1.5 transition-colors hover:text-foreground",
            activeCol && "text-foreground",
            align === "right" && "flex-row-reverse"
          )}
        >
          {label}
          <Icon className="size-3" />
        </button>
      </TableHead>
    );
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col gap-5"
    >
      <div className="flex items-end justify-between">
        <div>
          <h2 className="text-xl font-semibold tracking-tight text-foreground">
            Scan History
          </h2>
          <p className="mt-1 text-sm text-muted">
            Previous engagements, newest first.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={loadHistory} disabled={loading}>
          <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {/* KPI strip */}
      <Card>
        <div className="grid grid-cols-1 divide-y divide-line sm:grid-cols-3 sm:divide-x sm:divide-y-0">
          <Kpi
            label="Total Scans"
            value={loading ? "—" : total}
            icon={Radar}
            hint="Recorded engagements"
          />
          <Kpi
            label="High Risk"
            value={loading ? "—" : highRisk}
            icon={ShieldAlert}
            hint="Score ≥ 60"
          />
          <Kpi
            label="Unique Targets"
            value={loading ? "—" : uniqueTargets}
            icon={Fingerprint}
            hint="Distinct assets"
          />
        </div>
      </Card>

      {/* Data table */}
      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <SortHead label="Target" col="target" />
              <TableHead>Type</TableHead>
              <SortHead label="Timestamp" col="timestamp" />
              <SortHead label="Baseline" col="baseline_score" align="right" />
              <SortHead label="ML Score" col="ml_score" align="right" />
              <TableHead className="text-right">Severity</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              Array.from({ length: 6 }).map((_, i) => (
                <TableRow key={i} className="hover:bg-transparent">
                  <TableCell><Skeleton className="h-4 w-40" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-14" /></TableCell>
                  <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                  <TableCell><Skeleton className="ml-auto h-4 w-10" /></TableCell>
                  <TableCell><Skeleton className="ml-auto h-4 w-10" /></TableCell>
                  <TableCell><Skeleton className="ml-auto h-4 w-20" /></TableCell>
                </TableRow>
              ))
            ) : errored ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6}>
                  <EmptyState
                    icon={ShieldAlert}
                    title="Couldn't reach the API"
                    body="Ensure the ThreatFusion backend is running on 127.0.0.1:8000, then refresh."
                  />
                </TableCell>
              </TableRow>
            ) : sorted.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6}>
                  <EmptyState
                    icon={Inbox}
                    title="No scans yet"
                    body="Run your first scan from the console to populate this table."
                  />
                </TableCell>
              </TableRow>
            ) : (
              sorted.map((scan) => {
                const sev = resolveSeverity(finalScore(scan), scan.ml_label);
                return (
                  <TableRow key={scan.scan_id}>
                    <TableCell className="max-w-[240px] truncate font-mono text-xs text-foreground">
                      {scan.target}
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-[10px] uppercase tracking-wide2 text-subtle">
                        {scan.target_type}
                      </span>
                    </TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs text-muted">
                      {new Date(scan.timestamp || "").toLocaleString("en-GB", {
                        day: "2-digit",
                        month: "short",
                        year: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-muted">
                      {(scan.baseline_score * 100).toFixed(0)}
                    </TableCell>
                    <TableCell className="text-right font-mono text-sm tabular-nums text-foreground">
                      {(finalScore(scan) * 100).toFixed(0)}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-2.5">
                        <RiskMeter score={finalScore(scan)} label={scan.ml_label} />
                        <SeverityTag
                          score={finalScore(scan)}
                          label={scan.ml_label}
                          showIcon={false}
                          className={cn("w-[62px] justify-end", sev.weight)}
                        />
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </Card>
    </motion.div>
  );
};

function EmptyState({
  icon: Icon,
  title,
  body,
}: {
  icon: typeof Inbox;
  title: string;
  body: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
      <div className="flex size-12 items-center justify-center rounded-lg border border-line bg-surface-2">
        <Icon className="size-5 text-subtle" />
      </div>
      <div>
        <p className="text-sm font-medium text-foreground">{title}</p>
        <p className="mx-auto mt-1 max-w-sm text-xs text-subtle">{body}</p>
      </div>
    </div>
  );
}
