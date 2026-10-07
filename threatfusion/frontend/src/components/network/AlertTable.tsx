import { useMemo, useState } from "react";
import type { NetworkAlert, NetworkSeverity } from "@/api";
import { alertRows } from "@/lib/network";
import { timeAgo } from "@/lib/utils";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "./parts";

const FILTERS: (NetworkSeverity | "All")[] = ["All", "Critical", "High", "Medium", "Low"];

export function AlertTable({ alerts, onOpen }: { alerts: NetworkAlert[]; onOpen: (alert: NetworkAlert) => void }) {
  const [filter, setFilter] = useState<NetworkSeverity | "All">("All");
  const rows = useMemo(() => alertRows(alerts, filter), [alerts, filter]);
  const byId = useMemo(() => new Map(alerts.map((a) => [a.alert_id, a])), [alerts]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by severity">
        {FILTERS.map((f) => (
          <button
            key={f}
            type="button"
            onClick={() => setFilter(f)}
            aria-pressed={filter === f}
            className={`rounded border px-2.5 py-1 text-xs ${filter === f ? "border-foreground text-foreground" : "border-line text-muted hover:text-foreground"}`}
          >
            {f}
          </button>
        ))}
      </div>
      {rows.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted">{alerts.length === 0 ? "No alerts" : `No ${filter.toLowerCase()} alerts`}</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Device</TableHead>
                <TableHead>Summary</TableHead>
                <TableHead className="text-right">Score</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.id} className="cursor-pointer" onClick={() => onOpen(byId.get(r.id)!)} tabIndex={0}
                  onKeyDown={(e) => { if (e.key === "Enter") onOpen(byId.get(r.id)!); }}>
                  <TableCell className="whitespace-nowrap font-mono text-xs text-muted" title={new Date(r.time).toLocaleString()}>{timeAgo(r.time)}</TableCell>
                  <TableCell><SeverityBadge severity={r.severity} /></TableCell>
                  <TableCell className="whitespace-nowrap text-sm">{r.type}</TableCell>
                  <TableCell className="font-mono text-xs">{r.device}</TableCell>
                  <TableCell className="max-w-[420px] truncate text-sm" title={r.summary}>{r.summary}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums">{r.score}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
