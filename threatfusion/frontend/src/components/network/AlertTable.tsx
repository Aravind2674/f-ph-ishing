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
      <div className="flex flex-wrap items-center justify-between gap-3">
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
      </div>
      
      {rows.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted">{alerts.length === 0 ? "No alerts" : `No ${filter.toLowerCase()} alerts`}</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Device Info</TableHead>
                <TableHead>Packets</TableHead>
                <TableHead>Website / Packet Info</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => {
                const primaryDevice = r.deviceName || r.deviceMac || r.fallbackDevice;
                return (
                  <TableRow key={r.id} className="cursor-pointer" onClick={() => onOpen(byId.get(r.id)!)} tabIndex={0}
                    onKeyDown={(e) => { if (e.key === "Enter") onOpen(byId.get(r.id)!); }}>
                    <TableCell className="whitespace-nowrap">
                      <div className="flex flex-col gap-1.5 items-start">
                        <SeverityBadge severity={r.severity} />
                        <span className="font-mono text-xs text-muted" title={new Date(r.time).toLocaleString()}>{timeAgo(r.time)}</span>
                      </div>
                    </TableCell>
                    
                    <TableCell className="whitespace-nowrap">
                      <div className="flex flex-col gap-0.5">
                        <span className="font-medium text-sm text-foreground">{primaryDevice}</span>
                        {r.deviceName && r.deviceMac && <span className="font-mono text-[10px] text-muted">MAC: {r.deviceMac}</span>}
                        {r.deviceIp && <span className="font-mono text-[10px] text-muted">IP: {r.deviceIp}</span>}
                      </div>
                    </TableCell>

                    <TableCell className="font-mono text-xs tabular-nums text-muted">
                      {r.packets}
                    </TableCell>
                    
                    <TableCell className="max-w-[420px]">
                      <div className="flex flex-col gap-0.5">
                        <span className="truncate text-sm font-medium text-foreground">{r.target ? r.target : r.type}</span>
                        <span className="truncate text-xs text-muted" title={r.summary}>{r.summary}</span>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
