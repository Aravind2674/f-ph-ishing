import { useState } from "react";
import type { AccessPointRow } from "@/api";
import { timeAgo } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface Props {
  aps: AccessPointRow[];
  error: string | null;
  fix: string | null;
  onMark: (bssid: string, known: boolean) => Promise<void>;
}

export function AccessPointTable({ aps, error, fix, onMark }: Props) {
  const [busy, setBusy] = useState<string | null>(null);
  const [onlyWatched, setOnlyWatched] = useState(true);
  const shown = onlyWatched ? aps.filter((a) => a.watched || a.flagged || a.known) : aps;

  const mark = async (a: AccessPointRow) => {
    setBusy(a.bssid);
    try {
      await onMark(a.bssid, !a.known);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      {error && (
        <div className="rounded-lg border border-danger/40 p-3 text-sm">
          <p className="text-foreground">{error}</p>
          {fix && <p className="mt-1 text-danger">{fix}</p>}
        </div>
      )}
      <label className="flex items-center gap-2 text-xs text-muted">
        <input type="checkbox" checked={onlyWatched} onChange={(e) => setOnlyWatched(e.target.checked)} />
        Watched networks only (connected + NETWORK_MONITORED_SSIDS)
      </label>
      {shown.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted">{aps.length === 0 ? "No access points seen yet" : "No access points on a watched network"}</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Network</TableHead>
                <TableHead>BSSID</TableHead>
                <TableHead>Security</TableHead>
                <TableHead>Channels</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Status</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((a) => (
                <TableRow key={a.bssid}>
                  <TableCell className="text-sm">{a.ssid || "(hidden)"}</TableCell>
                  <TableCell className="font-mono text-xs">{a.bssid}</TableCell>
                  <TableCell className="text-xs">{a.security ?? "—"}</TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">{a.channels.length ? a.channels.join(", ") : "—"}</TableCell>
                  <TableCell className="whitespace-nowrap text-xs text-muted">{timeAgo(a.last_seen)}</TableCell>
                  <TableCell className="whitespace-nowrap text-xs">
                    {a.flagged && !a.known ? <span className="text-danger">Reported</span> : a.known ? <span className="text-ok">Known</span> : a.watched ? "Watched" : <span className="text-subtle">Not watched</span>}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" disabled={busy === a.bssid} onClick={() => mark(a)}>
                      {a.known ? "Unmark" : "Mark known"}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
