import type { DeviceProfile } from "@/api";
import { timeAgo } from "@/lib/utils";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function DeviceTable({ devices }: { devices: DeviceProfile[] }) {
  if (devices.length === 0) return <p className="py-8 text-center text-sm text-muted">No devices seen yet</p>;
  return (
    <div className="overflow-x-auto rounded-lg border border-line">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Device Info</TableHead>
            <TableHead>Network Activity</TableHead>
            <TableHead>Time</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {devices.map((d) => {
            const packets = (d as any).packets ?? d.dns_observations;
            return (
              <TableRow key={d.mac}>
                <TableCell className="whitespace-nowrap">
                  <div className="flex flex-col gap-0.5">
                    <span className="font-medium text-sm text-foreground">{d.hostname || d.mac}</span>
                    {d.hostname && d.mac && <span className="font-mono text-[10px] text-muted">MAC: {d.mac}</span>}
                    {d.ip && <span className="font-mono text-[10px] text-muted">IP: {d.ip}</span>}
                  </div>
                </TableCell>
                <TableCell className="max-w-[420px]">
                  <div className="flex flex-col gap-0.5">
                    <span className="truncate text-sm font-medium text-foreground">
                      {packets.toLocaleString("en-US")} packets · {d.distinct_domains.toLocaleString("en-US")} domains
                    </span>
                    <span className="truncate text-xs text-muted" title={d.top_domains.join(", ")}>
                      {d.top_domains.length ? d.top_domains.slice(0, 3).join(", ") + (d.top_domains.length > 3 ? "..." : "") : "No destinations"}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="whitespace-nowrap">
                  <div className="flex flex-col gap-0.5">
                    <span className="text-xs text-foreground">Seen: {timeAgo(d.last_seen)}</span>
                    <span className="text-[10px] text-muted">First: {timeAgo(d.first_seen)}</span>
                  </div>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
