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
            <TableHead>Device</TableHead>
            <TableHead>IP</TableHead>
            <TableHead className="text-right">DNS seen</TableHead>
            <TableHead className="text-right">Domains</TableHead>
            <TableHead>First seen</TableHead>
            <TableHead>Last seen</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {devices.map((d) => (
            <TableRow key={d.mac}>
              <TableCell className="font-mono text-xs">{d.hostname || d.mac}</TableCell>
              <TableCell className="font-mono text-xs">{d.ip ?? "—"}</TableCell>
              <TableCell className="text-right font-mono tabular-nums">{d.dns_observations.toLocaleString("en-US")}</TableCell>
              <TableCell className="text-right font-mono tabular-nums">{d.distinct_domains.toLocaleString("en-US")}</TableCell>
              <TableCell className="whitespace-nowrap text-xs text-muted">{timeAgo(d.first_seen)}</TableCell>
              <TableCell className="whitespace-nowrap text-xs text-muted">{timeAgo(d.last_seen)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
