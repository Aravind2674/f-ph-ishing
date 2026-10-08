import { useEffect, useState, useRef } from "react";
import { subscribePackets, type SensorEvent } from "@/api";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

import type { DeviceProfile } from "@/api";

export function PacketTable({ running, devices }: { running: boolean; devices: DeviceProfile[] }) {
  const [packets, setPackets] = useState<SensorEvent[]>([]);
  const subRef = useRef<{ close: () => void } | null>(null);

  useEffect(() => {
    if (!running) {
      if (subRef.current) {
        subRef.current.close();
        subRef.current = null;
      }
      return;
    }

    if (!subRef.current) {
      subRef.current = subscribePackets((packet) => {
        setPackets((prev) => {
          const next = [packet, ...prev];
          if (next.length > 500) next.length = 500;
          return next;
        });
      });
    }

    return () => {
      if (subRef.current) {
        subRef.current.close();
        subRef.current = null;
      }
    };
  }, [running]);

  const clear = () => setPackets([]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-foreground">Live Packet / Connection Log</h3>
        <div className="flex items-center gap-2">
          {running ? (
            <span className="flex items-center gap-1.5 text-xs font-medium text-ok">
              <span className="size-1.5 animate-pulse rounded-full bg-ok" /> Streaming
            </span>
          ) : (
            <span className="text-xs text-muted">Paused</span>
          )}
          <button onClick={clear} className="text-xs text-muted hover:text-foreground">Clear</button>
        </div>
      </div>
      <div className="overflow-x-auto rounded-lg border border-line h-[500px] overflow-y-auto bg-surface-2/30">
        <Table>
          <TableHeader className="sticky top-0 bg-surface z-10 shadow-sm">
            <TableRow>
              <TableHead className="w-[100px]">Time</TableHead>
              <TableHead>Sensor</TableHead>
              <TableHead>Device Info</TableHead>
              <TableHead>Destination (Website)</TableHead>
              <TableHead>Details</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {packets.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-sm text-muted">
                  {running ? "Waiting for traffic..." : "Capture is stopped."}
                </TableCell>
              </TableRow>
            ) : (
              packets.map((p, i) => {
                const domain = p.domain || p.raw.sni || p.raw.qname || "—";
                const device = devices.find(d => (p.mac && d.mac === p.mac) || (p.ip && d.ip === p.ip));
                const primaryName = device?.hostname || p.mac || p.ip || "—";
                
                return (
                  <TableRow key={`${p.timestamp}-${i}`} className="border-line/50">
                    <TableCell className="whitespace-nowrap font-mono text-xs text-muted">
                      {p.timestamp.split("T")[1]?.slice(0, 8) || p.timestamp}
                    </TableCell>
                    <TableCell>
                      <Badge variant="subtle" className="text-[10px]">{p.sensor}</Badge>
                    </TableCell>
                    <TableCell className="whitespace-nowrap">
                      <div className="flex flex-col gap-0.5">
                        <span className="font-medium text-sm text-foreground">{primaryName}</span>
                        {p.mac && <span className="font-mono text-[10px] text-muted">MAC: {p.mac}</span>}
                        {p.ip && <span className="font-mono text-[10px] text-muted">IP: {p.ip}</span>}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-[200px] truncate text-foreground font-medium text-sm" title={domain}>
                      {domain}
                    </TableCell>
                    <TableCell className="max-w-[300px] truncate text-muted font-mono text-xs" title={JSON.stringify(p.raw)}>
                      {p.event_type}
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
