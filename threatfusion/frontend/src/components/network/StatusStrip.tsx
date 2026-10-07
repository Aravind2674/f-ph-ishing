/**
 * The top of the Network view: what the capture is doing, in one line, with the reason and the fix when it is not capturing.
 * No decorative widgets: when capture cannot work, this strip is the whole story.
 */
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { type CaptureView, type SensorRow, connectionView } from "@/lib/network";
import { StatusDot } from "./parts";

interface Props {
  view: CaptureView;
  sensors: SensorRow[];
  connected: boolean;
  everConnected: boolean;
  busy: boolean;
  onStart: () => void;
  onStop: () => void;
}

function Figure({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-[11px] uppercase tracking-wide text-subtle">{label}</span>
      <span className="font-mono text-sm tabular-nums text-foreground">{value}</span>
    </div>
  );
}

export function StatusStrip({ view, sensors, connected, everConnected, busy, onStart, onStop }: Props) {
  const live = connectionView(connected, everConnected);
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <StatusDot tone={view.tone} label={view.label} className="text-base" />
        {view.running && (
          <>
            <Figure label="Interface" value={view.interfaceName ?? "—"} />
            <Figure label="Rate" value={view.rate} />
            <Figure label="Packets" value={view.packets} />
            <Figure label="Dropped" value={view.dropped} />
          </>
        )}
        <div className="ml-auto flex items-center gap-4">
          <StatusDot tone={live.tone} label={live.label} className="text-xs font-normal" />
          {view.running ? (
            <Button variant="outline" size="sm" disabled={busy || !view.canStop} onClick={onStop}>Stop</Button>
          ) : (
            <Button size="sm" disabled={busy || !view.canStart} onClick={onStart}>{view.startLabel}</Button>
          )}
        </div>
      </div>

      {view.reason && (
        <div className="mt-3 border-t border-line pt-3 text-sm">
          <p className="text-foreground">{view.reason}</p>
          {view.fix && <p className={cn("mt-1", view.tone === "bad" ? "text-danger" : "text-muted")}>{view.fix}</p>}
        </div>
      )}

      {view.running && sensors.length > 0 && (
        <details className="mt-3 border-t border-line pt-3">
          <summary className="cursor-pointer text-xs uppercase tracking-wide text-subtle">Sensors</summary>
          <table className="mt-2 w-full text-sm">
            <tbody>
              {sensors.map((s) => (
                <tr key={s.name} className="border-t border-line first:border-0">
                  <td className="py-1.5 pr-4"><StatusDot tone={s.tone} label={s.label} className="text-sm font-normal text-foreground" /></td>
                  <td className="py-1.5 pr-4 text-muted">{s.state}</td>
                  <td className="py-1.5 pr-4 text-right font-mono tabular-nums text-muted">{s.packets}</td>
                  <td className="py-1.5 pr-4 text-right font-mono tabular-nums text-muted">{s.events}</td>
                  <td className="py-1.5 text-xs text-muted">{s.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-1 text-[11px] text-subtle">packets · events per sensor</p>
        </details>
      )}
    </div>
  );
}
