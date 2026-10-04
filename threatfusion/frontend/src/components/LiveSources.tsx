/**
 * LiveSources — per-source status chips while a scan is running (A1-7).
 *
 * Folded from the backend's Server-Sent Events (`GET /scan/{id}/events`, see lib/evidence.ts). Providers run
 * concurrently, so chips flip from "waiting" to "running" together and finish independently; conditional providers
 * (NVD, endoflife.date) appear when they start. If the event stream is unavailable the parent simply shows no chips —
 * the scan itself is unaffected.
 */
import { SourceChip } from "@/components/SourceChip";
import type { LiveState } from "@/lib/evidence";

const STAGES: Record<string, string> = {
  features: "Building features…",
  scoring: "Scoring…",
};

export function LiveSources({ live }: { live: LiveState }) {
  if (!live.order.length) return null;
  const total = live.order.length;
  const finished = live.order.filter((s) => !["pending", "running"].includes(live.chips[s].status)).length;
  return (
    <div className="flex flex-col gap-3" aria-live="polite">
      <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] uppercase tracking-wide2 text-subtle">
        <span>
          {finished} of {total} sources done
        </span>
        {live.stage && <span>· {STAGES[live.stage] ?? live.stage}</span>}
      </div>
      <div className="flex flex-wrap gap-2">
        {live.order.map((source) => {
          const chip = live.chips[source];
          return (
            <SourceChip key={source} source={source} state={chip.status} reason={chip.reason} retryAfter={chip.retry_after}
              cached={chip.cached} latencyMs={chip.latency_ms} />
          );
        })}
      </div>
    </div>
  );
}
