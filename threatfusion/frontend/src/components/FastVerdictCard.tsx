/** The first answer, from local data only, shown while the full scan runs. "Nothing found" is never worded as safe. */
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { fastView } from "@/lib/fast";
import type { FastVerdict } from "@/api";

const BADGE = { block: "Listed", warn: "Suspicious", info: "Official", none: "Nothing found" } as const;

export function FastVerdictCard({ verdict, running }: { verdict: FastVerdict | null | undefined; running: boolean }) {
  const view = fastView(verdict, running);
  if (!view) return null;
  const alarm = view.level === "block" || view.level === "warn";
  return (
    <div className={cn("flex flex-col gap-2 rounded-lg border bg-surface p-4", view.level === "block" ? "border-danger" : view.level === "warn" ? "border-warn" : "border-line")}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className={cn("text-sm", alarm ? "font-semibold text-foreground" : "text-muted")}>{view.headline}</span>
        <Badge variant={alarm ? "solid" : "outline"}>{BADGE[view.level]}</Badge>
      </div>
      {view.reasons.length > 0 && (
        <ul className="flex flex-col gap-0.5 text-xs text-muted">
          {view.reasons.map((r) => (
            <li key={r}>— {r}</li>
          ))}
        </ul>
      )}
      {view.chips.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {view.chips.map((c) => (
            <span key={c} className="rounded border border-line px-1.5 py-0.5 font-mono text-[11px] text-muted">{c}</span>
          ))}
        </div>
      )}
      <p className="font-mono text-xs text-subtle">
        {view.caption} · {view.slowTierNote}
      </p>
    </div>
  );
}
