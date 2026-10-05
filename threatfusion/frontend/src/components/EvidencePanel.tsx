/**
 * EvidencePanel — what the verdict rests on (A1-7).
 *
 * "Based on 4 of 7 sources", one segment per applicable source (filled = it answered), the chips of every source
 * with their state, the sources that are missing and why — and the standing reminder that *no findings ≠ safe*.
 * Shown right under the headline so the number is never read without its evidence.
 */
import { CircleAlert, Layers } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { SourceChips } from "@/components/SourceChip";
import { evidenceCaution, summarizeEvidence } from "@/lib/evidence";
import type { ProviderOutcome } from "@/api";

export function EvidencePanel({
  outcomes,
  verdict,
  className,
}: {
  outcomes: ProviderOutcome[] | undefined;
  verdict?: "ok" | "partial" | "unknown";
  className?: string;
}) {
  const summary = summarizeEvidence(outcomes);
  const caution = evidenceCaution(verdict ?? (summary.level === "complete" ? "ok" : summary.level === "none" ? "unknown" : "partial"));
  const applicable = (outcomes ?? []).filter((o) => ["ok", "not_found", "error", "not_configured"].includes(o.status));

  return (
    <Card className={cn("flex flex-col gap-4 p-5", className)}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Layers className="size-4 text-muted" />
          <span className="text-sm font-semibold text-foreground">Evidence</span>
          <span className="tf-eyebrow ml-1">what this score rests on</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="font-mono text-sm font-semibold tabular-nums text-foreground">{summary.text}</span>
          {/* One segment per applicable source: solid = answered, hollow = missing. */}
          <div className="flex gap-1" role="img" aria-label={summary.text}>
            {applicable.map((o) => (
              <span
                key={o.source}
                className={cn("h-2 w-5 rounded-sm border border-line-strong", o.status === "ok" ? "bg-foreground" : "bg-transparent")}
              />
            ))}
          </div>
        </div>
      </div>

      {outcomes?.length ? <SourceChips outcomes={outcomes} /> : null}

      {summary.missing.length > 0 && (
        <ul className="flex flex-col gap-1 font-mono text-[11px] text-muted">
          {summary.missing.map((m) => (
            <li key={m.source}>
              <span className="text-foreground">{m.label}</span> — {m.detail}
            </li>
          ))}
        </ul>
      )}

      {caution && (
        <p className="flex items-start gap-2 border-t border-line pt-3 text-xs leading-relaxed text-muted">
          <CircleAlert className="mt-0.5 size-3.5 shrink-0 text-foreground" aria-hidden />
          <span>{caution}</span>
        </p>
      )}
    </Card>
  );
}
