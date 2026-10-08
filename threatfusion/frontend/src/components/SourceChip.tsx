/**
 * SourceChip — one provider's state as a chip (A1-7).
 *
 * The UI is strictly monochrome, so state is carried by **icon + wording + border style**, never by colour:
 *   ok            solid border, check mark          "ok"
 *   running       pulsing dot, solid border          "running"
 *   pending       dashed border, empty circle        "waiting"
 *   no record     dotted border, question mark       "no record"   (answered, but nothing on this target)
 *   failed        solid border, alert icon           "failed"      (+ the reason in plain words)
 *   skipped       dashed border, minus               "skipped"
 *   not configured dotted border, key                "not configured"
 * Hover/focus shows the full detail (reason, cache, latency).
 */
import { Check, CircleAlert, CircleHelp, KeyRound, Minus, Circle } from "lucide-react";
import { cn } from "@/lib/utils";
import { humanReason, sourceLabel, visibleOutcomes, type ChipState } from "@/lib/evidence";
import type { ProviderOutcome } from "@/api";

const WORD: Record<ChipState, string> = {
  ok: "ok",
  running: "running",
  pending: "waiting",
  not_found: "no record",
  error: "failed",
  skipped: "skipped",
  not_configured: "not configured",
};

const BORDER: Record<ChipState, string> = {
  ok: "border-line-strong bg-foreground/[0.06] text-foreground",
  running: "border-line-strong text-foreground",
  pending: "border-dashed border-line text-subtle",
  not_found: "border-dotted border-line-strong text-muted",
  error: "border-line-strong text-foreground",
  skipped: "border-dashed border-line text-subtle",
  not_configured: "border-dotted border-line-strong text-muted",
};

function StateIcon({ state }: { state: ChipState }) {
  const cls = "size-3 shrink-0";
  switch (state) {
    case "ok": return <Check className={cls} aria-hidden />;
    case "running": return <span className="size-1.5 shrink-0 animate-pulse rounded-full bg-foreground" aria-hidden />;
    case "pending": return <Circle className={cls} aria-hidden />;
    case "not_found": return <CircleHelp className={cls} aria-hidden />;
    case "error": return <CircleAlert className={cls} aria-hidden />;
    case "skipped": return <Minus className={cls} aria-hidden />;
    case "not_configured": return <KeyRound className={cls} aria-hidden />;
  }
}

export interface SourceChipProps {
  source: string;
  state: ChipState;
  reason?: string | null;
  retryAfter?: number | null;
  cached?: boolean;
  latencyMs?: number | null;
  /** Show the plain-words reason next to the chip (e.g. "Timed out"). */
  showReason?: boolean;
  className?: string;
}

export function SourceChip({ source, state, reason, retryAfter, cached, latencyMs, showReason = true, className }: SourceChipProps) {
  const why = humanReason(reason, retryAfter);
  const detail = [
    `${sourceLabel(source)}: ${WORD[state]}`,
    why,
    cached ? "served from the local cache" : null,
    latencyMs != null ? `${Math.round(latencyMs)} ms` : null,
  ].filter(Boolean).join(" · ");
  const inlineWhy = showReason && why && (state === "error" || state === "skipped" || state === "not_found" || state === "not_configured");
  return (
    <span
      title={detail}
      aria-label={detail}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[11px] leading-none",
        BORDER[state],
        className,
      )}
    >
      <StateIcon state={state} />
      <span className="font-medium">{sourceLabel(source)}</span>
      <span className="text-subtle">· {WORD[state]}</span>
      {inlineWhy && <span className="text-subtle">· {why}</span>}
      {cached && state === "ok" && <span className="text-subtle">· cached</span>}
    </span>
  );
}

/** All providers of a finished scan, in the backend's stable order. */
export function SourceChips({ outcomes, className }: { outcomes: ProviderOutcome[]; className?: string }) {
  return (
    <div className={cn("flex flex-wrap gap-2", className)}>
      {visibleOutcomes(outcomes).map((o) => (
        <SourceChip
          key={o.source}
          source={o.source}
          state={o.status as ChipState}
          reason={o.reason}
          retryAfter={o.retry_after}
          cached={o.cached}
          latencyMs={o.latency_ms}
        />
      ))}
    </div>
  );
}
