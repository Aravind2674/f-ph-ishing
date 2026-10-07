/** Is this host pretending to be a known brand? A local check: a flag shows its evidence and the brand's real domain; "no match" is never worded as safe. */
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { lookalikeView } from "@/lib/lookalike";
import type { BrandCheck } from "@/api";

export function LookalikePanel({ check }: { check: BrandCheck | null | undefined }) {
  const view = lookalikeView(check);
  if (!view) return null;
  const flagged = view.status === "lookalike";

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className={cn("text-sm", flagged ? "font-semibold text-danger" : "text-muted")}>{view.headline}</p>
          {view.detail && <p className="mt-0.5 text-xs text-subtle">{view.detail}</p>}
        </div>
        <Badge variant={flagged ? "solid" : "outline"}>{flagged ? "Look-alike" : view.status === "official" ? "Official" : "No match"}</Badge>
      </div>

      {view.match && (
        <div className="flex flex-col gap-2">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 font-mono text-xs">
            <dt className="text-subtle">Imitates</dt>
            <dd className="text-foreground">{view.match.brand} <span className="text-subtle">({view.match.sector})</span></dd>
            <dt className="text-subtle">Real domain</dt>
            <dd className="text-foreground">{view.match.domain}</dd>
            <dt className="text-subtle">Trick</dt>
            <dd className="text-foreground">{view.match.kind} <span className="text-subtle">· {view.match.rule}</span></dd>
            {view.match.mixedScript && (
              <>
                <dt className="text-subtle">Scripts</dt>
                <dd className="text-warn">Mixes alphabets</dd>
              </>
            )}
          </dl>
          <ul className="flex flex-col gap-1 text-xs text-muted">
            {view.match.evidence.map((e) => (
              <li key={e}>— {e}</li>
            ))}
          </ul>
        </div>
      )}

      {view.candidates.length > 0 && (
        <p className="text-xs text-muted">Weaker: {view.candidates.map((c) => `${c.brand} — ${c.kind} (${c.rule})`).join("; ")}</p>
      )}
      {view.notes.map((n) => (
        <p key={n} className="text-xs text-subtle">{n}</p>
      ))}
      <p className="font-mono text-[11px] text-subtle">{view.coverage}</p>
    </div>
  );
}
