/**
 * LookalikePanel — is this domain pretending to be a well-known brand? (B4)
 *
 * A local, deterministic check, so the card shows *why* it matched (the substitutions / edits) and *what was compared* — and a
 * clean result is worded as "no resemblance found", never "safe". Kept separate from the maliciousness scores: a freshly
 * registered impersonator can have no external reputation at all. Monochrome: a flag is a solid badge + wording + a heavier
 * border, a genuine brand domain a quiet outline badge.
 */
import { BadgeCheck, Fingerprint } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { lookalikeView } from "@/lib/lookalike";
import type { BrandCheck } from "@/api";

export function LookalikePanel({ check }: { check: BrandCheck | null | undefined }) {
  const view = lookalikeView(check);
  if (!view) return null;
  const flagged = view.status === "lookalike";
  const Icon = view.status === "official" ? BadgeCheck : Fingerprint;

  return (
    <Card className={cn("flex flex-col gap-3 p-5", flagged && "border-2 border-foreground")}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Icon className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">Brand impersonation</span>
            <span className="tf-eyebrow ml-1">local check · separate from the maliciousness score</span>
          </div>
          <p className={cn("mt-1 text-sm", flagged ? "font-semibold text-foreground" : "text-muted")}>{view.headline}</p>
          <p className="mt-0.5 max-w-xl text-xs text-subtle">{view.detail}</p>
        </div>
        <Badge variant={flagged ? "solid" : "outline"}>
          {flagged ? "Look-alike" : view.status === "official" ? "Official domain" : "No match"}
        </Badge>
      </div>

      {view.match && (
        <div className="flex flex-col gap-2 border-t border-line pt-3">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 font-mono text-[11px]">
            <dt className="text-subtle">Impersonates</dt>
            <dd className="text-foreground">{view.match.brand} <span className="text-subtle">({view.match.sector})</span></dd>
            <dt className="text-subtle">Real domain</dt>
            <dd className="text-foreground">{view.match.domain}</dd>
            <dt className="text-subtle">Trick</dt>
            <dd className="text-foreground">{view.match.kind} <span className="text-subtle">· {view.match.rule}</span></dd>
            {view.match.mixedScript && (
              <>
                <dt className="text-subtle">Scripts</dt>
                <dd className="text-foreground">mixes alphabets (homograph signature)</dd>
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
        <p className="text-xs text-muted">
          Weaker resemblances (below the flag threshold):{" "}
          {view.candidates.map((c) => `${c.brand} — ${c.kind} (${c.rule})`).join("; ")}
        </p>
      )}
      {view.notes.map((n) => (
        <p key={n} className="text-xs text-subtle">{n}</p>
      ))}
      <p className="border-t border-line pt-2 font-mono text-[11px] text-subtle">{view.coverage}</p>
    </Card>
  );
}
