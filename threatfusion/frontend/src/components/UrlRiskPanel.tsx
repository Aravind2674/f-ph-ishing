/**
 * UrlRiskPanel — what the calibrated URL-text models say (A2, B7).
 *
 * The models read the URL string only. The card leads with the calibrated probability *and* what it means at realistic phishing
 * prevalence, names the operating point behind the flag, shows every channel with its role (and "not available" rather than 0),
 * and lists the evidence with its unit (log-odds) plus a what-if in probability points. Monochrome: the flag is a solid badge +
 * wording + a heavier border; direction is "raises" / "lowers" in words and an arrow, never colour.
 */
import { ArrowDown, ArrowUp, Binary } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { urlRiskView } from "@/lib/urlrisk";
import type { RiskExplanation, UrlRiskAssessment } from "@/api";

export function UrlRiskPanel({ risk, evidence }: { risk: UrlRiskAssessment | null | undefined; evidence: RiskExplanation[] }) {
  const view = urlRiskView(risk, evidence);
  if (!view) return null;

  return (
    <Card className={cn("flex flex-col gap-4 p-5", view.flagged && "border-2 border-foreground")}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Binary className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">URL text analysis</span>
            <span className="tf-eyebrow ml-1">calibrated · reads the URL string only</span>
          </div>
          <p className={cn("mt-1 text-sm", view.flagged ? "font-semibold text-foreground" : "text-muted")}>{view.verdict}</p>
          <p className="mt-0.5 text-xs text-subtle">{view.basis}</p>
        </div>
        <div className="flex items-baseline gap-3">
          <span className="font-mono text-4xl font-semibold tabular-nums leading-none text-foreground">{view.scoreText}</span>
          <Badge variant={view.flagged ? "solid" : "outline"}>{view.flagged ? "Flagged" : "Not flagged"}</Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {view.channels.map((c) => (
          <div key={c.key} className={cn("rounded-md border p-3", c.headline ? "border-foreground" : "border-line")}>
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-xs font-semibold text-foreground">{c.label}</span>
              <span className={cn("font-mono text-sm tabular-nums", c.value === "not available" ? "italic text-subtle" : "text-foreground")}>{c.value}</span>
            </div>
            <p className="mt-1 text-[11px] leading-snug text-subtle">{c.role}</p>
          </div>
        ))}
      </div>

      {view.prevalence.length > 0 && (
        <p className="font-mono text-[11px] text-muted">
          This score means: {view.prevalence.map((p) => `${p.label} → ${p.value}`).join(" · ")}
        </p>
      )}

      {view.evidence.length > 0 && (
        <div className="flex flex-col gap-1.5 border-t border-line pt-3">
          <span className="tf-eyebrow">Evidence (log-odds in the tree model's raw score)</span>
          <ul className="flex flex-col gap-1.5">
            {view.evidence.map((e) => (
              <li key={e.feature} className="flex flex-col gap-0.5 text-xs">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  {e.direction === "raises" ? <ArrowUp className="size-3 text-foreground" /> : <ArrowDown className="size-3 text-subtle" />}
                  <span className="text-foreground">{e.text}</span>
                  <span className="font-mono text-[11px] text-muted">{e.logOdds}</span>
                  {e.group && <span className="font-mono text-[10px] uppercase tracking-wide2 text-subtle">{e.group}</span>}
                </div>
                {e.whatIf && <span className="pl-5 text-[11px] text-subtle">{e.whatIf}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {view.rules.length > 0 && (
        <div className="flex flex-col gap-1 border-t border-line pt-3">
          <span className="tf-eyebrow">Baseline rules that fired</span>
          <ul className="flex flex-col gap-0.5 font-mono text-[11px] text-muted">
            {view.rules.map((r) => (
              <li key={r.text}>
                {r.weight} · {r.text}
              </li>
            ))}
          </ul>
        </div>
      )}

      {view.notes.map((n) => (
        <p key={n} className="text-xs text-subtle">{n}</p>
      ))}
      <p className="border-t border-line pt-2 font-mono text-[10px] text-subtle">{view.model}</p>
    </Card>
  );
}
