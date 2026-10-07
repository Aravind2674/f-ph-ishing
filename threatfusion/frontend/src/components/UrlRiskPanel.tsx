/** The calibrated URL-text models: the headline probability, the flag and its operating point, each channel, and what the score means at realistic prevalence. */
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { urlRiskView } from "@/lib/urlrisk";
import type { UrlRiskAssessment } from "@/api";

export function UrlRiskPanel({ risk }: { risk: UrlRiskAssessment | null | undefined }) {
  const view = urlRiskView(risk);
  if (!view) return null;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <p className={cn("text-sm", view.flagged ? "font-semibold text-danger" : "text-muted")}>{view.verdict}</p>
          {view.basis && <p className="mt-0.5 font-mono text-xs text-subtle">{view.basis}</p>}
        </div>
        <div className="flex items-baseline gap-3">
          <span className="font-mono text-2xl font-semibold text-foreground">{view.scoreText}</span>
          <Badge variant={view.flagged ? "solid" : "outline"}>{view.flagged ? "Flagged" : "Not flagged"}</Badge>
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-1 font-mono text-xs sm:grid-cols-4">
        {view.channels.map((c) => (
          <div key={c.key} className="flex items-baseline justify-between gap-2 border-b border-line py-1">
            <dt className={cn(c.headline ? "text-foreground" : "text-subtle")}>{c.label}</dt>
            <dd className={cn(c.value === "not available" ? "italic text-subtle" : "text-foreground")}>{c.value}</dd>
          </div>
        ))}
      </dl>

      {view.prevalence.length > 0 && (
        <p className="font-mono text-xs text-muted">{view.prevalence.map((p) => `${p.label} → ${p.value}`).join(" · ")}</p>
      )}

      {view.rules.length > 0 && (
        <ul className="flex flex-col gap-0.5 font-mono text-xs text-muted">
          {view.rules.map((r) => (
            <li key={r.text}>
              {r.weight} · {r.text}
            </li>
          ))}
        </ul>
      )}

      {view.notes.map((n) => (
        <p key={n} className="text-xs text-subtle">{n}</p>
      ))}
      <p className="font-mono text-[11px] text-subtle">{view.model}</p>
    </div>
  );
}
