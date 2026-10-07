/** One network alert: the fused score, every signal that moved it (degraded ones included), the web-reputation sub-score, WiGLE history, the device baseline and raw evidence. */
import { useState, type ReactNode } from "react";
import type { NetworkAlert, SignalContribution } from "@/api";
import { cn } from "@/lib/utils";
import { alertTypeLabel } from "@/lib/network";
import { verdictView } from "@/lib/verdict";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityTag } from "@/components/RiskIndicators";
import { RiskScorePanel } from "@/components/RiskScorePanel";

interface Props {
  alert: NetworkAlert;
  onBack: () => void;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="flex flex-col gap-4 p-5">
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      {children}
    </Card>
  );
}

export function NetworkAlertDetail({ alert, onBack }: Props) {
  const ev = alert.evidence;
  const app = ev.app_layer;
  const wigle = ev.wigle;
  const baseline = ev.baseline;

  return (
    <div className="flex flex-col gap-5">
      <div>
        <Button variant="outline" size="sm" onClick={onBack} className="mb-4">
          Back
        </Button>
        <div className="flex flex-col gap-4 border-b border-line pb-5 sm:flex-row sm:items-end sm:justify-between">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-3">
              <SeverityTag score={alert.fused_score / 100} label={alert.severity} />
              <Badge variant="subtle">{alertTypeLabel(alert.alert_type)}</Badge>
              <span className="font-mono text-xs text-subtle">{alert.alert_id.slice(0, 8).toUpperCase()}</span>
            </div>
            <h2 className="break-words text-xl font-semibold tracking-tight text-foreground">{alert.title}</h2>
            <p className="mt-1 text-sm text-muted">{alert.trigger_type}</p>
            <p className="mt-1 font-mono text-xs text-subtle">{new Date(alert.timestamp).toLocaleString()}</p>
          </div>
          <div className="flex shrink-0 flex-col sm:items-end">
            <div className="flex items-baseline gap-1.5">
              <span className="font-mono text-4xl font-semibold leading-none text-foreground">{Math.round(alert.fused_score)}</span>
              <span className="font-mono text-xs text-subtle">/ 100</span>
            </div>
            <span className="mt-1 tf-eyebrow">Fused score</span>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {alert.involved.map((x) => (
          <span key={x} className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-[11px] text-muted">
            {x}
          </span>
        ))}
      </div>

      <Section title="Score breakdown">
        <SignalBars signals={ev.signals} />
      </Section>

      {app && (
        <Section title="Web reputation">
          {app.available ? (
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-mono text-foreground">{app.target}</span>
                <Badge variant={app.flagged ? "solid" : "outline"}>{app.flagged ? "Flagged" : "Not flagged"}</Badge>
              </div>
              <RiskScorePanel
                showHeadline={false}
                view={verdictView({
                  baseline_score: app.baseline_score ?? null, baseline_label: null, ml_score: app.ml_score ?? null, ml_label: app.ml_label ?? "Unknown",
                  headline_band: null, driven_by: null, agreement: null, baseline_terms: [], url_risk: null,
                })}
              />
              {typeof app.vt_malicious_count === "number" && (
                <p className="font-mono text-xs text-subtle">
                  VirusTotal: {app.vt_malicious_count} / {app.vt_total_engines} engines malicious
                </p>
              )}
              {app.top_explanations.length > 0 && (
                <ul className="flex flex-col gap-1 text-xs text-muted">
                  {app.top_explanations.map((e, i) => (
                    <li key={i}>· {e}</li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <Degraded reason={app.reason} label="Lookup unavailable" />
          )}
        </Section>
      )}

      {wigle && (
        <Section title="WiGLE history">
          {wigle.available ? (
            <div className="flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-mono text-foreground">{wigle.bssid}</span>
                <Badge variant={wigle.found ? "outline" : "solid"}>{wigle.found ? "Publicly known" : "Never publicly seen"}</Badge>
              </div>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <Stat label="Observations" value={wigle.total_observations} />
                <Stat label="First seen" value={wigle.first_seen ?? "—"} />
                <Stat label="Last seen" value={wigle.last_seen ?? "—"} />
              </div>
              {wigle.known_ssids.length > 0 && <p className="font-mono text-xs text-subtle">Known SSIDs: {wigle.known_ssids.join(", ")}</p>}
            </div>
          ) : (
            <Degraded reason={wigle.reason} label="Lookup unavailable" />
          )}
        </Section>
      )}

      {baseline && (
        <Section title="Device baseline">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Observations" value={baseline.observations} />
            <Stat label="Known domains" value={baseline.known_domain_count} />
            <Stat label="Baseline" value={baseline.established ? "Established" : "Learning"} />
            <Stat label="This domain" value={baseline.is_new_domain ? "New" : "Known"} />
          </div>
          <p className="text-sm text-muted">{baseline.deviation_detail}</p>
          {baseline.known_domains_sample.length > 0 && (
            <div className="flex flex-col gap-1.5">
              <span className="tf-eyebrow">Usually contacts</span>
              <div className="flex flex-wrap gap-1.5">
                {baseline.known_domains_sample.map((d) => (
                  <span key={d} className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-[11px] text-muted">
                    {d}
                  </span>
                ))}
              </div>
            </div>
          )}
        </Section>
      )}

      {alert.recommended_actions.length > 0 && (
        <Section title="Actions">
          <ul className="flex flex-col gap-2">
            {alert.recommended_actions.map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-muted">
                <span className="mt-2 size-1.5 shrink-0 rounded-full bg-accent" aria-hidden />
                {a}
              </li>
            ))}
          </ul>
        </Section>
      )}

      <RawEvidence raw={ev.raw} />
    </div>
  );
}

/** Bars to the right raise the score, bars to the left lower it. */
function SignalBars({ signals }: { signals: SignalContribution[] }) {
  const maxAbs = Math.max(...signals.map((s) => Math.abs(s.points)), 1);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wide2 text-subtle">
        <span>← Lowers</span>
        <span>Raises →</span>
      </div>
      {signals.map((s, i) => {
        const raises = s.points >= 0;
        const widthPct = Math.max((Math.abs(s.points) / maxAbs) * 50, s.points === 0 ? 0 : 2);
        return (
          <div key={`${s.name}-${i}`}>
            <div className="mb-1 flex items-baseline justify-between gap-3">
              <span className="flex items-center gap-2 truncate text-xs">
                <span className={cn("text-foreground", !s.available && "text-subtle line-through")}>{s.label}</span>
                {!s.available && (
                  <Badge variant="ghost" className="shrink-0">
                    degraded
                  </Badge>
                )}
              </span>
              <span className="shrink-0 font-mono text-xs text-foreground">
                {s.points > 0 ? "+" : s.points < 0 ? "−" : ""}
                {Math.abs(s.points).toFixed(1)}
              </span>
            </div>
            <div className="relative h-2 w-full rounded-sm bg-surface-2">
              <div className="absolute left-1/2 top-0 h-full w-px bg-line-strong" />
              {widthPct > 0 && (
                <div className={cn("absolute top-0 h-full", raises ? "left-1/2 rounded-r-sm bg-danger" : "right-1/2 rounded-l-sm bg-ok")} style={{ width: `${widthPct}%` }} />
              )}
            </div>
            <p className="mt-1 text-[11px] leading-snug text-subtle">
              {s.detail}
              {!s.available && s.reason ? ` — ${s.reason}` : ""}
            </p>
          </div>
        );
      })}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="tf-eyebrow">{label}</span>
      <span className="font-mono text-sm text-foreground">{value}</span>
    </div>
  );
}

function Degraded({ reason, label }: { reason?: string | null; label: string }) {
  return (
    <div className="rounded-md border border-dashed border-line bg-surface-2/40 p-4">
      <p className="text-sm font-medium text-foreground">{label}</p>
      <p className="mt-1 font-mono text-xs text-subtle">{reason || "Scored on the remaining signals only"}</p>
    </div>
  );
}

function RawEvidence({ raw }: { raw: Record<string, any> }) {
  const [open, setOpen] = useState(false);
  const keys = Object.keys(raw ?? {});
  if (keys.length === 0) return null;
  return (
    <Card>
      <button type="button" aria-expanded={open} onClick={() => setOpen((o) => !o)} className="flex w-full items-center justify-between p-5 text-left text-sm font-semibold text-foreground">
        Raw evidence
        <span className="font-mono text-xs font-normal text-subtle">{keys.length} fields</span>
      </button>
      {open && <pre className="max-h-96 overflow-auto border-t border-line px-5 py-4 font-mono text-[11px] leading-relaxed text-muted">{JSON.stringify(raw, null, 2)}</pre>}
    </Card>
  );
}
