/**
 * NetworkAlertDetail — Screen B: the full "why is the score what it is"
 * breakdown for a single network alert.
 *
 * Shows, explicitly and honestly:
 *   - the trigger + fused score + severity,
 *   - every SignalContribution that moved the score (incl. degraded ones),
 *   - the App-Layer sub-score (reusing RiskScorePanel's visual language),
 *   - the WiGLE public-history result (or the reason it was unavailable),
 *   - the device's learned baseline vs. the observed behaviour,
 *   - a raw-evidence section,
 *   - recommended defensive actions.
 */
import { useState, type ReactNode } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ChevronDown,
  CircleAlert,
  Radar,
  Network as NetworkIcon,
  ShieldCheck,
  ShieldAlert,
  Boxes,
} from "lucide-react";
import type { NetworkAlert, SignalContribution } from "@/api";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityTag } from "@/components/RiskIndicators";
import { RiskScorePanel } from "@/components/RiskScorePanel";

const ALERT_TYPE_LABEL: Record<string, string> = {
  deauth_flood: "Deauth flood",
  rogue_ap: "Rogue AP",
  evil_twin: "Evil twin",
  new_device: "New device",
  cross_layer_hit: "Cross-layer hit",
  behavioral_deviation: "Behavioural deviation",
  arp_spoof: "ARP spoofing",
};

interface Props {
  alert: NetworkAlert;
  onBack: () => void;
}

export function NetworkAlertDetail({ alert, onBack }: Props) {
  const ev = alert.evidence;
  const app = ev.app_layer;
  const wigle = ev.wigle;
  const baseline = ev.baseline;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col gap-5"
    >
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div>
        <Button variant="subtle" size="sm" onClick={onBack} className="mb-4">
          Back to feed
        </Button>
        <div className="flex flex-col gap-4 border-b border-line pb-5 sm:flex-row sm:items-end sm:justify-between">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-3">
              <SeverityTag score={alert.fused_score / 100} label={alert.severity} />
              <Badge variant="subtle">
                {ALERT_TYPE_LABEL[alert.alert_type] ?? alert.alert_type}
              </Badge>
              <span className="font-mono text-xs text-subtle">
                {alert.alert_id.slice(0, 8).toUpperCase()}
              </span>
            </div>
            <h2 className="truncate text-xl font-semibold tracking-tight text-foreground md:text-2xl">
              {alert.title}
            </h2>
            <p className="mt-1 text-sm text-muted">{alert.trigger_type}</p>
            <p className="mt-1 font-mono text-xs text-subtle">
              {new Date(alert.timestamp).toLocaleString()}
            </p>
          </div>
          <div className="flex shrink-0 flex-col items-end">
            <div className="flex items-baseline gap-1.5">
              <span className="font-mono text-4xl font-semibold tabular-nums leading-none text-foreground">
                {Math.round(alert.fused_score)}
              </span>
              <span className="font-mono text-xs uppercase tracking-wide2 text-subtle">
                / 100
              </span>
            </div>
            <span className="mt-1 tf-eyebrow">Fused score</span>
          </div>
        </div>
      </div>

      {/* ── Involved identifiers ───────────────────────────────────────── */}
      <div className="flex flex-wrap gap-1.5">
        {alert.involved.map((x) => (
          <span
            key={x}
            className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-[11px] text-muted"
          >
            {x}
          </span>
        ))}
      </div>

      {/* ── Signal contributions (why the score is what it is) ─────────── */}
      <Card className="p-5">
        <div className="mb-4 flex items-center gap-2">
          <CircleAlert className="size-4 text-muted" />
          <span className="text-sm font-semibold text-foreground">
            Score Breakdown
          </span>
          <span className="tf-eyebrow ml-1">every signal that fired</span>
        </div>
        <SignalBars signals={ev.signals} />
      </Card>

      {/* ── App-Layer sub-score (cross-layer correlation) ──────────────── */}
      {app && (
        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <Radar className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              App-Layer Sub-Score
            </span>
            <span className="tf-eyebrow ml-1">cross-layer correlation</span>
          </div>
          {app.available ? (
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="text-muted">Observed target</span>
                <span className="font-mono text-foreground">{app.target}</span>
                {app.flagged ? (
                  <Badge variant="solid">Flagged</Badge>
                ) : (
                  <Badge variant="outline">Not flagged</Badge>
                )}
                <Badge variant={app.live ? "outline" : "subtle"}>
                  {app.live ? "Live VirusTotal" : "Mock data"}
                </Badge>
              </div>
              <RiskScorePanel
                baselineScore={Math.round((app.baseline_score ?? 0) * 100)}
                mlScore={Math.round((app.ml_score ?? 0) * 100)}
                severityLabel={app.ml_label}
                revealKey={alert.alert_id}
              />
              {typeof app.vt_malicious_count === "number" && (
                <p className="font-mono text-xs text-subtle">
                  VirusTotal: {app.vt_malicious_count} / {app.vt_total_engines} engines malicious
                </p>
              )}
              {app.top_explanations.length > 0 && (
                <div className="flex flex-col gap-1.5">
                  <span className="tf-eyebrow">Top drivers</span>
                  {app.top_explanations.map((e, i) => (
                    <span key={i} className="text-xs text-muted">
                      · {e}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <Degraded reason={app.reason} label="App-Layer lookup unavailable" />
          )}
        </Card>
      )}

      {/* ── WiGLE public history ───────────────────────────────────────── */}
      {wigle && (
        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <ShieldAlert className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              WiGLE Public History
            </span>
            <span className="tf-eyebrow ml-1">rogue-AP signal</span>
          </div>
          {wigle.available ? (
            <div className="flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-mono text-foreground">{wigle.bssid}</span>
                {wigle.found ? (
                  <Badge variant="outline">Publicly known</Badge>
                ) : (
                  <Badge variant="solid">Never publicly seen</Badge>
                )}
              </div>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <Stat label="Observations" value={wigle.total_observations} />
                <Stat label="First seen" value={wigle.first_seen ?? "—"} />
                <Stat label="Last seen" value={wigle.last_seen ?? "—"} />
              </div>
              {wigle.known_ssids.length > 0 && (
                <p className="font-mono text-xs text-subtle">
                  Known SSIDs: {wigle.known_ssids.join(", ")}
                </p>
              )}
            </div>
          ) : (
            <Degraded reason={wigle.reason} label="WiGLE lookup unavailable" />
          )}
        </Card>
      )}

      {/* ── Device baseline vs observed ────────────────────────────────── */}
      {baseline && (
        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <NetworkIcon className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Device Baseline vs. Observed
            </span>
            <span className="tf-eyebrow ml-1">behavioural profile</span>
          </div>
          <div className="flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Stat label="Observations" value={baseline.observations} />
              <Stat label="Known domains" value={baseline.known_domain_count} />
              <Stat
                label="Baseline"
                value={baseline.established ? "Established" : "Learning"}
              />
              <Stat
                label="Observed domain"
                value={baseline.is_new_domain ? "NEW" : "Known"}
              />
            </div>
            <p className="text-sm text-muted">{baseline.deviation_detail}</p>
            {baseline.known_domains_sample.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <span className="tf-eyebrow">Normally contacts</span>
                <div className="flex flex-wrap gap-1.5">
                  {baseline.known_domains_sample.map((d) => (
                    <span
                      key={d}
                      className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-[11px] text-muted"
                    >
                      {d}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* ── Recommended actions ────────────────────────────────────────── */}
      {alert.recommended_actions.length > 0 && (
        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <ShieldCheck className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Recommended Actions
            </span>
          </div>
          <ul className="flex flex-col gap-2">
            {alert.recommended_actions.map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-muted">
                <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-foreground/60" />
                {a}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {/* ── Raw evidence ───────────────────────────────────────────────── */}
      <RawEvidence raw={ev.raw} />
    </motion.div>
  );
}

/* Center-anchored bars: right = raises score, left = lowers it. Monochrome. */
function SignalBars({ signals }: { signals: SignalContribution[] }) {
  const maxAbs = Math.max(...signals.map((s) => Math.abs(s.points)), 1);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wide2 text-subtle">
        <span>← lowers</span>
        <span>raises →</span>
      </div>
      {signals.map((s, i) => {
        const raises = s.points >= 0;
        const widthPct = Math.max((Math.abs(s.points) / maxAbs) * 50, s.points === 0 ? 0 : 2);
        return (
          <div key={`${s.name}-${i}`}>
            <div className="mb-1 flex items-baseline justify-between gap-3">
              <span className="flex items-center gap-2 truncate text-xs">
                <span className={cn("text-foreground", !s.available && "text-subtle line-through")}>
                  {s.label}
                </span>
                {!s.available && (
                  <Badge variant="ghost" className="shrink-0">
                    degraded
                  </Badge>
                )}
              </span>
              <span className="shrink-0 font-mono text-xs tabular-nums text-foreground">
                {s.points > 0 ? "+" : s.points < 0 ? "−" : ""}
                {Math.abs(s.points).toFixed(1)}
              </span>
            </div>
            <div className="relative h-2 w-full rounded-sm bg-surface-2">
              <div className="absolute left-1/2 top-0 h-full w-px bg-line-strong" />
              {widthPct > 0 && (
                <div
                  className={cn(
                    "absolute top-0 h-full",
                    raises
                      ? "left-1/2 rounded-r-sm bg-foreground"
                      : "right-1/2 rounded-l-sm border border-foreground/60 bg-foreground/10"
                  )}
                  style={{ width: `${widthPct}%` }}
                />
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
      <span className="font-mono text-sm tabular-nums text-foreground">{value}</span>
    </div>
  );
}

function Degraded({ reason, label }: { reason?: string | null; label: string }) {
  return (
    <div className="flex items-start gap-3 rounded-md border border-dashed border-line bg-surface-2/40 p-4">
      <CircleAlert className="mt-0.5 size-4 shrink-0 text-subtle" />
      <div>
        <p className="text-sm font-medium text-foreground">{label}</p>
        <p className="mt-1 font-mono text-xs text-subtle">
          {reason || "Signal unavailable — scored on remaining real signals only."}
        </p>
      </div>
    </div>
  );
}

function RawEvidence({ raw }: { raw: Record<string, any> }) {
  const [open, setOpen] = useState(false);
  const keys = Object.keys(raw ?? {});
  if (keys.length === 0) return null;
  return (
    <Card>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between p-5 text-left"
      >
        <div className="flex items-center gap-2">
          <Boxes className="size-4 text-muted" />
          <span className="text-sm font-semibold text-foreground">Raw Evidence</span>
          <Badge variant="subtle">{keys.length} fields</Badge>
        </div>
        <ChevronDown
          className={cn(
            "size-4 text-subtle transition-transform duration-300",
            open && "rotate-180"
          )}
        />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden"
          >
            <pre className="border-t border-line px-5 py-4 font-mono text-[11px] leading-relaxed text-muted">
              {JSON.stringify(raw, null, 2)}
            </pre>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  );
}
