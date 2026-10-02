/**
 * RiskScorePanel — quiet side-by-side score comparison for the scan verdict.
 *
 * Replaces the radar/HUD scope experiment with two equal cards (Baseline vs
 * experimental ML), each with a large count-up numeral and a thin linear progress
 * bar. A single verdict row underneath carries severity + Δ vs baseline.
 * Strictly monochrome; prefers-reduced-motion snaps to final values.
 */
import { useEffect, useState } from "react";
import { useReducedMotion } from "framer-motion";
import { cn } from "@/lib/utils";
import { resolveSeverity } from "@/lib/severity";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

const FILL_MS = 500;

function easeOutCubic(t: number) {
  return 1 - Math.pow(1 - t, 3);
}

/** Count 0 → target over durationMs; bar width tracks the same eased value. */
function useSyncedReveal(
  target: number,
  durationMs: number,
  reduced: boolean | null,
  key: string | number
) {
  const [value, setValue] = useState(reduced ? target : 0);

  useEffect(() => {
    if (reduced) {
      setValue(target);
      return;
    }
    setValue(0);
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      setValue(target * easeOutCubic(t));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs, reduced, key]);

  return value;
}

export interface RiskScorePanelProps {
  /** Baseline heuristic score, 0..100; null = not computed (no evidence). */
  baselineScore: number | null;
  /** ML fusion score, 0..100; null = not computed (no evidence / model unavailable). */
  mlScore: number | null;
  /** Backend label of the BASELINE score (preferred over the numeric band). */
  severityLabel?: string | null;
  /** Remount / re-key to replay the reveal (e.g. scan_id). */
  revealKey?: string | number;
  className?: string;
}

export function RiskScorePanel({
  baselineScore,
  mlScore,
  severityLabel,
  revealKey = "reveal",
  className,
}: RiskScorePanelProps) {
  const reduced = useReducedMotion();
  // Severity follows the baseline (the headline), not the experimental model.
  const sev = resolveSeverity(baselineScore == null ? null : baselineScore / 100, severityLabel);
  const delta = mlScore != null && baselineScore != null ? Math.round(mlScore - baselineScore) : null;

  const baselineAnim = useSyncedReveal(
    baselineScore ?? 0,
    FILL_MS,
    reduced,
    revealKey
  );
  const mlAnim = useSyncedReveal(mlScore ?? 0, FILL_MS, reduced, revealKey);

  return (
    <div className={cn("flex flex-col gap-3", className)}>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {/* The transparent baseline is the headline. The XGBoost model is experimental: it
            currently reads VirusTotal features only (audit §E), so it is labelled as such. */}
        <ScoreCard
          label="Baseline Heuristic"
          subtitle="Transparent weighted-sum rules — evidence below"
          value={baselineScore == null ? null : baselineAnim}
          primary
        />
        <ScoreCard
          label="Experimental model"
          subtitle="XGBoost · VirusTotal signals only · not yet validated"
          value={mlScore == null ? null : mlAnim}
          primary={false}
          experimental
        />
      </div>

      {/* Quiet verdict row — severity left, delta right. No chord / HUD chrome. */}
      <div className="flex items-center justify-between px-1 pt-1">
        <span
          className={cn(
            "font-mono text-xs uppercase tracking-wide2 text-foreground",
            sev.weight
          )}
          style={{ opacity: 0.55 + sev.intensity * 0.45 }}
        >
          {sev.label}
        </span>
        <span className="font-mono text-[11px] uppercase tracking-wide2 text-subtle">
          Δ vs baseline{" "}
          <span className="text-foreground">
            {delta == null ? "n/a" : `${delta > 0 ? "+" : delta < 0 ? "−" : "±"}${Math.abs(delta)}`}
          </span>
        </span>
      </div>
    </div>
  );
}

function ScoreCard({
  label,
  subtitle,
  value,
  primary,
  experimental = false,
}: {
  label: string;
  subtitle: string;
  value: number | null;
  primary: boolean;
  experimental?: boolean;
}) {
  const unavailable = value == null;
  const display = unavailable ? null : Math.round(value);
  const fill = unavailable ? 0 : Math.max(0, Math.min(100, value));

  return (
    <Card
      className={cn(
        "flex flex-col gap-5 p-5 sm:p-6",
        primary && "border-line-strong"
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "text-sm tracking-tight",
                primary
                  ? "font-semibold text-foreground"
                  : "font-medium text-muted"
              )}
            >
              {label}
            </span>
            {primary && <Badge variant="solid">Headline</Badge>}
            {experimental && <Badge variant="outline">Experimental</Badge>}
          </div>
          <p className="mt-0.5 text-xs text-subtle">{subtitle}</p>
        </div>
      </div>

      <div>
        <div className="flex items-baseline gap-1.5">
          <span className="font-mono text-4xl font-semibold tabular-nums leading-none text-foreground">
            {unavailable ? "—" : display}
          </span>
          <span className="font-mono text-xs uppercase tracking-wide2 text-subtle">
            {unavailable ? "unavailable" : "/ 100"}
          </span>
        </div>
        <Progress value={fill} className="mt-4" aria-label={`${label} score`} />
      </div>
    </Card>
  );
}
