import { cn } from "@/lib/utils";
import { MAX_BARS, resolveSeverity } from "@/lib/severity";

/*
 * Shared monochrome risk indicators.
 *
 * These are the canonical way risk is drawn anywhere in the app. They read the
 * Severity bundle from lib/severity and translate it into non-colour signals:
 * bar density, fill opacity, glyph and font weight.
 */

interface RiskProps {
  /** 0..1 model probability; null/undefined = unknown. */
  score: number | null | undefined;
  /** Optional backend label (preferred over the numeric band when recognised). */
  label?: string | null;
  className?: string;
}

/** A 5-segment density meter. Filled segments = severity; unfilled are hairlines. */
export function RiskMeter({ score, label, className }: RiskProps & { size?: "sm" | "md" }) {
  const sev = resolveSeverity(score, label);
  return (
    <div
      className={cn("flex items-end gap-[3px]", className)}
      role="img"
      aria-label={`${sev.label} — ${sev.bars} of ${MAX_BARS}`}
    >
      {Array.from({ length: MAX_BARS }).map((_, i) => {
        const filled = i < sev.bars;
        // Bars step up in height so density reads even in tiny sizes.
        const height = 6 + i * 3;
        return (
          <span
            key={i}
            style={{ height, opacity: filled ? sev.intensity : 1 }}
            className={cn(
              "w-[3px] rounded-[1px]",
              filled ? "bg-foreground" : "bg-foreground/12"
            )}
          />
        );
      })}
    </div>
  );
}

/** Icon + uppercase label, weight scaled by severity. */
export function SeverityTag({
  score,
  label,
  className,
  showIcon = true,
}: RiskProps & { showIcon?: boolean }) {
  const sev = resolveSeverity(score, label);
  const Icon = sev.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-wide2",
        sev.weight,
        className
      )}
      style={{ opacity: 0.55 + sev.intensity * 0.45 }}
    >
      {showIcon && <Icon className="size-3.5" style={{ opacity: sev.intensity }} />}
      {sev.label}
    </span>
  );
}
