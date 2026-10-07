import { cn } from "@/lib/utils";
import { MAX_BARS, resolveSeverity } from "@/lib/severity";

interface RiskProps {
  /** 0..1 model probability; null/undefined = unknown. */
  score: number | null | undefined;
  /** Backend label (preferred over the numeric band when recognised). */
  label?: string | null;
  className?: string;
}

/** A 5-segment meter: filled segments = severity, in the severity's colour. */
export function RiskMeter({ score, label, className }: RiskProps) {
  const sev = resolveSeverity(score, label);
  return (
    <div className={cn("flex items-end gap-[3px]", className)} role="img" aria-label={`${sev.label} — ${sev.bars} of ${MAX_BARS}`}>
      {Array.from({ length: MAX_BARS }).map((_, i) => (
        <span
          key={i}
          style={{ height: 6 + i * 3 }}
          className={cn("w-[3px] rounded-[1px]", i < sev.bars ? sev.fill : "bg-foreground/12")}
        />
      ))}
    </div>
  );
}

/** Icon + uppercase label in the severity's colour. */
export function SeverityTag({ score, label, className, showIcon = true }: RiskProps & { showIcon?: boolean }) {
  const sev = resolveSeverity(score, label);
  const Icon = sev.icon;
  return (
    <span className={cn("inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-wide2", sev.weight, sev.text, className)}>
      {showIcon && <Icon className="size-3.5" aria-hidden />}
      {sev.label}
    </span>
  );
}
