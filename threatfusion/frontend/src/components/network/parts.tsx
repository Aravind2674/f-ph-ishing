/** Small shared pieces of the Network view: a status dot with text, and a severity badge that is colour *and* text. */
import { cn } from "@/lib/utils";
import type { NetworkSeverity } from "@/api";
import type { Tone } from "@/lib/network";

const DOT: Record<Tone, string> = { ok: "bg-ok", warn: "bg-warn", bad: "bg-danger", idle: "bg-subtle" };
const TEXT: Record<Tone, string> = { ok: "text-ok", warn: "text-warn", bad: "text-danger", idle: "text-muted" };

export function StatusDot({ tone, label, className }: { tone: Tone; label: string; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2 text-sm font-medium", TEXT[tone], className)}>
      <span className={cn("size-2 rounded-full", DOT[tone])} aria-hidden />
      {label}
    </span>
  );
}

const SEVERITY: Record<NetworkSeverity, string> = {
  Low: "border-line text-muted",
  Medium: "border-warn/50 text-warn",
  High: "border-danger/50 text-danger",
  Critical: "border-transparent bg-danger text-background font-semibold",
};

export function SeverityBadge({ severity }: { severity: NetworkSeverity }) {
  return <span className={cn("inline-block rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wide", SEVERITY[severity])}>{severity}</span>;
}
