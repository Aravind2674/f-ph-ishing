/**
 * FastVerdictCard — the first answer, from local data only (B1).
 *
 * Shown the moment a scan starts, while the full scan is still running. It says the checks were local (nothing about the target was
 * sent anywhere), names the evidence, and never presents "nothing found" as safe. Monochrome: a listing is a solid badge + a heavier
 * border; everything else is quiet.
 */
import { Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { fastView } from "@/lib/fast";
import type { FastVerdict } from "@/api";

export function FastVerdictCard({ verdict, running }: { verdict: FastVerdict | null | undefined; running: boolean }) {
  const view = fastView(verdict, running);
  if (!view) return null;
  const alarm = view.level === "block" || view.level === "warn";
  return (
    <Card className={cn("flex flex-col gap-3 p-5", view.level === "block" && "border-2 border-foreground")}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Zap className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">Fast check</span>
            <span className="tf-eyebrow ml-1">local only · first answer</span>
          </div>
          <p className={cn("mt-1 text-sm", alarm ? "font-semibold text-foreground" : "text-muted")}>{view.headline}</p>
        </div>
        <Badge variant={alarm ? "solid" : "outline"}>{view.level === "block" ? "Listed" : view.level === "warn" ? "Suspicious" : view.level === "info" ? "Official" : "Nothing found"}</Badge>
      </div>
      {view.reasons.length > 0 && (
        <ul className="flex flex-col gap-1 text-xs text-muted">
          {view.reasons.map((r) => (
            <li key={r}>— {r}</li>
          ))}
        </ul>
      )}
      {view.chips.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {view.chips.map((c) => (
            <span key={c} className="rounded border border-line px-1.5 py-0.5 font-mono text-[10px] text-muted">{c}</span>
          ))}
        </div>
      )}
      <p className="font-mono text-[11px] text-subtle">{view.caption}</p>
      <p className="text-xs text-subtle">{view.slowTierNote}</p>
    </Card>
  );
}
