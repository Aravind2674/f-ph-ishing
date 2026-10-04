/**
 * ExposurePanel — how likely is it that something this host exposes gets exploited? (B11)
 *
 * Deliberately a *separate* card from the maliciousness scores: CVSS measures severity, not likelihood, so the headline
 * here is the chance that at least one listed CVE is exploited (EPSS prediction + CISA KEV observation), with every CVE's
 * evidence underneath and the severity shown beside it. Unknown is said, never drawn as zero. Monochrome: urgency is
 * carried by the category word, a solid/outline badge and the table order (worst first), not by colour.
 */
import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CATEGORY_MEANING, exposureView, type Category } from "@/lib/exposure";
import type { ExposureAssessment } from "@/api";

const COLLAPSED_ROWS = 8;

export function ExposurePanel({ exposure }: { exposure: ExposureAssessment | null | undefined }) {
  const [all, setAll] = useState(false);
  const view = exposureView(exposure);
  if (!view) return null;
  const rows = all ? view.rows : view.rows.slice(0, COLLAPSED_ROWS);
  const urgent = view.category === "Act" || view.category === "Attend";

  return (
    <Card className="flex flex-col gap-4 p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <ShieldAlert className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">Exploit exposure</span>
            <span className="tf-eyebrow ml-1">separate from the maliciousness score</span>
          </div>
          <p className="mt-1 max-w-xl text-xs text-subtle">{view.caption}</p>
        </div>
        <div className="flex items-baseline gap-3">
          <span className="font-mono text-4xl font-semibold tabular-nums leading-none text-foreground">{view.scoreText}</span>
          {view.category && (
            <Badge variant={urgent ? "solid" : "outline"} title={CATEGORY_MEANING[view.category as Category]}>
              {view.category}
            </Badge>
          )}
        </div>
      </div>

      <p className="font-mono text-[11px] text-muted">
        {view.coverage}
        {view.feedLine ? ` · ${view.feedLine}` : ""}
      </p>
      {view.category && <p className="text-xs leading-relaxed text-muted">{CATEGORY_MEANING[view.category as Category]}</p>}

      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[42rem] border-collapse text-left font-mono text-[11px]">
            <thead>
              <tr className="border-b border-line text-subtle">
                <th className="py-2 pr-3 font-normal">CVE</th>
                <th className="py-2 pr-3 font-normal">CVSS</th>
                <th className="py-2 pr-3 font-normal">EPSS</th>
                <th className="py-2 pr-3 font-normal">KEV</th>
                <th className="py-2 pr-3 font-normal">CISA SSVC points</th>
                <th className="py-2 pr-3 font-normal">Category</th>
                <th className="py-2 font-normal">P(exploit)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.cve} className="border-b border-line/60 align-top">
                  <td className="py-2 pr-3 text-foreground">{r.cve}</td>
                  <td className="py-2 pr-3 tabular-nums text-muted">{r.cvss}</td>
                  <td className={cn("py-2 pr-3 tabular-nums", r.epss === "unknown" ? "italic text-subtle" : "text-muted")}>{r.epss}</td>
                  <td className={cn("py-2 pr-3", r.kev.startsWith("In KEV") ? "font-semibold text-foreground" : "text-muted")}>{r.kev}</td>
                  <td className="py-2 pr-3 text-muted">{r.ssvc}</td>
                  <td className={cn("py-2 pr-3", r.category === "Act" || r.category === "Attend" ? "font-semibold text-foreground" : "text-muted")}>
                    {r.category}
                  </td>
                  <td className={cn("py-2 tabular-nums", r.probability === "unknown" ? "italic text-subtle" : "text-foreground")}>{r.probability}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {view.rows.length > COLLAPSED_ROWS && (
            <button type="button" onClick={() => setAll((a) => !a)} className="mt-2 font-mono text-[11px] text-subtle underline-offset-2 hover:text-foreground hover:underline">
              {all ? "Show fewer" : `Show all ${view.rows.length} CVEs`}
            </button>
          )}
        </div>
      )}

      {view.notes.length > 0 && (
        <ul className="flex flex-col gap-1 text-xs text-muted">
          {view.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
      <p className="border-t border-line pt-3 text-[11px] leading-relaxed text-subtle">{view.method}</p>
    </Card>
  );
}
