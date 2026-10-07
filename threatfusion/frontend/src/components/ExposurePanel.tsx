/** Likelihood that a listed CVE gets exploited (EPSS + CISA KEV), kept apart from the maliciousness scores. Unknown is said, never drawn as zero. */
import { useState } from "react";
import { cn } from "@/lib/utils";
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
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="min-w-0 max-w-xl text-xs text-subtle">{view.caption}</p>
        <div className="flex items-baseline gap-3">
          <span className="font-mono text-2xl font-semibold text-foreground">{view.scoreText}</span>
          {view.category && <Badge variant={urgent ? "solid" : "outline"}>{view.category}</Badge>}
        </div>
      </div>

      {view.category && <p className="text-xs text-muted">{CATEGORY_MEANING[view.category as Category]}</p>}
      <p className="font-mono text-xs text-muted">
        {view.coverage}
        {view.feedLine ? ` · ${view.feedLine}` : ""}
      </p>

      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[40rem] border-collapse text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-line text-subtle">
                <th className="py-2 pr-3 font-normal">CVE</th>
                <th className="py-2 pr-3 font-normal">CVSS</th>
                <th className="py-2 pr-3 font-normal">EPSS</th>
                <th className="py-2 pr-3 font-normal">KEV</th>
                <th className="py-2 pr-3 font-normal">SSVC</th>
                <th className="py-2 pr-3 font-normal">Category</th>
                <th className="py-2 font-normal">P(exploit)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.cve} className="border-b border-line/60 align-top">
                  <td className="py-2 pr-3 text-foreground">{r.cve}</td>
                  <td className="py-2 pr-3 text-muted">{r.cvss}</td>
                  <td className={cn("py-2 pr-3", r.epss === "unknown" ? "italic text-subtle" : "text-muted")}>{r.epss}</td>
                  <td className={cn("py-2 pr-3", r.kev.startsWith("In KEV") ? "font-semibold text-danger" : "text-muted")}>{r.kev}</td>
                  <td className="py-2 pr-3 text-muted">{r.ssvc}</td>
                  <td className={cn("py-2 pr-3", r.category === "Act" || r.category === "Attend" ? "font-semibold text-danger" : "text-muted")}>{r.category}</td>
                  <td className={cn("py-2", r.probability === "unknown" ? "italic text-subtle" : "text-foreground")}>{r.probability}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {view.rows.length > COLLAPSED_ROWS && (
            <button type="button" onClick={() => setAll((a) => !a)} className="mt-2 font-mono text-xs text-subtle underline-offset-2 hover:text-foreground hover:underline">
              {all ? "Show fewer" : `Show all ${view.rows.length}`}
            </button>
          )}
        </div>
      )}

      {view.notes.map((n) => (
        <p key={n} className="text-xs text-muted">{n}</p>
      ))}
      <p className="font-mono text-[11px] text-subtle">{view.method}</p>
    </div>
  );
}
