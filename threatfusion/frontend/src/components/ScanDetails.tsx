/** Collapsible details under the evidence table: SHAP factors, URL-text models, features, look-alike, exposure, attack paths, raw JSON. */
import React, { useState } from "react";
import { ArrowRight, ChevronDown } from "lucide-react";
import type { AttackPath, NeuralExplanation, ScanResult } from "@/api";
import { cn } from "@/lib/utils";
import { shapRows, type ShapRow } from "@/lib/scanview";
import { RiskMeter } from "@/components/RiskIndicators";
import { UrlRiskPanel } from "@/components/UrlRiskPanel";
import { LookalikePanel } from "@/components/LookalikePanel";
import { ExposurePanel } from "@/components/ExposurePanel";
import { FeatureProvenance } from "@/components/FeatureProvenance";

const pct = (n: number | null | undefined): number | null => (n == null ? null : Math.round(n * 100));

/** SHAP waterfall: bars to the right raise the risk, bars to the left lower it. */
function ShapWaterfall({ rows }: { rows: ShapRow[] }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wide2 text-subtle">
        <span>← Lowers risk</span>
        <span>Raises risk →</span>
      </div>
      {rows.map((row) => (
        <div key={row.key}>
          <div className="mb-1 flex items-baseline justify-between gap-3">
            <span className="min-w-0 truncate text-xs text-muted">{row.text}</span>
            <span className="shrink-0 font-mono text-xs text-foreground">
              {row.logOdds}
              {row.points && <span className="ml-2 text-subtle">{row.points}</span>}
            </span>
          </div>
          <div className="relative h-2 w-full rounded-sm bg-surface-2">
            <div className="absolute left-1/2 top-0 h-full w-px bg-line-strong" />
            <div
              className={cn("absolute top-0 h-full", row.raises ? "left-1/2 rounded-r-sm bg-danger" : "right-1/2 rounded-l-sm bg-ok")}
              style={{ width: `${Math.max(row.share * 50, 2)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

/** The URL with the substrings the character model found suspicious highlighted. Indices are into the lower-cased string it saw. */
function HighlightedUrl({ target, spans }: { target: string; spans: NeuralExplanation[] }) {
  const ranges = [...spans].filter((s) => s.end > s.start).sort((a, b) => a.start - b.start);
  const segments: { text: string; hot: boolean }[] = [];
  let cursor = 0;
  for (const r of ranges) {
    const start = Math.max(r.start, cursor);
    if (start >= target.length) break;
    if (start > cursor) segments.push({ text: target.slice(cursor, start), hot: false });
    const end = Math.min(r.end, target.length);
    if (end > start) segments.push({ text: target.slice(start, end), hot: true });
    cursor = Math.max(cursor, end);
  }
  if (cursor < target.length) segments.push({ text: target.slice(cursor), hot: false });
  return (
    <div className="overflow-x-auto rounded-md border border-line bg-surface-2 px-3 py-2.5">
      <code className="whitespace-pre font-mono text-xs text-subtle">
        {segments.map((s, i) =>
          s.hot ? (
            <span key={i} className="rounded-sm bg-accent px-0.5 font-semibold text-background">{s.text}</span>
          ) : (
            <span key={i}>{s.text}</span>
          ),
        )}
      </code>
    </div>
  );
}

function AttackChain({ path }: { path: AttackPath }) {
  const steps = [
    { label: "Entry", meta: "" },
    ...path.nodes.map((n) => ({ label: n.cve_id, meta: n.is_in_kev ? "KEV" : n.cvss_score ? `CVSS ${n.cvss_score}` : "" })),
    { label: "Compromise", meta: "" },
  ];
  return (
    <div className="overflow-x-auto pb-1">
      <div className="flex min-w-max items-stretch">
        {steps.map((s, i) => (
          <React.Fragment key={i}>
            <div className="flex min-w-[120px] flex-col justify-center rounded-md border border-line bg-surface-2 px-3 py-2">
              <span className="font-mono text-xs text-foreground">{s.label}</span>
              {s.meta && <span className="font-mono text-[10px] uppercase tracking-wide2 text-subtle">{s.meta}</span>}
            </div>
            {i < steps.length - 1 && <ArrowRight className="mx-1.5 size-3.5 self-center text-subtle" aria-hidden />}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-3">
      <h3 className="tf-eyebrow">{title}</h3>
      {children}
    </section>
  );
}

export function ScanDetails({ result }: { result: ScanResult }) {
  const [open, setOpen] = useState(false);
  const shap = shapRows(result.explanations);
  const spans = result.neural_explanations ?? [];
  const paths = result.attack_paths ?? [];

  return (
    <section className="rounded-lg border border-line bg-surface">
      <button
        type="button"
        aria-expanded={open}
        aria-controls="tf-scan-details"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-3 text-left text-sm font-medium text-foreground"
      >
        Details
        <ChevronDown className={cn("size-4 text-subtle transition-transform", open && "rotate-180")} aria-hidden />
      </button>
      {open && (
        <div id="tf-scan-details" className="flex flex-col gap-6 border-t border-line p-4">
          {shap.length > 0 && (
            <Section title="Why this score">
              <ShapWaterfall rows={shap} />
            </Section>
          )}

          {spans.length > 0 && (
            <Section title="Suspicious text">
              <HighlightedUrl target={result.target} spans={spans} />
              <ul className="flex flex-col gap-1">
                {spans.map((s, i) => (
                  <li key={`${s.substring}-${i}`} className="flex items-center justify-between gap-3 font-mono text-xs">
                    <span className="truncate text-foreground">{s.substring}</span>
                    <span className="shrink-0 text-subtle">{pct(s.importance)} %</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {result.url_risk && (
            <Section title="URL models">
              <UrlRiskPanel risk={result.url_risk} />
            </Section>
          )}

          {result.features && (
            <Section title="Features">
              <FeatureProvenance features={result.features} outcomes={result.provider_results} />
            </Section>
          )}

          {result.brand_check && (
            <Section title="Look-alike">
              <LookalikePanel check={result.brand_check} />
            </Section>
          )}

          {result.exposure && (
            <Section title="Exposure">
              <ExposurePanel exposure={result.exposure} />
            </Section>
          )}

          {paths.length > 0 && (
            <Section title="Attack paths">
              <div className="flex flex-col gap-3">
                {paths.map((path) => (
                  <div key={path.path_id} className="rounded-lg border border-line bg-surface-2/40">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2">
                      <span className="font-mono text-xs text-muted">
                        {path.path_id} · {path.summary}
                      </span>
                      {path.total_risk_score == null ? (
                        <span className="font-mono text-xs text-subtle">— no CVSS, EPSS or KEV data</span>
                      ) : (
                        <span className="flex items-center gap-2">
                          <RiskMeter score={path.total_risk_score} />
                          <span className="font-mono text-xs text-foreground">{pct(path.total_risk_score)} %</span>
                        </span>
                      )}
                    </div>
                    <div className="p-3">
                      <AttackChain path={path} />
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          )}

          <Section title="Raw JSON">
            <pre className="max-h-96 overflow-auto rounded-md border border-line bg-background p-3 font-mono text-xs text-muted">{JSON.stringify(result, null, 2)}</pre>
          </Section>
        </div>
      )}
    </section>
  );
}
