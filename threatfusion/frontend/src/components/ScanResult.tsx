import React, { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Copy,
  Check,
  Download,
  RefreshCw,
  ChevronDown,
  Network,
  Boxes,
  Bug,
  GitBranch,
  ArrowRight,
  CircleAlert,
  Radar,
  BrainCircuit,
} from "lucide-react";
import type {
  ScanResult as IScanResult,
  RiskExplanation,
  AttackPath,
  NeuralExplanation,
} from "@/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { RiskMeter, SeverityTag } from "@/components/RiskIndicators";
import { RiskScorePanel } from "@/components/RiskScorePanel";
import { EvidencePanel } from "@/components/EvidencePanel";
import { ExposurePanel } from "@/components/ExposurePanel";
import { LookalikePanel } from "@/components/LookalikePanel";
import { ReputationPanel } from "@/components/ReputationPanel";
import { UrlRiskPanel } from "@/components/UrlRiskPanel";
import { ReportKitPanel } from "@/components/ReportKitPanel";
import { reportKitForScan, type ReportKit } from "@/api";
import { FeatureProvenance } from "@/components/FeatureProvenance";
import { HostSignals } from "@/components/HostSignals";
import { SourceChips } from "@/components/SourceChip";

interface ScanResultProps {
  result: IScanResult;
  onRescan?: () => void;
}

// null/undefined stay null: an unavailable score is shown as unavailable, never as 0.
const pct = (n: number | null | undefined): number | null =>
  n == null ? null : Math.round(n * 100);

/* ────────────────────────────────────────────────────────────────────────
 * SHAP waterfall. Sign is drawn with DIRECTION (right = raises risk, left =
 * lowers it) and FILL (solid vs hollow) — magnitude with bar length. No hue.
 * ──────────────────────────────────────────────────────────────────────── */
function ShapWaterfall({ items }: { items: RiskExplanation[] }) {
  const maxAbs = Math.max(...items.map((e) => Math.abs(e.shap_value)), 0.0001);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wide2 text-subtle">
        <span>← Decreases Risk</span>
        <span>Increases Risk → (log-odds)</span>
      </div>
      {items.map((exp, i) => {
        const raises = exp.shap_value > 0;
        const widthPct = Math.max((Math.abs(exp.shap_value) / maxAbs) * 50, 2);
        return (
          <motion.div
            key={`${exp.feature_name}-${i}`}
            initial={{ opacity: 0, x: raises ? 8 : -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.04, duration: 0.35 }}
          >
            <div className="mb-1 flex items-baseline justify-between gap-3">
              <span className="truncate text-xs text-muted">{exp.human_readable}</span>
              <span className="shrink-0 font-mono text-xs tabular-nums text-foreground">
                {raises ? "+" : "−"}
                {Math.abs(exp.shap_value).toFixed(3)}
              </span>
            </div>
            {/* Center-anchored track: bars grow out from the middle axis. */}
            <div className="relative h-2 w-full rounded-sm bg-surface-2">
              <div className="absolute left-1/2 top-0 h-full w-px bg-line-strong" />
              <div
                className={cn(
                  "absolute top-0 h-full",
                  raises
                    ? "left-1/2 rounded-r-sm bg-foreground"
                    : "right-1/2 rounded-l-sm border border-foreground/60 bg-foreground/10"
                )}
                style={{ width: `${widthPct}%` }}
              />
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}

/* Collapsible full feature-vector table (all 19 dimensions). */
function FeatureVectorTable({ items }: { items: RiskExplanation[] }) {
  const [open, setOpen] = useState(false);
  const sorted = [...items].sort(
    (a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value)
  );

  return (
    <Card>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between p-5 text-left"
      >
        <div className="flex items-center gap-2">
          <Boxes className="size-4 text-muted" />
          <span className="text-sm font-semibold text-foreground">
            Raw Machine Learning Features
          </span>
          <Badge variant="subtle">{items.length} dims</Badge>
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
            <div className="border-t border-line max-h-[400px] overflow-y-auto pr-1 tf-scrollbar">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line">
                    <th className="px-5 py-2 text-left font-mono text-[10px] uppercase tracking-wide2 text-subtle">
                      Feature
                    </th>
                    <th className="px-5 py-2 text-right font-mono text-[10px] uppercase tracking-wide2 text-subtle">
                      Value
                    </th>
                    <th className="px-5 py-2 text-right font-mono text-[10px] uppercase tracking-wide2 text-subtle">
                      Contribution
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((f, i) => (
                    <tr
                      key={`${f.feature_name}-${i}`}
                      className="border-b border-line last:border-0 hover:bg-surface-2/50"
                    >
                      <td className="px-5 py-2">
                        <div className="font-mono text-xs text-foreground">
                          {f.feature_name}
                        </div>
                        <div className="text-[11px] text-subtle">
                          {f.human_readable}
                        </div>
                      </td>
                      <td className="px-5 py-2 text-right font-mono text-xs tabular-nums text-muted">
                        {f.feature_value == null ? "unknown" : Number(f.feature_value).toFixed(3)}
                      </td>
                      <td className="px-5 py-2 text-right font-mono text-xs tabular-nums text-foreground">
                        {f.shap_value > 0 ? "+" : "−"}
                        {Math.abs(f.shap_value).toFixed(3)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  );
}

/* Monochrome horizontal node-link attack chain. */
function AttackChain({ path }: { path: AttackPath }) {
  const steps = [
    { label: "Initial Access", meta: "entry" },
    ...path.nodes.map((n) => ({
      label: n.cve_id,
      meta: n.is_in_kev ? "KEV" : n.cvss_score ? `CVSS ${n.cvss_score}` : "",
    })),
    { label: "System Compromise", meta: "objective" },
  ];

  return (
    <div className="overflow-x-auto pb-1">
      <div className="flex min-w-max items-stretch gap-0">
        {steps.map((s, i) => (
          <React.Fragment key={i}>
            <div
              className={cn(
                "flex min-w-[132px] flex-col justify-center rounded-md border px-3 py-2.5",
                i === 0 || i === steps.length - 1
                  ? "border-line-strong bg-surface-2"
                  : "border-line bg-surface"
              )}
            >
              <span className="font-mono text-xs text-foreground">{s.label}</span>
              {s.meta && (
                <span className="mt-0.5 font-mono text-[10px] uppercase tracking-wide2 text-subtle">
                  {s.meta}
                </span>
              )}
            </div>
            {i < steps.length - 1 && (
              <div className="flex items-center px-1.5 text-subtle">
                <span className="h-px w-4 bg-line-strong" />
                <ArrowRight className="size-3.5" />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

/* Small labelled data block used inside enrichment panels. */
function DataRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="tf-eyebrow">{label}</span>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────────
 * Neural URL analysis. Surfaces the character-level deep-learning model:
 * the fused (lexical + reputation) risk, the URL-string-only "zero-day" risk,
 * and the suspicious substrings the saliency map flagged — rendered inline so
 * a viewer can see *which* characters looked like phishing.
 * ──────────────────────────────────────────────────────────────────────── */

function HighlightedUrl({
  target,
  spans,
}: {
  target: string;
  spans: NeuralExplanation[];
}) {
  // Merge/sort the flagged ranges, then slice the string into alternating
  // plain / highlighted segments. Indices are into the lower-cased string the
  // model saw, which has the same length as the display target.
  const ranges = [...spans]
    .filter((s) => s.end > s.start)
    .sort((a, b) => a.start - b.start);

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
            <span
              key={i}
              className="rounded-sm bg-foreground px-0.5 font-semibold text-background"
            >
              {s.text}
            </span>
          ) : (
            <span key={i}>{s.text}</span>
          )
        )}
      </code>
    </div>
  );
}

function NeuralStat({ label, score }: { label: string; score: number }) {
  return (
    <div className="flex flex-col gap-2 rounded-md border border-line bg-surface p-4">
      <span className="tf-eyebrow">{label}</span>
      <span className="font-mono text-2xl font-semibold tabular-nums text-foreground">
        {pct(score)}
        <span className="text-base text-subtle">%</span>
      </span>
      <RiskMeter score={score} />
    </div>
  );
}

function NeuralPanel({ result }: { result: IScanResult }) {
  const neural = result.neural_score;
  if (neural == null) return null; // backend has no neural checkpoint loaded

  const urlOnly = result.neural_url_score ?? neural;
  const spans = result.neural_explanations ?? [];

  return (
    <Card className="p-5">
      <div className="mb-4 flex items-center gap-2">
        <BrainCircuit className="size-4 text-muted" />
        <span className="text-sm font-semibold text-foreground">
          AI Phishing Analysis
        </span>
        <span className="tf-eyebrow ml-1">Detects suspicious patterns in URLs</span>
        <span className="ml-auto">
          <SeverityTag score={neural} label={result.neural_label ?? undefined} />
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <NeuralStat label="Combined Risk (AI + Reputation)" score={neural} />
        <NeuralStat label="Raw AI Risk (URL string only)" score={urlOnly} />
      </div>

      <p className="mt-4 text-xs leading-relaxed text-subtle">
        This AI model flags suspicious phishing patterns directly in the URL text, even if the link has never been reported to security vendors before.
      </p>

      {spans.length > 0 && (
        <div className="mt-4 flex flex-col gap-3">
          <span className="tf-eyebrow">Suspicious URL Substrings</span>
          <HighlightedUrl target={result.target} spans={spans} />
          <div className="flex flex-col gap-1.5">
            {spans.map((s, i) => (
              <div
                key={`${s.substring}-${i}`}
                className="flex items-center justify-between gap-3"
              >
                <span className="truncate font-mono text-xs text-muted">
                  <span className="rounded-sm bg-surface-2 px-1 text-foreground">
                    {s.substring}
                  </span>
                </span>
                <span className="shrink-0 font-mono text-xs tabular-nums text-subtle">
                  {pct(s.importance)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

function ReportThisSite({ scanId }: { scanId: string }) {
  const [kit, setKit] = useState<ReportKit | null>(null);
  const [lost, setLost] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = async (lostMoney: boolean) => {
    setLost(lostMoney);
    setError(null);
    try {
      setKit(await reportKitForScan(scanId, lostMoney));
    } catch (e: any) {
      setError(e.message || "Could not prepare the report");
    }
  };
  if (!kit) {
    return (
      <div className="flex flex-wrap items-center gap-3">
        <Button type="button" variant="outline" size="sm" onClick={() => load(false)}>Report this site</Button>
        <span className="text-xs text-subtle">Prepares text and lists the official channels (cybercrime.gov.in, 1930, CERT-In). Nothing is sent for you.</span>
        {error && <span className="font-mono text-xs text-foreground">{error}</span>}
      </div>
    );
  }
  return <ReportKitPanel kit={kit} lostMoney={lost} onToggleLost={load} />;
}

export const ScanResult: React.FC<ScanResultProps> = ({ result, onRescan }) => {
  const [copied, setCopied] = useState(false);
  const baseline = pct(result.baseline_score);
  // No fallback to the baseline score: the backend returns null when the model has no evidence.
  const ml = pct(result.ml_score);

  const explanations = result.explanations ?? [];
  const topShap = [...explanations]
    .sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value))
    .slice(0, 6);

  const shodan = result.shodan;
  const techs: any[] = result.tech_fingerprint?.technologies ?? [];
  const cves: any[] = result.cve?.cves ?? [];
  const vt = result.virustotal;

  const copyTarget = async () => {
    try {
      await navigator.clipboard.writeText(result.target);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable in some contexts — non-fatal */
    }
  };

  const handleExport = () => {
    // Export the full raw result as JSON (an evidence artefact for a report).
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threatfusion-${result.scan_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col gap-4"
    >
      {/* Target header */}
      <div className="flex flex-col gap-4 border-b border-line pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-3">
            <SeverityTag score={baseline == null ? null : baseline / 100} label={result.baseline_label} />
            <span className="font-mono text-xs text-subtle">
              {result.scan_id.slice(0, 8).toUpperCase()}
            </span>
            <Badge variant="subtle">{result.target_type}</Badge>
          </div>
          <div className="flex items-center gap-2">
            <h2 className="truncate font-mono text-xl font-semibold tracking-tight text-foreground md:text-2xl">
              {result.target}
            </h2>
            <button
              onClick={copyTarget}
              className="text-subtle transition-colors hover:text-foreground"
              aria-label="Copy target"
            >
              {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
            </button>
          </div>
          <p className="mt-1 font-mono text-xs text-subtle">
            {new Date(result.timestamp).toLocaleString()}
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button variant="outline" size="sm" onClick={onRescan}>
            <RefreshCw className="size-3.5" />
            Re-scan
          </Button>
          <Button variant="subtle" size="sm" onClick={handleExport}>
            <Download className="size-3.5" />
            Export JSON
          </Button>
        </div>
      </div>

      {/* "Unknown" banner. A partial verdict is explained by the Evidence panel just below the scores (A1-7). */}
      {result.verdict_status === "unknown" && (
        <Card className="flex items-start gap-3 border-line-strong p-4">
          <CircleAlert className="mt-0.5 size-4 shrink-0 text-foreground" />
          <div>
            <p className="text-sm font-semibold text-foreground">Risk unknown — no reputation evidence</p>
            {result.verdict_reason && (
              <p className="mt-1 text-xs text-muted">{result.verdict_reason}</p>
            )}
          </div>
        </Card>
      )}

      {result.summary && (
        <p className="text-sm leading-relaxed text-muted">{result.summary}</p>
      )}

<<<<<<< Updated upstream
      {/* ── Score comparison — quiet dual cards + verdict row ─────────── */}
      <RiskScorePanel
        baselineScore={baseline}
        mlScore={ml}
        severityLabel={result.baseline_label}
        revealKey={result.scan_id}
      />

      {/* ── Calibrated URL-text models (A2): reads the URL string only; units and prevalence stated ─ */}
      <UrlRiskPanel risk={result.url_risk} evidence={result.explanations ?? []} />

      {/* ── What the score rests on: "based on N of M sources", per-source chips, "no findings ≠ safe" ─ */}
      <EvidencePanel outcomes={result.provider_results} verdict={result.verdict_status} />

      {/* ── Brand impersonation (B4): local look-alike check, kept apart from the maliciousness scores ─ */}
      <LookalikePanel check={result.brand_check} />

      {/* ── Independent reputation (B2): blocklists + abuse feeds side by side — not a score ─ */}
      <ReputationPanel reputation={result.reputation} />

      {/* ── Exploit exposure (B11): likelihood of exploitation, kept apart from the maliciousness scores ─ */}
      <ExposurePanel exposure={result.exposure} />

      {/* ── Neural URL analysis (deep-learning model) ─────────────────── */}
      <NeuralPanel result={result} />

      {/* ── SHAP explanation + data sources ───────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="flex items-center gap-2 p-5 pb-4">
            <Radar className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Why this score?
            </span>
            <span className="tf-eyebrow ml-1">Top factors affecting the score</span>
          </div>
          <div className="px-5 pb-5">
            {topShap.length ? (
              <ShapWaterfall items={topShap} />
            ) : (
              <p className="py-6 text-center text-sm text-subtle">
                No specific factors found to explain this score.
              </p>
            )}
          </div>
        </Card>

        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <CircleAlert className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              External Data Sources
            </span>
          </div>
          <div className="flex flex-col gap-4">
            {/* The per-source states live in the Evidence panel above; the chips are repeated here with their timings. */}
            {!!result.provider_results?.length && <SourceChips outcomes={result.provider_results} />}
            <p className="text-xs leading-relaxed text-subtle">
              "No record" and "not configured" mean a source had nothing to say about this target — that is missing evidence,
              not a clean result.
            </p>
            {(result.model_versions || result.feature_schema_version) && (
              <p className="border-t border-line pt-3 font-mono text-[10px] leading-relaxed text-subtle">
                {result.mock_mode ? "MOCK DATA · " : ""}
                {Object.entries(result.model_versions ?? {})
                  .map(([k, v]) => `${k} ${v}`)
                  .join(" · ")}
                {result.feature_schema_version ? ` · features v${result.feature_schema_version}` : ""}
                {result.app_version ? ` · app ${result.app_version}` : ""}
              </p>
            )}
            {vt && (
              <div className="border-t border-line pt-3">
                <span className="tf-eyebrow">Antivirus Detections</span>
                <p className="mt-1 font-mono text-lg tabular-nums text-foreground">
                  {vt.malicious_count ?? 0}
                  <span className="text-subtle">
                    {" "}
                    / {vt.total_engines ?? "?"}
                  </span>
=======
      {/* Masonry-style 2-column layout to prevent unused gaps */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
        
        {/* LEFT COLUMN */}
        <div className="flex flex-col gap-4">
          <RiskScorePanel
            baselineScore={baseline}
            mlScore={ml}
            severityLabel={result.ml_label}
            revealKey={result.scan_id}
          />

          <Card className="p-0">
            <div className="flex items-center gap-2 p-5 pb-4 border-b border-line">
              <Radar className="size-4 text-muted" />
              <span className="text-sm font-semibold text-foreground">
                Why this score? (Top Factors)
              </span>
            </div>
            <div className="px-5 py-5">
              {topShap.length ? (
                <ShapWaterfall items={topShap} />
              ) : (
                <p className="py-6 text-center text-sm text-subtle">
                  No specific factors found to explain this score.
>>>>>>> Stashed changes
                </p>
              )}
              </div>
          </Card>

          {explanations.length > 0 && <FeatureVectorTable items={explanations} />}

<<<<<<< Updated upstream
      {/* ── Feature provenance: every feature's value (or "unknown") and the source it came from ─────── */}
      <FeatureProvenance features={result.features} outcomes={result.provider_results} />

      {/* ── Host evidence: TLS certificate, registration (domain age), DNS, technology + end-of-life ──── */}
      <HostSignals result={result} />

      {/* ── Enrichment: network exposure + tech stack ─────────────────── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <Network className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Open Ports & Services
            </span>
            <span className="tf-eyebrow ml-1">(via Shodan)</span>
          </div>
          {shodan ? (
            <div className="flex flex-col gap-4">
              <DataRow label="Open Ports">
                {shodan.open_ports?.length ? (
                  shodan.open_ports.map((p: number) => (
                    <span
                      key={p}
                      className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-xs tabular-nums text-foreground"
                    >
                      {p}
                    </span>
=======
          {result.attack_paths && result.attack_paths.length > 0 && (
            <Card className="flex flex-col p-4 sm:p-5 max-h-[400px]">
              <div className="mb-4 flex items-center gap-2 shrink-0">
                <GitBranch className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Attack Paths
                </span>
                <Badge variant="subtle">{result.attack_paths.length}</Badge>
              </div>
              <div className="flex-1 overflow-y-auto pr-1.5 min-h-0 tf-scrollbar">
                <div className="flex flex-col gap-4">
                  {result.attack_paths.map((path) => (
                  <div
                    key={path.path_id}
                    className="rounded-lg border border-line bg-surface-2/40"
                  >
                    <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
                      <span className="font-mono text-xs text-muted">
                        Path {path.path_id} - {path.summary}
                      </span>
                      <span className="flex items-center gap-2">
                        <RiskMeter score={path.total_risk_score} />
                        <span className="font-mono text-xs tabular-nums text-foreground">
                          {pct(path.total_risk_score)}%
                        </span>
                      </span>
                    </div>
                    <div className="p-4">
                      <AttackChain path={path} />
                    </div>
                  </div>
                ))}
                </div>
              </div>
            </Card>
          )}
        </div>

        {/* RIGHT COLUMN */}
        <div className="flex flex-col gap-4">
          <NeuralPanel result={result} />

          <Card className="flex flex-col p-4 sm:p-5 max-h-[340px]">
            <div className="mb-4 flex items-center gap-2 shrink-0">
              <CircleAlert className="size-4 text-muted" />
              <span className="text-sm font-semibold text-foreground">
                Data Sources
              </span>
            </div>
            <div className="flex-1 overflow-y-auto pr-1.5 min-h-0 tf-scrollbar">
              <div className="flex flex-col gap-4">
              <DataRow label={"Successful - " + (result.data_sources_succeeded?.length ?? 0)}>
                {result.data_sources_succeeded?.length ? (
                  result.data_sources_succeeded.map((s) => (
                    <Badge key={s} variant="outline">
                      {s}
                    </Badge>
>>>>>>> Stashed changes
                  ))
                ) : (
                  <span className="text-xs text-subtle">None</span>
                )}
              </DataRow>
              <DataRow label={"Failed - " + (result.data_sources_failed?.length ?? 0)}>
                {result.data_sources_failed?.length ? (
                  result.data_sources_failed.map((s) => (
                    <Badge key={s} variant="ghost" className="line-through">
                      {s}
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs text-subtle">None</span>
                )}
              </DataRow>
              {vt && (
                <div className="border-t border-line pt-3">
                  <span className="tf-eyebrow">Antivirus Detections</span>
                  <p className="mt-1 font-mono text-lg tabular-nums text-foreground">
                    {vt.malicious_count ?? 0}
                    <span className="text-subtle">
                      {" "}/ {vt.total_engines ?? "?"}
                    </span>
                  </p>
                </div>
              )}
            </div>
          </Card>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Card className="p-4 sm:p-5 flex flex-col max-h-[340px]">
              <div className="mb-4 flex items-center gap-2 shrink-0">
                <Boxes className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Technologies
                </span>
              </div>
              <div className="flex-1 overflow-y-auto pr-1.5 min-h-0 tf-scrollbar">
                {techs.length ? (
                  <div className="flex flex-col divide-y divide-line">
                    {techs.map((t, i) => (
                      <div key={i} className="flex items-center justify-between py-2 first:pt-0">
                        <span className="text-sm text-foreground">{t.name}</span>
                        <span
                          className={cn(
                            "rounded border px-2 py-0.5 font-mono text-[10px]",
                            t.is_eol
                              ? "border-line-strong font-semibold text-foreground"
                              : "border-line text-subtle"
                          )}
                        >
                          v{t.version || "?"}
                          {t.is_eol ? " (EOL)" : ""}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyPanel icon={Boxes} text="No tech stack detected." />
                )}
              </div>
            </Card>

            <Card className="p-4 sm:p-5 flex flex-col max-h-[340px]">
              <div className="mb-4 flex items-center gap-2 shrink-0">
                <Network className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Open Ports
                </span>
              </div>
              <div className="flex-1 overflow-y-auto pr-1.5 min-h-0 tf-scrollbar">
                {shodan ? (
                  <div className="flex flex-col gap-4">
                    <DataRow label="Ports">
                      {shodan.open_ports?.length ? (
                        shodan.open_ports.map((p) => (
                          <span
                            key={p}
                            className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-xs tabular-nums text-foreground"
                          >
                            {p}
                          </span>
                        ))
                      ) : (
                        <span className="text-xs text-subtle">None</span>
                      )}
                    </DataRow>
                  </div>
                ) : (
                  <EmptyPanel icon={Network} text="No ports detected." />
                )}
              </div>
            </Card>
          </div>

          {cves.length > 0 && (
            <Card className="flex flex-col p-4 sm:p-5 max-h-[400px]">
              <div className="mb-4 flex items-center gap-2 shrink-0">
                <Bug className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Vulnerabilities (CVEs)
                </span>
                <Badge variant="subtle">{cves.length}</Badge>
              </div>
              <div className="flex-1 overflow-y-auto pr-1.5 min-h-0 tf-scrollbar">
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {cves.map((c, i) => {
                  const id = c.cve_id || c.id;
                  const cvss = c.cvss_v3_score ?? c.cvss_score;
                  return (
                    <div
                      key={id || i}
                      className="flex items-center justify-between rounded-md border border-line bg-surface-2 px-3 py-2"
                    >
                      <span className="font-mono text-xs text-foreground">{id}</span>
                      {cvss != null && (
                        <span className="flex items-center gap-2">
                          <RiskMeter score={Number(cvss) / 10} />
                          <span className="font-mono text-xs tabular-nums text-muted">
                            {Number(cvss).toFixed(1)}
                          </span>
                        </span>
                      )}
                    </div>
                  );
                })}
                </div>
              </div>
<<<<<<< Updated upstream
            ))}
          </div>
        </Card>
      )}

      {/* ── Report (B16): prepares the text and lists the official channels; nothing is submitted for the user ─ */}
      <ReportThisSite scanId={result.scan_id} />
    </motion.div>
  );
=======
            </Card>
          )}
        </div>
      </div>
    </motion.div>  );
>>>>>>> Stashed changes
};

function EmptyPanel({
  icon: Icon,
  text,
}: {
  icon: typeof Network;
  text: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-line py-8 text-center">
      <Icon className="size-6 text-subtle/60" />
      <span className="text-xs text-subtle">{text}</span>
    </div>
  );
}
