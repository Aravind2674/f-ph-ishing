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
} from "lucide-react";
import type { ScanResult as IScanResult, RiskExplanation, AttackPath } from "@/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { RiskMeter, SeverityTag } from "@/components/RiskIndicators";
import { RiskScorePanel } from "@/components/RiskScorePanel";

interface ScanResultProps {
  result: IScanResult;
  onRescan?: () => void;
}

const pct = (n: number) => Math.round((n ?? 0) * 100);

/* ────────────────────────────────────────────────────────────────────────
 * SHAP waterfall. Sign is drawn with DIRECTION (right = raises risk, left =
 * lowers it) and FILL (solid vs hollow) — magnitude with bar length. No hue.
 * ──────────────────────────────────────────────────────────────────────── */
function ShapWaterfall({ items }: { items: RiskExplanation[] }) {
  const maxAbs = Math.max(...items.map((e) => Math.abs(e.shap_value)), 0.0001);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wide2 text-subtle">
        <span>← lowers risk</span>
        <span>raises risk →</span>
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
            Feature Vector
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
            <div className="border-t border-line">
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
                        {Number(f.feature_value).toFixed(3)}
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
    { label: "Foothold", meta: "entry" },
    ...path.nodes.map((n) => ({
      label: n.cve_id,
      meta: n.is_in_kev ? "KEV" : n.cvss_score ? `CVSS ${n.cvss_score}` : "",
    })),
    { label: "Compromise", meta: "objective" },
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

export const ScanResult: React.FC<ScanResultProps> = ({ result, onRescan }) => {
  const [copied, setCopied] = useState(false);
  const baseline = pct(result.baseline_score);
  const ml = pct(result.ml_score ?? result.baseline_score);

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
      className="flex flex-col gap-5"
    >
      {/* ── Target header ─────────────────────────────────────────────── */}
      <div className="flex flex-col gap-4 border-b border-line pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-3">
            <SeverityTag score={ml / 100} label={result.ml_label} />
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

      {result.summary && (
        <p className="text-sm leading-relaxed text-muted">{result.summary}</p>
      )}

      {/* ── Score comparison — quiet dual cards + verdict row ─────────── */}
      <RiskScorePanel
        baselineScore={baseline}
        mlScore={ml}
        severityLabel={result.ml_label}
        revealKey={result.scan_id}
      />

      {/* ── SHAP explanation + data sources ───────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="flex items-center gap-2 p-5 pb-4">
            <Radar className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Decision Rationale
            </span>
            <span className="tf-eyebrow ml-1">SHAP · top drivers</span>
          </div>
          <div className="px-5 pb-5">
            {topShap.length ? (
              <ShapWaterfall items={topShap} />
            ) : (
              <p className="py-6 text-center text-sm text-subtle">
                No explanation data returned for this scan.
              </p>
            )}
          </div>
        </Card>

        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <CircleAlert className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Data Sources
            </span>
          </div>
          <div className="flex flex-col gap-4">
            <DataRow label={`Succeeded · ${result.data_sources_succeeded?.length ?? 0}`}>
              {result.data_sources_succeeded?.length ? (
                result.data_sources_succeeded.map((s) => (
                  <Badge key={s} variant="outline">
                    {s}
                  </Badge>
                ))
              ) : (
                <span className="text-xs text-subtle">None</span>
              )}
            </DataRow>
            <DataRow label={`Failed · ${result.data_sources_failed?.length ?? 0}`}>
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
                <span className="tf-eyebrow">AV Detections</span>
                <p className="mt-1 font-mono text-lg tabular-nums text-foreground">
                  {vt.malicious_count ?? 0}
                  <span className="text-subtle">
                    {" "}
                    / {vt.total_engines ?? "?"}
                  </span>
                </p>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* ── Full feature vector (collapsible) ─────────────────────────── */}
      {explanations.length > 0 && <FeatureVectorTable items={explanations} />}

      {/* ── Enrichment: network exposure + tech stack ─────────────────── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <Network className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Network Exposure
            </span>
            <span className="tf-eyebrow ml-1">Shodan</span>
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
                  ))
                ) : (
                  <span className="text-xs text-subtle">None detected</span>
                )}
              </DataRow>
              {shodan.hostnames?.length > 0 && (
                <DataRow label="Hostnames">
                  {shodan.hostnames.map((h: string) => (
                    <span
                      key={h}
                      className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-[11px] text-muted"
                    >
                      {h}
                    </span>
                  ))}
                </DataRow>
              )}
              {shodan.cpes?.length > 0 && (
                <DataRow label="CPEs">
                  {shodan.cpes.slice(0, 6).map((c: string) => (
                    <span
                      key={c}
                      className="max-w-full truncate rounded border border-line bg-surface-2 px-2 py-1 font-mono text-[10px] text-subtle"
                    >
                      {c}
                    </span>
                  ))}
                </DataRow>
              )}
            </div>
          ) : (
            <EmptyPanel icon={Network} text="No network exposure data." />
          )}
        </Card>

        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <Boxes className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Technology Stack
            </span>
            <span className="tf-eyebrow ml-1">Fingerprint</span>
          </div>
          {techs.length ? (
            <div className="flex flex-col divide-y divide-line">
              {techs.map((t, i) => (
                <div key={i} className="flex items-center justify-between py-2.5 first:pt-0">
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
                    {t.is_eol ? " · EOL" : ""}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyPanel icon={Boxes} text="No technologies detected." />
          )}
        </Card>
      </div>

      {/* ── Vulnerabilities ───────────────────────────────────────────── */}
      {cves.length > 0 && (
        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <Bug className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Vulnerabilities
            </span>
            <Badge variant="subtle">{cves.length}</Badge>
          </div>
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
        </Card>
      )}

      {/* ── Predictive attack chains ──────────────────────────────────── */}
      {result.attack_paths && result.attack_paths.length > 0 && (
        <Card className="p-5">
          <div className="mb-4 flex items-center gap-2">
            <GitBranch className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">
              Predictive Attack Chains
            </span>
            <Badge variant="subtle">{result.attack_paths.length}</Badge>
          </div>
          <div className="flex flex-col gap-4">
            {result.attack_paths.map((path) => (
              <div
                key={path.path_id}
                className="rounded-lg border border-line bg-surface-2/40"
              >
                <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
                  <span className="font-mono text-xs text-muted">
                    Path {path.path_id} · {path.summary}
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
        </Card>
      )}
    </motion.div>
  );
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
