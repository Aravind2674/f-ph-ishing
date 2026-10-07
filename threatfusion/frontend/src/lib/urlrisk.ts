/**
 * urlrisk.ts — view model for the calibrated URL-text models (A2, B7).
 *
 * The models read the URL *string* only. The headline is a calibrated probability for this data, followed by what the same score
 * means at realistic phishing prevalence (the benchmark is ~half phishing; traffic is not). A channel that is not available is
 * said to be unavailable, never drawn as zero, and the flag is tied to a stated operating point rather than an arbitrary 50 %.
 */
import type { UrlRiskAssessment } from "../api.ts";

export interface UrlRiskChannel {
  key: string;
  label: string;
  value: string; // "87 %" or "not available"
  headline: boolean;
}

export interface UrlRiskView {
  scoreText: string;
  flagged: boolean;
  verdict: string;
  basis: string;
  channels: UrlRiskChannel[];
  prevalence: { label: string; value: string }[];
  rules: { text: string; weight: string }[];
  notes: string[];
  model: string;
}

export function percentText(p: number | null | undefined): string {
  if (p == null) return "not available";
  const v = p * 100;
  if (v > 0 && v < 1) return "<1 %";
  if (v > 99 && v < 100) return ">99 %";
  return `${Math.round(v)} %`;
}

export function urlRiskView(a: UrlRiskAssessment | null | undefined): UrlRiskView | null {
  if (!a || !a.applicable) return null;
  const channels: UrlRiskChannel[] = [
    { key: "fused", label: "Fused", value: percentText(a.fused_score), headline: a.fused_score != null },
    { key: "xgb", label: "Tree model", value: percentText(a.score), headline: a.fused_score == null },
    { key: "cnn", label: "Character CNN", value: percentText(a.cnn_score), headline: false },
    { key: "baseline", label: "Rule baseline", value: percentText(a.baseline_score), headline: false },
  ];
  return {
    scoreText: percentText(a.headline_score),
    flagged: a.flagged,
    verdict: a.flagged ? "Flagged: the URL text looks like phishing" : "Not flagged: the URL text is below the flag threshold",
    basis: a.threshold != null ? `Flag threshold ${percentText(a.threshold)} — ${a.threshold_basis ?? "operating point chosen on validation data"}` : "",
    channels,
    prevalence: Object.entries(a.at_prevalence).map(([k, v]) => ({ label: `If ${k} of URLs are phishing`, value: percentText(v) })),
    rules: a.baseline_terms.map((t) => ({ text: t.text, weight: `${t.weight > 0 ? "+" : "−"}${Math.abs(t.weight).toFixed(2)}` })),
    notes: a.notes,
    model: `${a.model_name ?? "url model"} ${a.model_version ?? ""}`.trim(),
  };
}
