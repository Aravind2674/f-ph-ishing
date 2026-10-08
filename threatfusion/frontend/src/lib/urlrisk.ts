/**
 * urlrisk.ts — view model for the calibrated URL-text model card (A2, B7).
 *
 * The models read the URL *string* only. The card keeps four promises: (1) the headline is a *calibrated probability for this
 * data*, followed immediately by what the same score means at realistic phishing prevalence (the benchmark is ~half phishing;
 * traffic is not); (2) every channel is shown with its role — the tree model, the character CNN, the transparent baseline and
 * their fusion — and one that is not available is said to be unavailable, never drawn as zero; (3) evidence is shown with its
 * unit (log-odds) and a plain-language what-if in probability points; (4) the flag is tied to a stated operating point
 * ("false-positive rate ≤ 1 % on validation"), not to an arbitrary 50 %.
 */
import type { RiskExplanation, UrlRiskAssessment } from "../api.ts";

export interface UrlRiskChannel {
  key: string;
  label: string;
  value: string; // "87 %" or "not available"
  role: string;
  headline: boolean;
}

export interface UrlRiskEvidence {
  feature: string;
  text: string;
  direction: "raises" | "lowers";
  logOdds: string; // "+1.23 log-odds"
  whatIf: string | null; // "removing it would lower the probability by about 12 points"
  group: string | null;
}

export interface UrlRiskView {
  scoreText: string;
  flagged: boolean;
  verdict: string;
  basis: string;
  channels: UrlRiskChannel[];
  prevalence: { label: string; value: string }[];
  rules: { text: string; weight: string }[];
  evidence: UrlRiskEvidence[];
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

function pointsText(delta: number | null | undefined): string | null {
  if (delta == null) return null;
  const pts = Math.round(Math.abs(delta) * 100);
  if (pts === 0) return "removing it would barely change the probability";
  return `removing it would ${delta > 0 ? "lower" : "raise"} the probability by about ${pts} point${pts === 1 ? "" : "s"}`;
}

const ROLES: Record<string, string> = {
  xgb: "gradient-boosted trees over 39 URL features (calibrated)",
  cnn: "character CNN over the URL text (calibrated)",
  baseline: "hand-written rules, weights fixed before any training (calibrated)",
  fused: "stacked fusion of the channels that answered",
};

export function urlRiskView(a: UrlRiskAssessment | null | undefined, evidence: RiskExplanation[] = [], top = 6): UrlRiskView | null {
  if (!a || !a.applicable) return null;
  const channels: UrlRiskChannel[] = [
    { key: "fused", label: "Fused", value: percentText(a.fused_score), role: ROLES.fused, headline: a.fused_score != null },
    { key: "xgb", label: "Tree model", value: percentText(a.score), role: ROLES.xgb, headline: a.fused_score == null },
    { key: "cnn", label: "Character CNN", value: percentText(a.cnn_score), role: ROLES.cnn, headline: false },
    { key: "baseline", label: "Rule baseline", value: percentText(a.baseline_score), role: ROLES.baseline, headline: false },
  ];
  const ev: UrlRiskEvidence[] = [...evidence]
    .sort((x, y) => Math.abs(y.shap_value) - Math.abs(x.shap_value))
    .slice(0, top)
    .map((e) => ({
      feature: e.feature_name,
      text: e.human_readable.split(" — ")[0],
      direction: e.shap_value > 0 ? "raises" : "lowers",
      logOdds: `${e.shap_value > 0 ? "+" : "−"}${Math.abs(e.shap_value).toFixed(2)} ${e.unit ?? "log-odds"}`,
      whatIf: pointsText(e.probability_delta),
      group: e.group ?? null,
    }));
  return {
    scoreText: percentText(a.headline_score),
    flagged: a.flagged,
    verdict: a.flagged ? "Flagged: the URL text looks vulnerable" : "Not flagged: the URL text is below the flag threshold",
    basis: a.threshold != null ? `Flag threshold ${percentText(a.threshold)} — ${a.threshold_basis ?? "operating point chosen on validation data"}` : "",
    channels,
    prevalence: Object.entries(a.at_prevalence).map(([k, v]) => ({ label: `If ${k} of URLs are vulnerable`, value: percentText(v) })),
    rules: a.baseline_terms.map((t) => ({ text: t.text, weight: `${t.weight > 0 ? "+" : "−"}${Math.abs(t.weight).toFixed(2)}` })),
    evidence: ev,
    notes: a.notes,
    model: `${a.model_name ?? "url model"} ${a.model_version ?? ""}`.trim(),
  };
}
