/**
 * verdict.ts — view model for the headline verdict.
 *
 * Two channels answer different questions and are never blended:
 *   URL model          — does the URL *text* look like phishing? (calibrated; a what-if at realistic prevalence is shown)
 *   Provider evidence  — what do VirusTotal, open ports, CVEs, TLS and domain age say? (transparent weighted sum)
 * The backend picks the headline as the higher-risk band of the two and says which one drove it (`driven_by`). The scores
 * themselves are shown exactly as computed. Unknown is "—", never 0.
 */
import type { ScanResult } from "../api.ts";

export type DrivenBy = "url_model" | "provider_evidence" | "both";

export interface ChannelView {
  key: "url_model" | "provider_evidence";
  label: string;
  hint: string;
  /** 0..100, or null when the channel produced no score. */
  value: number | null;
  /** "87", or "—". */
  text: string;
  band: string | null;
}

export interface VerdictView {
  headline: string;
  drivenBy: DrivenBy | null;
  reason: string;
  disagree: boolean;
  channels: [ChannelView, ChannelView];
  /** Top provider contributions, shown when provider evidence drives the verdict. */
  providerReasons: string[];
  /** The URL model's what-if at realistic prevalence, e.g. "At 1 % phishing: 12 %". */
  prevalence: string | null;
}

export const DASH = "—";

/** A score on 0..100, or "—". */
export function scoreText(points: number | null | undefined): string {
  return points == null || Number.isNaN(points) ? DASH : String(Math.round(points));
}

const toPoints = (v: number | null | undefined): number | null => (v == null ? null : v * 100);
const band = (label: string | null | undefined): string | null => (label && label !== "Unknown" ? label : null);

function percent(p: number | null | undefined): string {
  if (p == null) return DASH;
  const v = p * 100;
  if (v > 0 && v < 1) return "<1 %";
  if (v > 99 && v < 100) return ">99 %";
  return `${Math.round(v)} %`;
}

type VerdictInput = Pick<
  ScanResult,
  "baseline_score" | "baseline_label" | "ml_score" | "ml_label" | "headline_band" | "driven_by" | "agreement" | "baseline_terms" | "url_risk"
> & { verdict_status?: ScanResult["verdict_status"] };

function reasonFor(headline: string | null, drivenBy: DrivenBy | null, urlBand: string | null, providerBand: string | null, flagged: boolean | undefined, noProvider: boolean): string {
  if (!headline || !drivenBy) return "No channel produced a score";
  if (headline === "Low") return noProvider ? "URL text looks benign; no provider answered, so this is not a clearance" : "Low on every channel that answered";
  const verb = headline === "Medium" ? "Raised by" : "Flagged by";
  if (drivenBy === "both") return "Both channels agree";
  if (drivenBy === "url_model") {
    return providerBand ? `${verb} XGBoost heuristic — the Baseline score is ${providerBand}` : `${verb} XGBoost heuristic — no Baseline score`;
  }
  if (!urlBand) return `${verb} the Baseline score — XGBoost heuristic did not run`;
  return flagged === false || urlBand === "Low" ? `${verb} the Baseline score — URL text looks benign` : `${verb} the Baseline score — URL text is below the flag threshold`;
}

export function verdictView(r: VerdictInput): VerdictView {
  const urlBand = band(r.ml_label);
  const providerBand = band(r.baseline_label);
  const url = toPoints(r.ml_score);
  const provider = toPoints(r.baseline_score);
  const drivenBy = (r.driven_by ?? null) as DrivenBy | null;
  const headline = r.headline_band && r.headline_band !== "Unknown" ? r.headline_band : null;
  const prevalence = r.url_risk?.at_prevalence ? Object.entries(r.url_risk.at_prevalence)[0] : undefined;
  return {
    headline: headline ?? DASH,
    drivenBy,
    reason: reasonFor(headline, drivenBy, urlBand, providerBand, r.url_risk?.flagged, r.verdict_status === "unknown"),
    disagree: r.agreement === false,
    channels: [
      { key: "url_model", label: "XGBoost heuristic", hint: "URL text only", value: url, text: scoreText(url), band: urlBand },
      { key: "provider_evidence", label: "Baseline score", hint: "Reputation, ports, CVEs, TLS", value: provider, text: scoreText(provider), band: providerBand },
    ],
    providerReasons: drivenBy === "provider_evidence" ? [...(r.baseline_terms ?? [])].sort((a, b) => b.weight - a.weight).slice(0, 3).map((t) => t.text) : [],
    prevalence: prevalence ? `At ${prevalence[0].replace("%", " %")} vulnerable: ${percent(prevalence[1])}` : null,
  };
}
