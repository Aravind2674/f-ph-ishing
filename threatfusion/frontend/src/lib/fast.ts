/**
 * fast.ts — view model for the fast-tier verdict (B1): the first answer, from local data only.
 * "Nothing found" is never worded as safe, and an unreadable local list is a gap, not a clean answer.
 */
import type { FastVerdict } from "../api.ts";

export interface FastView {
  level: FastVerdict["level"];
  headline: string;
  reasons: string[];
  chips: string[];
  caption: string;
  slowTierNote: string;
}

const HEADLINES: Record<FastVerdict["level"], string> = {
  block: "On a phishing list",
  warn: "Looks suspicious",
  info: "A known brand's own domain",
  none: "Nothing found locally",
};

export function fastView(v: FastVerdict | null | undefined, slowTierRunning = true): FastView | null {
  if (!v || v.status === "invalid") return null;
  const chips: string[] = [];
  if (v.listed_by.length) chips.push(`listed: ${v.listed_by.join(", ")}`);
  if (v.brand_check?.status === "lookalike" && v.brand_check.match) chips.push(`imitates ${v.brand_check.match.brand}`);
  if (v.url_risk_flagged) chips.push("URL text flagged");
  if (v.popularity_rank != null) chips.push(`popularity rank #${v.popularity_rank.toLocaleString("en-US")}`);
  if (v.cached_scan) chips.push(`scanned before: ${v.cached_scan.baseline_label ?? "result"} risk`);
  if (v.list_gaps.length) chips.push(`not available: ${v.list_gaps.join(", ")} list`);
  const notAssessable = v.status === "not_assessable" || v.status === "not_applicable";
  return {
    level: v.level,
    headline: notAssessable ? "Not checked by the fast tier" : HEADLINES[v.level],
    reasons: v.reasons,
    chips,
    caption: `Local only · ${Math.max(1, Math.round(v.latency_ms))} ms`,
    slowTierNote: slowTierRunning ? "Full scan running — nothing found is not a clearance" : "Full scan done",
  };
}
