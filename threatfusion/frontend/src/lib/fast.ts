/**
 * fast.ts — view model for the fast-tier verdict card (B1).
 *
 * The fast tier answers in a fraction of a second from *local* data only (local blocklists, the brand check, the URL-text models, a
 * recent scan). The card makes three promises: (1) it says it is local — nothing about the target was sent anywhere; (2) "nothing
 * found" is worded as *not a clean bill of health* (the slow tier is still running and may find more); (3) an unreadable local
 * list is a gap, not a clean answer.
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
  none: "Nothing found in the local checks",
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
    caption: `Local checks only · answered in ${Math.max(1, Math.round(v.latency_ms))} ms · nothing about this target was sent anywhere`,
    slowTierNote: slowTierRunning
      ? "The full scan is still running — it may find more. Nothing found here is not a clean bill of health."
      : "The full scan has finished (below).",
  };
}
