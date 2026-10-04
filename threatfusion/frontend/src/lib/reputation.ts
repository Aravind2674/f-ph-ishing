/**
 * reputation.ts — view model for the independent-reputation card (B2).
 *
 * Several sources that do not depend on VirusTotal each say what they know about the target. The card keeps four promises:
 * (1) it lists *who said what*, with the source's own words and a link to the public record — it is not a score and never
 * averages the sources; (2) "not listed" is worded as absence of evidence, never as "safe" (blocklists lag the attackers);
 * (3) a local list always shows how old it is, and an out-of-date list says so; (4) a channel that could not answer is a gap
 * (counted as "N of M answered"), not a clean result. Popularity (Tranco) and scanner context (GreyNoise) are context, never
 * a listing.
 */
import type { ReputationSummary, ReputationVerdict } from "../api.ts";
import { sourceLabel } from "./evidence.ts";

export interface ReputationRow {
  source: string;
  label: string;
  /** What kind of statement this is — shown with an icon/wording, not colour. */
  kind: "listed" | "record" | "context";
  statement: string;
  detail: string | null;
  match: string | null;
  reference: string | null;
  age: string | null;
  stale: boolean;
}

export interface ReputationView {
  headline: string;
  listed: boolean;
  answered: string;
  rows: ReputationRow[];
  feeds: { source: string; label: string; text: string; stale: boolean }[];
  popularity: string | null;
  notes: string[];
}

export const MATCH_TEXT: Record<string, string> = {
  exact_url: "this exact URL",
  url_path: "the same page (different query string)",
  host: "the host (other URLs on it are listed)",
  ip: "the IP address",
  ioc: "an indicator of compromise",
};

/** "under 1 hour", "5 hours", "2 days" — a feed age in plain words. */
export function ageText(days: number | null | undefined): string | null {
  if (days == null) return null;
  const hours = days * 24;
  if (hours < 1) return "under 1 hour old";
  if (hours < 48) return `${Math.round(hours)} hour${Math.round(hours) === 1 ? "" : "s"} old`;
  const d = Math.round(days);
  return `${d} day${d === 1 ? "" : "s"} old`;
}

function rowFor(v: ReputationVerdict): ReputationRow {
  const kind: ReputationRow["kind"] = v.listed ? "listed" : v.category === "popular" || v.category === "scanner" || v.category === "benign" ? "context" : "record";
  const statement = v.listed
    ? "Listed"
    : v.category === "popular"
      ? "Popular site"
      : v.category === "benign"
        ? "Known benign service"
        : v.category === "scanner"
          ? "Internet scanner noise"
          : "Has a record, not flagged";
  return {
    source: v.source,
    label: sourceLabel(v.source),
    kind,
    statement,
    detail: v.detail,
    match: v.match ? MATCH_TEXT[v.match] ?? v.match : null,
    reference: v.reference,
    age: ageText(v.feed_age_days),
    stale: v.stale,
  };
}

export function reputationView(rep: ReputationSummary | null | undefined): ReputationView | null {
  if (!rep) return null;
  const listed = rep.listed_by.length > 0;
  const names = rep.listed_by.map(sourceLabel).join(", ");
  const rows = [...rep.verdicts].map(rowFor).sort((a, b) => order(a.kind) - order(b.kind) || a.label.localeCompare(b.label));
  const feeds = Object.entries(rep.feed_ages).map(([source, days]) => {
    const feedStale = rep.verdicts.some((v) => v.source === source && v.stale);
    const age = ageText(days);
    return {
      source,
      label: sourceLabel(source),
      text: age ? `${age}${feedStale ? " — out of date" : ""}` : "never downloaded",
      stale: feedStale,
    };
  });
  return {
    headline: listed
      ? `Listed by ${rep.listed_by.length} of ${rep.channels_applicable} channels: ${names}`
      : "Not listed by any channel that answered — that is absence of evidence, not proof of safety",
    listed,
    answered: `${rep.channels_answered} of ${rep.channels_applicable} channels answered`,
    rows,
    feeds,
    popularity: rep.popularity_rank != null ? `Ranked #${rep.popularity_rank.toLocaleString("en-US")} in the Tranco popularity list — a prior, not a verdict` : null,
    notes: rep.notes,
  };
}

function order(kind: ReputationRow["kind"]): number {
  return kind === "listed" ? 0 : kind === "record" ? 1 : 2;
}
