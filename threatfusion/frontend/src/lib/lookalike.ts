/**
 * lookalike.ts — view model for the brand-impersonation card (B4).
 *
 * The check is local and deterministic, so the card is about *what was compared and why it matched* — three promises:
 * (1) a flag always shows its evidence (the substitutions or edits) and the brand's real domain, so the reader can verify it;
 * (2) "no match" says how much was compared ("N brands") and is never phrased as "safe" — a brand we do not protect, or a
 * trick we do not model, is invisible to it; (3) the similarity is called a rule score for the *kind* of trick, not a
 * probability. A genuine brand domain is shown as such, quietly.
 */
import type { BrandCheck, LookalikeKind, LookalikeMatch } from "../api.ts";

export const KIND_LABEL: Record<LookalikeKind, string> = {
  homoglyph: "Look-alike characters",
  leetspeak: "Digits or letter pairs for letters",
  typo: "Typo of the brand name",
  separator: "Brand name split by hyphens",
  brand_keyword: "Brand name + a phishing keyword",
  brand_in_subdomain: "Brand name in a subdomain",
  same_name_other_tld: "Brand name on another domain ending",
  contains_brand: "Contains the brand name",
};

export interface LookalikeView {
  status: "lookalike" | "official" | "no_match";
  headline: string;
  detail: string;
  match: { brand: string; kind: string; domain: string; sector: string; rule: string; evidence: string[]; mixedScript: boolean } | null;
  candidates: { brand: string; kind: string; rule: string }[];
  coverage: string;
  notes: string[];
}

const SECTOR: Record<string, string> = {
  payments: "payments", bank: "banking", gov: "government", ecommerce: "e-commerce", telecom: "telecom", tech: "technology",
  social: "social media", logistics: "logistics", crypto: "crypto", media: "media", travel: "travel", popular: "popular site",
};

function ruleText(m: LookalikeMatch): string {
  return `rule score ${m.similarity.toFixed(2)}`;
}

function matchView(m: LookalikeMatch) {
  return {
    brand: m.brand,
    kind: KIND_LABEL[m.kind] ?? m.kind,
    domain: m.brand_domain,
    sector: SECTOR[m.sector] ?? m.sector,
    rule: ruleText(m),
    evidence: m.evidence,
    mixedScript: m.mixed_script,
  };
}

export function coverageText(c: BrandCheck): string {
  const popular = c.popular_checked > 0 ? ` + ${c.popular_checked} popular sites` : "";
  return `Compared with ${c.brands_checked} protected brands${popular} · flag at rule score ≥ ${c.threshold.toFixed(2)}`;
}

export function lookalikeView(check: BrandCheck | null | undefined): LookalikeView | null {
  if (!check) return null;
  const common = {
    coverage: coverageText(check),
    notes: check.notes,
    candidates: check.candidates.map((c) => ({ brand: c.brand, kind: KIND_LABEL[c.kind] ?? c.kind, rule: ruleText(c) })),
  };
  if (check.status === "lookalike" && check.match) {
    return {
      status: "lookalike",
      headline: `Looks like ${check.match.brand}, but is not its domain`,
      detail: `${KIND_LABEL[check.match.kind] ?? check.match.kind} — the real ${check.match.brand} site is ${check.match.brand_domain}.`,
      match: matchView(check.match),
      ...common,
    };
  }
  if (check.status === "official") {
    return {
      status: "official",
      headline: `This is one of ${check.official_of ?? "a known brand"}'s own domains`,
      detail: "",
      match: null,
      ...common,
    };
  }
  return {
    status: "no_match",
    headline: "No resemblance to a protected brand found",
    detail: "This is not a safety verdict: only the brands in the list, and only the tricks this check models, can be seen.",
    match: null,
    ...common,
  };
}
