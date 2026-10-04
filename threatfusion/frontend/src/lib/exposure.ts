/**
 * exposure.ts — view model for the exploit-informed exposure panel (B11).
 *
 * Exposure answers *"how likely is it that something this host exposes gets exploited?"* — a different question from
 * *"is this target malicious?"* (the scores above it). It is never blended into those, and the view model keeps three
 * promises: (1) the headline says what the number is — the chance that **at least one listed CVE is exploited** — not a
 * vague "risk"; (2) severity (CVSS) sits **beside** the exploitation evidence, not inside it; (3) unknown is said
 * ("Unknown", "KEV unknown", "not assessable"), never shown as 0 or "not listed".
 */
import type { ExposureAssessment, ExposureCve } from "../api.ts";

export type Category = "Track" | "Track*" | "Attend" | "Act";

/** Plain-language meaning of each SSVC-style category, in order of urgency. */
export const CATEGORY_MEANING: Record<Category, string> = {
  "Track": "Track — no sign of exploitation; handle in the normal patch cycle.",
  "Track*": "Track* — watch closely: exploitation is plausible (a proof of concept exists, or EPSS ranks it very high).",
  "Attend": "Attend — exploitation is happening or imminent: prioritise this ahead of the normal cycle.",
  "Act": "Act — exploited in the wild and easy to automate or total in impact: fix or mitigate now.",
};

export interface ExposureRow {
  cve: string;
  cvss: string;
  epss: string;
  kev: string;
  ssvc: string;
  category: string;
  probability: string;
}

export interface ExposureView {
  scoreText: string;
  caption: string;
  category: Category | null;
  coverage: string;
  rows: ExposureRow[];
  notes: string[];
  method: string;
  feedLine: string | null;
}

function percent(v: number): string {
  // 94.358 -> "94.4", 0.04 -> "0.04", 12 -> "12"
  const text = v >= 1 ? v.toFixed(1) : v.toFixed(2);
  return text.replace(/\.0+$/, "").replace(/(\.\d*?)0+$/, "$1");
}

function topPercent(percentile: number): string {
  const x = (1 - percentile) * 100;
  if (x < 1) return x.toFixed(2).replace(/0+$/, "").replace(/\.$/, "");
  if (x < 10) return x.toFixed(1).replace(/\.0$/, "");
  return String(Math.round(x));
}

function probabilityText(p: number | null | undefined): string {
  if (p == null) return "unknown";
  const v = p * 100;
  return v > 0 && v < 1 ? "<1%" : `${Math.round(v)}%`;
}

export function feedAgeText(label: string, days: number | null | undefined): string {
  if (days == null) return `${label} age unknown`;
  if (days < 1) return `${label} refreshed less than a day ago`;
  if (days < 60) return `${label} refreshed ${Math.floor(days)} days ago`;
  const months = Math.floor(days / 30);
  return `${label} refreshed ${months} ${months === 1 ? "month" : "months"} ago`;
}

function row(c: ExposureCve): ExposureRow {
  const points: string[] = [];
  if (c.ssvc_exploitation) points.push(`Exploitation ${c.ssvc_exploitation}`);
  if (c.ssvc_automatable) points.push(`Automatable ${c.ssvc_automatable}`);
  if (c.ssvc_technical_impact) points.push(`Impact ${c.ssvc_technical_impact}`);
  return {
    cve: c.cve_id,
    cvss: c.cvss == null ? "n/a" : c.cvss.toFixed(1),
    epss: c.epss == null ? "unknown" : `${percent(c.epss * 100)}%${c.epss_percentile != null ? ` · top ${topPercent(c.epss_percentile)}%` : ""}`,
    kev: c.in_kev == null ? "KEV unknown" : c.in_kev ? (c.kev_ransomware ? "In KEV · ransomware use" : "In KEV") : "Not in KEV",
    ssvc: points.length ? points.join(" · ") : "—",
    category: c.category ?? "not assessable",
    probability: probabilityText(c.probability),
  };
}

export function exposureView(e: ExposureAssessment | null | undefined): ExposureView | null {
  if (!e) return null;
  const scoreText = e.score == null ? "Unknown" : e.score > 0 && e.score < 1 ? "<1%" : `${Math.round(e.score)}%`;
  const coverage =
    e.cves_total === 0 && e.complete
      ? "No vulnerabilities listed for this host"
      : e.complete
        ? `All ${e.cves_total} CVEs assessed`
        : `Based on ${e.cves_assessed} of ${e.cves_total} CVEs`;
  return {
    scoreText,
    caption: "chance that at least one of the listed vulnerabilities is exploited — likelihood, not severity",
    category: (e.category as Category | null) ?? null,
    coverage,
    rows: e.cves.map(row),
    notes: e.notes,
    method: e.method,
    feedLine: "kev" in (e.feed_ages ?? {}) ? feedAgeText("KEV catalogue", e.feed_ages["kev"]) : null,
  };
}
