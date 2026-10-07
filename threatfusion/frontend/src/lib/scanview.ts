/**
 * scanview.ts — the rows of the scan's evidence table: source · status · value · latency.
 *
 * One row per source that applied to the scan. The value is what the source said, in a few words; a source that did not answer shows
 * why instead. Nothing is filled in: a value the scan did not carry is "—". Sources without a key are left out and only counted.
 * Pure functions (unit-tested); the components render what they return.
 */
import type { RiskExplanation, ScanResult } from "../api.ts";
import { DASH } from "./verdict.ts";
import { evidenceCaution, humanReason, sourceLabel, summarizeEvidence, type ChipState, type LiveState } from "./evidence.ts";
import { ctView, dnsView, registrationView, sortTechs, tlsView, type Fact } from "./hostsignals.ts";
import { reputationView } from "./reputation.ts";

export const STATUS_TEXT: Record<ChipState, string> = {
  ok: "ok",
  running: "running",
  pending: "waiting",
  not_found: "no record",
  error: "failed",
  skipped: "skipped",
  not_configured: "not configured",
};

export interface EvidenceRow {
  source: string;
  label: string;
  state: ChipState;
  status: string;
  /** What the source said — or why it did not answer. "—" when neither is known. */
  value: string;
  latencyMs: number | null;
  cached: boolean;
  /** Extra lines shown when the row is opened. */
  facts: Fact[];
  /** The value deserves a look (a listing, an invalid certificate, an end-of-life component…). */
  flag: boolean;
}

export interface EvidenceTable {
  rows: EvidenceRow[];
  /** "Based on 4 of 7 sources" */
  summary: string;
  /** Sources that were never usable here (no key). Counted, not listed. */
  notConfigured: number;
  /** "No findings ≠ safe …" — null when the verdict status is unknown to the view. */
  caution: string | null;
}

interface Said {
  value: string;
  facts?: Fact[];
  flag?: boolean;
}

const count = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;
const list = (items: unknown): string[] | null => (Array.isArray(items) ? items.map(String) : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** "812 ms", "cached" or "—". */
export function latencyText(row: Pick<EvidenceRow, "latencyMs" | "cached">): string {
  if (row.cached) return "cached";
  return row.latencyMs == null ? DASH : `${Math.round(row.latencyMs)} ms`;
}

function virustotal(r: ScanResult): Said | null {
  const vt = r.virustotal;
  const malicious = num(vt?.malicious_count);
  if (malicious == null) return null;
  const total = num(vt.total_engines);
  const suspicious = num(vt.suspicious_count);
  const parts = [total == null ? `${malicious} engines malicious` : `${malicious} of ${total} engines malicious`];
  if (suspicious) parts.push(`${suspicious} suspicious`);
  return { value: parts.join(", "), flag: malicious > 0 };
}

function internetDb(r: ScanResult): Said | null {
  const sh = r.shodan;
  if (!sh) return null;
  const ports = list(sh.open_ports);
  const vulns = list(sh.vulns);
  const hostnames = list(sh.hostnames) ?? [];
  const cpes = list(sh.cpes) ?? [];
  const tags = list(sh.tags) ?? [];
  const parts = [ports ? count(ports.length, "open port") : null, vulns ? count(vulns.length, "CVE") : null].filter(Boolean) as string[];
  const facts: Fact[] = [];
  if (ports?.length) facts.push({ label: "Ports", value: ports.join(", ") });
  if (hostnames.length) facts.push({ label: "Hostnames", value: hostnames.join(", ") });
  if (cpes.length) facts.push({ label: "Software", value: cpes.slice(0, 6).join(", ") + (cpes.length > 6 ? ` … +${cpes.length - 6}` : "") });
  if (tags.length) facts.push({ label: "Tags", value: tags.join(", ") });
  return { value: parts.length ? parts.join(", ") : DASH, facts, flag: (vulns?.length ?? 0) > 0 };
}

function nvd(r: ScanResult): Said | null {
  const cve = r.cve;
  const total = num(cve?.total_cves);
  if (total == null) return null;
  const max = num(cve.max_cvss_score);
  const cves: any[] = Array.isArray(cve.cves) ? cve.cves : [];
  const facts: Fact[] = cves.slice(0, 8).map((c) => {
    const score = num(c.cvss_v3_score ?? c.cvss_score);
    return { label: String(c.cve_id ?? c.id ?? "CVE"), value: score == null ? "unscored" : `CVSS ${score.toFixed(1)}`, flag: score != null && score >= 7 };
  });
  return { value: max == null ? count(total, "CVE") : `${count(total, "CVE")}, max CVSS ${max.toFixed(1)}`, facts, flag: max != null && max >= 7 };
}

function epss(r: ScanResult): Said | null {
  const e = r.exposure;
  if (!e) return null;
  if (e.cves_total === 0) return { value: "No CVEs to assess" };
  if (e.max_epss == null) return { value: DASH };
  return { value: `max ${(e.max_epss * 100).toFixed(1)} % exploitation chance` };
}

function kev(r: ScanResult): Said | null {
  const e = r.exposure;
  if (!e) return null;
  if (e.cves_total === 0) return { value: "No CVEs to check" };
  return { value: `${e.kev_count} of ${count(e.cves_total, "CVE")} in KEV`, flag: e.kev_count > 0 };
}

function vulnrichment(r: ScanResult): Said | null {
  const e = r.exposure;
  if (!e) return null;
  const withSsvc = e.cves.filter((c) => c.ssvc_exploitation != null);
  if (e.cves_total === 0) return { value: "No CVEs to assess" };
  const facts: Fact[] = withSsvc.slice(0, 8).map((c) => ({
    label: c.cve_id,
    value: `exploitation ${c.ssvc_exploitation}${c.ssvc_automatable ? `, automatable ${c.ssvc_automatable}` : ""}${c.ssvc_technical_impact ? `, impact ${c.ssvc_technical_impact}` : ""}`,
    flag: c.ssvc_exploitation === "active",
  }));
  return { value: withSsvc.length ? `SSVC for ${withSsvc.length} of ${count(e.cves_total, "CVE")}` : "No SSVC data", facts, flag: facts.some((f) => f.flag) };
}

function techFingerprint(r: ScanResult): Said | null {
  const techs = r.tech_fingerprint?.technologies;
  if (!techs) return null;
  const facts: Fact[] = sortTechs(techs).map((t) => ({ label: t.version ? `${t.name} ${t.version}` : t.name, value: t.text, flag: t.badge === "end-of-life" }));
  return { value: count(techs.length, "technology", "technologies"), facts };
}

function endOfLife(r: ScanResult): Said | null {
  const techs = r.tech_fingerprint?.technologies;
  if (!techs) return null;
  const assessed = r.tech_fingerprint?.eol_assessed ?? techs.filter((t) => t.eol != null).length;
  if (assessed === 0) return { value: "No versioned technology" };
  const eol = sortTechs(techs).filter((t) => t.badge === "end-of-life");
  return {
    value: `${eol.length} of ${assessed} end-of-life`,
    facts: eol.map((t) => ({ label: t.version ? `${t.name} ${t.version}` : t.name, value: t.text, flag: true })),
    flag: eol.length > 0,
  };
}

function card(view: { headline: string; ok: boolean | null; facts: Fact[] } | null, value?: (facts: Fact[]) => string | undefined): Said | null {
  if (!view) return null;
  return { value: value?.(view.facts) ?? view.headline, facts: view.facts, flag: view.ok === false || view.facts.some((f) => f.flag) };
}

function reputationSaid(source: string, r: ScanResult): Said | null {
  const view = reputationView(r.reputation);
  if (!view) return null;
  const row = view.rows.find((x) => x.source === source);
  if (row) {
    const facts: Fact[] = [];
    if (row.match) facts.push({ label: "Matched", value: row.match });
    if (row.age) facts.push({ label: "List", value: row.stale ? `${row.age} — out of date` : row.age, flag: row.stale });
    if (row.reference) facts.push({ label: "Record", value: row.reference });
    return { value: row.detail ? `${row.statement} — ${row.detail}` : row.statement, facts, flag: row.kind === "listed" };
  }
  if (source === "tranco") {
    const rank = r.reputation?.popularity_rank;
    return { value: rank != null ? `Rank #${rank.toLocaleString("en-US")}` : "Not ranked" };
  }
  return null;
}

const REPUTATION_SOURCES = new Set(["openphish", "phishtank", "urlhaus", "threatfox", "safebrowsing", "urlscan", "otx", "abuseipdb", "greynoise", "tranco"]);

function whatItSaid(source: string, r: ScanResult, now: Date): Said | null {
  switch (source) {
    case "virustotal": return virustotal(r);
    case "shodan_internetdb": return internetDb(r);
    case "nvd": return nvd(r);
    case "epss": return epss(r);
    case "kev": return kev(r);
    case "vulnrichment": return vulnrichment(r);
    case "tech_fingerprint": return techFingerprint(r);
    case "endoflife": return endOfLife(r);
    case "tls": return card(tlsView(r.tls, now));
    case "rdap": return card(registrationView(r.rdap, now));
    case "dns": return card(dnsView(r.dns), (facts) => facts.find((f) => f.label === "Addresses")?.value);
    case "ct": return card(ctView(r.ct));
    default: return REPUTATION_SOURCES.has(source) ? reputationSaid(source, r) : null;
  }
}

function brandRow(r: ScanResult): EvidenceRow | null {
  const b = r.brand_check;
  if (!b) return null;
  const value = b.status === "lookalike" && b.match ? `Imitates ${b.match.brand}` : b.status === "official" ? `Official domain of ${b.official_of ?? "a known brand"}` : "No look-alike found";
  return {
    source: "brand_check",
    label: "Brand look-alike",
    state: "ok",
    status: STATUS_TEXT.ok,
    value,
    latencyMs: null,
    cached: false,
    facts: b.match ? [{ label: "Matched", value: b.match.matched }, ...b.match.evidence.map((e) => ({ label: "Why", value: e }))] : [],
    flag: b.status === "lookalike",
  };
}

export function evidenceTable(r: ScanResult, now: Date = new Date()): EvidenceTable {
  const outcomes = r.provider_results ?? [];
  const rows: EvidenceRow[] = [];
  let notConfigured = 0;
  for (const o of outcomes) {
    if (o.status === "not_configured") {
      notConfigured += 1;
      continue;
    }
    const state = o.status as ChipState;
    const why = humanReason(o.reason, o.retry_after);
    let said: Said | null = null;
    let value: string;
    if (state === "ok") {
      said = whatItSaid(o.source, r, now);
      value = said?.value ?? DASH;
    } else if (state === "not_found") {
      value = why ?? "No record";
    } else {
      value = why ?? (state === "error" ? "Unavailable" : DASH);
    }
    rows.push({
      source: o.source,
      label: sourceLabel(o.source),
      state,
      status: STATUS_TEXT[state],
      value,
      latencyMs: o.latency_ms ?? null,
      cached: !!o.cached,
      facts: said?.facts ?? [],
      flag: !!said?.flag,
    });
  }
  const brand = brandRow(r);
  if (brand) rows.push(brand);
  return { rows, summary: summarizeEvidence(outcomes).text, notConfigured, caution: evidenceCaution(r.verdict_status) };
}

export interface ShapRow {
  key: string;
  text: string;
  /** "+0.500" / "−1.234" — log-odds in the model's raw score. */
  logOdds: string;
  /** What removing the feature would change, in probability points ("+12 pts"); null when the backend gave none. */
  points: string | null;
  raises: boolean;
  /** Bar length as a share of the strongest factor, 0..1. */
  share: number;
}

/** The strongest factors behind the URL model's score, strongest first. */
export function shapRows(explanations: RiskExplanation[] | null | undefined, top = 6): ShapRow[] {
  const strongest = [...(explanations ?? [])].sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value)).slice(0, top);
  const max = Math.max(...strongest.map((e) => Math.abs(e.shap_value)), 1e-4);
  return strongest.map((e, i) => {
    const pts = e.probability_delta == null ? null : Math.round(Math.abs(e.probability_delta) * 100);
    return {
      key: `${e.feature_name}-${i}`,
      text: e.human_readable.split(" — ")[0],
      logOdds: `${e.shap_value > 0 ? "+" : "−"}${Math.abs(e.shap_value).toFixed(3)}`,
      points: pts == null ? null : pts === 0 ? "0 pts" : `${(e.probability_delta as number) > 0 ? "+" : "−"}${pts} pts`,
      raises: e.shap_value > 0,
      share: Math.abs(e.shap_value) / max,
    };
  });
}

/** The same rows while the scan is still running, from the progress events. */
export function liveRows(live: LiveState): EvidenceRow[] {
  return live.order
    .filter((source) => live.chips[source] && live.chips[source].status !== "not_configured")
    .map((source) => {
      const chip = live.chips[source];
      const state = chip.status;
      const why = state === "error" || state === "skipped" || state === "not_found" ? humanReason(chip.reason, chip.retry_after) : null;
      return {
        source,
        label: sourceLabel(source),
        state,
        status: STATUS_TEXT[state],
        value: why ?? DASH,
        latencyMs: chip.latency_ms ?? null,
        cached: !!chip.cached,
        facts: [],
        flag: false,
      };
    });
}
