/**
 * evidence.ts — the evidence-first view model (A1-7).
 *
 * A score is only as good as the evidence under it, so the UI states that evidence explicitly instead of letting
 * a number speak for itself:
 *
 *   - how many sources a score rests on ("Based on 4 of 7 sources") and which ones are missing;
 *   - "No findings ≠ safe" wording — a source that has nothing to report is missing *evidence of risk*, not
 *     evidence of safety;
 *   - for every feature: its value (or "unknown") and the source it came from — an unknown feature says *why*
 *     (which source timed out, was rate-limited, is not configured, or never ran);
 *   - live per-source progress while a scan runs (folded from the backend's Server-Sent Events).
 *
 * Pure functions only (no React, no DOM, no icons): they are unit-tested with `node --test` and the components
 * in `components/` just render what they return. Statuses use the backend's vocabulary:
 * ok · not_found · error · skipped · not_configured (+ pending / running while a scan is in flight).
 */
import type { ProviderOutcome } from "../api.ts";

export type ChipState = "pending" | "running" | "ok" | "not_found" | "error" | "skipped" | "not_configured";

export const SOURCE_LABELS: Record<string, string> = {
  virustotal: "VirusTotal",
  shodan_internetdb: "Shodan InternetDB",
  nvd: "NVD",
  epss: "EPSS",
  kev: "CISA KEV",
  vulnrichment: "CISA Vulnrichment",
  tech_fingerprint: "Tech fingerprint",
  endoflife: "endoflife.date",
  tls: "TLS certificate",
  rdap: "Registration (RDAP)",
  dns: "DNS",
  ct: "Certificate transparency",
  openphish: "OpenPhish",
  phishtank: "PhishTank",
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
  safebrowsing: "Google Safe Browsing",
  urlscan: "urlscan.io",
  otx: "AlienVault OTX",
  abuseipdb: "AbuseIPDB",
  greynoise: "GreyNoise",
  tranco: "Tranco",
};

export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source;
}

/** A provider's reason code in plain words (unknown codes are shown as-is, never hidden). */
export function humanReason(reason: string | null | undefined, retryAfter?: number | null): string | null {
  if (!reason) return null;
  if (reason === "rate_limited") {
    return retryAfter && retryAfter > 0 ? `Rate limited — retry in ${Math.ceil(retryAfter)}s` : "Rate limited";
  }
  if (reason.startsWith("blocked:")) return `Refused by the safety policy (${reason.slice(8)})`;
  if (reason.startsWith("partial:")) return `Partial — ${reason.slice(8)}`;
  if (reason.startsWith("truncated:")) return `Truncated ${reason.slice(10)}`;
  if (reason.startsWith("unexpected:")) return "Unexpected error";
  switch (reason) {
    case "auth": return "Credential rejected (check the API key)";
    case "auth_or_rate_limited": return "Rejected or throttled by the provider (HTTP 403)";
    case "timeout": return "Timed out";
    case "network": return "Network error";
    case "dns_failure": return "DNS lookup failed";
    case "server_error": return "Provider server error";
    case "bad_request": return "Request rejected by the provider";
    case "parse_error": return "Unreadable response";
    case "bot_challenge": return "Blocked by a bot-challenge page";
    case "wappalyzer_unavailable": return "Fingerprint data unavailable";
    case "feed_unavailable": return "Feed not downloaded yet";
    case "stale_feed": return "Feed is out of date — using the last downloaded copy";
    case "suspicious_shrink": return "The download looked truncated — kept the previous copy";
    case "not_found_upstream": return "Feed URL not found";
    case "tls_handshake_failed": return "TLS handshake failed";
    case "whois_failed": return "WHOIS fallback failed";
    case "bootstrap_failed": return "RDAP service directory unavailable";
    case "no_resolved_ip": return "No public IP address was found to ask about";
    case "not_applicable": return "Does not apply to this kind of target";
    case "response_too_large": return "The answer was too large to read (a very busy domain)";
    case "disabled": return "Switched off in settings";
    case "not_configured": return "Not configured";
    case "no_registered_domain": return "No registered domain to look up";
    case "no_rdap_for_tld": return "This TLD publishes no RDAP data";
    case "no_registration_date": return "The registry publishes no registration date";
    case "no_assessable_technologies": return "No versioned technology to check";
    case "no_analysis": return "No analysis available yet";
    case "ip_literal": return "IP addresses have no host name to check";
    case "private_name":
    case "single_label":
    case "private_address":
    case "invalid_name":
      return "Private or local name — never sent to third parties";
    default: return reason;
  }
}

// ── "based on N of M sources" ───────────────────────────────────────────────
export interface MissingSource {
  source: string;
  label: string;
  status: ProviderOutcome["status"];
  detail: string;
}

export interface EvidenceSummary {
  /** Sources that answered with data. */
  answered: number;
  /** Sources that applied to this target (answered, no record or failed; `skipped` and `not_configured` are excluded). */
  applicable: number;
  missing: MissingSource[];
  text: string;
  level: "complete" | "partial" | "none";
}

// A source with no key is not part of this scan: it is hidden (never listed as "not configured") and not counted in "N of M".
const APPLICABLE: ReadonlyArray<ProviderOutcome["status"]> = ["ok", "not_found", "error"];

/** The outcomes worth showing: everything except sources that were never usable here (no key). */
export function visibleOutcomes<T extends { status: string }>(outcomes: T[] | undefined | null): T[] {
  return (outcomes ?? []).filter((o) => o.status !== "not_configured");
}

export function summarizeEvidence(outcomes: ProviderOutcome[] | undefined | null): EvidenceSummary {
  if (!outcomes) {
    return { answered: 0, applicable: 0, missing: [], text: "No sources were queried", level: "none" };
  }
  const applicable = outcomes.filter((o) => APPLICABLE.includes(o.status));
  const answered = applicable.filter((o) => o.status === "ok");
  const missing = applicable
    .filter((o) => o.status !== "ok")
    .map((o): MissingSource => ({
      source: o.source,
      label: sourceLabel(o.source),
      status: o.status,
      detail:
        humanReason(o.reason, o.retry_after) ??
        (o.status === "not_found" ? "No record of this target" : "Unavailable"),
    }));
  const level = applicable.length > 0 && answered.length === applicable.length ? "complete" : answered.length === 0 ? "none" : "partial";
  const text = applicable.length === 0 ? "No sources were queried" : `Based on ${answered.length} of ${applicable.length} sources`;
  return { answered: answered.length, applicable: applicable.length, missing, text, level };
}

/** The caution shown next to a score. Absence of findings is never worded as safety. */
export function evidenceCaution(verdict: "ok" | "partial" | "unknown" | undefined | null): string | null {
  switch (verdict) {
    case "ok":
      return "No findings ≠ safe. These sources had nothing to report; that does not prove the target is harmless.";
    case "partial":
      return "No findings ≠ safe. Some sources did not answer, so this score rests on partial evidence.";
    case "unknown":
      return "Risk unknown — there is no reputation evidence for this target. Absence of evidence is not evidence of safety.";
    default:
      return null;
  }
}

// ── per-feature provenance ──────────────────────────────────────────────────
/** feature name → the providers that supply it (first = primary). */
export const FEATURE_SOURCES: Record<string, string[]> = {
  vt_malicious_ratio: ["virustotal"],
  vt_suspicious_ratio: ["virustotal"],
  vt_reputation_score: ["virustotal"],
  vt_last_seen_days_ago: ["virustotal"],
  shodan_open_port_count: ["shodan_internetdb"],
  shodan_has_high_risk_port: ["shodan_internetdb"],
  shodan_cve_count: ["shodan_internetdb"],
  shodan_max_cvss_score: ["nvd", "shodan_internetdb"],
  shodan_has_iot_tag: ["shodan_internetdb"],
  shodan_has_compromised_tag: ["shodan_internetdb"],
  shodan_service_diversity_score: ["shodan_internetdb"],
  shodan_high_risk_cpe_count: ["shodan_internetdb"],
  tech_count: ["tech_fingerprint"],
  tech_has_known_eol_component: ["tech_fingerprint", "endoflife"],
  tech_avg_confidence: ["tech_fingerprint"],
  tech_stack_diversity_count: ["tech_fingerprint"],
  tech_has_eol_cms_version: ["tech_fingerprint", "endoflife"],
  ssl_cert_valid: ["tls"],
  domain_age_days: ["rdap"],
};

export interface FeatureSourceChip {
  source: string;
  label: string;
  status: ChipState;
}

export interface FeatureRow {
  name: string;
  label: string;
  value: number | null;
  known: boolean;
  /** Why the value is unknown (which source failed / is missing), else null. */
  unknownWhy: string | null;
  sources: FeatureSourceChip[];
}

function featureLabel(name: string): string {
  return name.replace(/_/g, " ");
}

export function featureProvenance(
  features: Record<string, number | null | undefined> | null | undefined,
  outcomes: ProviderOutcome[] | undefined | null,
): FeatureRow[] {
  if (!features) return [];
  const bySource = new Map((outcomes ?? []).map((o) => [o.source, o]));
  return Object.entries(features).map(([name, raw]) => {
    const value = raw ?? null;
    const sources = (FEATURE_SOURCES[name] ?? []).map((source): FeatureSourceChip => ({
      source,
      label: sourceLabel(source),
      // A source that never ran for this target (or an older scan without that outcome) reads as "skipped".
      status: (bySource.get(source)?.status ?? "skipped") as ChipState,
    }));
    let unknownWhy: string | null = null;
    if (value === null) {
      // Blame a failed source first, then a missing one, then one that never ran.
      const failed = (FEATURE_SOURCES[name] ?? []).map((s) => bySource.get(s)).find((o) => o?.status === "error");
      const missing = (FEATURE_SOURCES[name] ?? []).map((s) => bySource.get(s)).find((o) => o && (o.status === "not_configured" || o.status === "not_found"));
      const skipped = (FEATURE_SOURCES[name] ?? []).map((s) => bySource.get(s)).find((o) => o?.status === "skipped");
      const culprit = failed ?? missing ?? skipped;
      if (culprit) {
        const why =
          humanReason(culprit.reason, culprit.retry_after) ??
          (culprit.status === "not_found" ? "no record of this target" : culprit.status === "not_configured" ? "not configured" : "unavailable");
        unknownWhy = `${sourceLabel(culprit.source)}: ${why}`;
      } else {
        unknownWhy = "not collected for this target";
      }
    }
    return { name, label: featureLabel(name), value, known: value !== null, unknownWhy, sources };
  });
}

// ── live progress (Server-Sent Events from GET /scan/{id}/events) ───────────
export type ScanEvent =
  | { type: "start"; scan_id: string; target_type: string; providers: string[] }
  | {
      type: "provider";
      source: string;
      status: "running" | "ok" | "not_found" | "error" | "skipped" | "not_configured";
      reason?: string | null;
      cached?: boolean;
      latency_ms?: number | null;
      retry_after?: number | null;
    }
  | { type: "stage"; stage: string }
  | { type: "done"; scan_id: string; verdict_status?: string; success?: boolean }
  | { type: "error"; scan_id: string; message?: string }
  | { type: "timeout" };

export interface LiveChip {
  status: ChipState;
  reason?: string | null;
  cached?: boolean;
  latency_ms?: number | null;
  retry_after?: number | null;
}

export interface LiveState {
  chips: Record<string, LiveChip>;
  /** Sources in first-seen order (the expected ones first, conditional ones as they start). */
  order: string[];
  stage?: string;
  finished: boolean;
  failed: boolean;
}

export function emptyLiveState(): LiveState {
  return { chips: {}, order: [], finished: false, failed: false };
}

export function applyLiveEvent(state: LiveState, event: ScanEvent): LiveState {
  switch (event.type) {
    case "start": {
      const chips = { ...state.chips };
      const order = [...state.order];
      for (const source of event.providers) {
        if (!chips[source]) {
          chips[source] = { status: "pending" };
          order.push(source);
        }
      }
      return { ...state, chips, order };
    }
    case "provider": {
      const order = state.order.includes(event.source) ? state.order : [...state.order, event.source];
      const chip: LiveChip = {
        status: event.status,
        reason: event.reason ?? null,
        cached: event.cached,
        latency_ms: event.latency_ms ?? null,
        retry_after: event.retry_after ?? null,
      };
      return { ...state, order, chips: { ...state.chips, [event.source]: chip } };
    }
    case "stage":
      return { ...state, stage: event.stage };
    case "done":
      return { ...state, finished: true, failed: event.success === false };
    case "error":
    case "timeout":
      return { ...state, finished: true, failed: true };
    default:
      return state;
  }
}
