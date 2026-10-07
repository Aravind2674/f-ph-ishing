/** The evidence table (revamp T1c): one row per applicable source; a source that did not answer shows why, never a made-up value. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { evidenceTable, latencyText, liveRows, shapRows } from "./scanview.ts";
import { applyLiveEvent, emptyLiveState } from "./evidence.ts";
import { DASH } from "./verdict.ts";
import type { ProviderOutcome, RiskExplanation, ScanResult } from "../api.ts";

const NOW = new Date("2026-01-01T00:00:00Z");
const outcome = (source: string, status: ProviderOutcome["status"], over: Partial<ProviderOutcome> = {}): ProviderOutcome => ({
  source, status, fetched_at: "2026-01-01T00:00:00Z", cached: false, latency_ms: 120, ...over,
});
const scan = (provider_results: ProviderOutcome[], over: Record<string, unknown> = {}): ScanResult =>
  ({ provider_results, verdict_status: "ok", ...over }) as unknown as ScanResult;

test("rows keep the backend's order, and a source with no key is counted, not listed", () => {
  const t = evidenceTable(scan([outcome("virustotal", "ok"), outcome("otx", "not_configured"), outcome("tls", "ok"), outcome("abuseipdb", "not_configured")]), NOW);
  assert.deepEqual(t.rows.map((r) => r.source), ["virustotal", "tls"]);
  assert.equal(t.notConfigured, 2);
});

test("VirusTotal reads as engines out of total; a clean count is not flagged", () => {
  const hit = evidenceTable(scan([outcome("virustotal", "ok")], { virustotal: { malicious_count: 3, suspicious_count: 1, total_engines: 72 } }), NOW).rows[0];
  assert.equal(hit.value, "3 of 72 engines malicious, 1 suspicious");
  assert.equal(hit.flag, true);
  const clean = evidenceTable(scan([outcome("virustotal", "ok")], { virustotal: { malicious_count: 0, total_engines: 72 } }), NOW).rows[0];
  assert.equal(clean.value, "0 of 72 engines malicious");
  assert.equal(clean.flag, false);
});

test("an answered source whose data is missing shows a dash, not zero", () => {
  const row = evidenceTable(scan([outcome("virustotal", "ok"), outcome("shodan_internetdb", "ok")], { virustotal: null, shodan: null }), NOW).rows;
  assert.deepEqual(row.map((r) => r.value), [DASH, DASH]);
});

test("a failed or skipped source shows why, with no value and no facts", () => {
  const rows = evidenceTable(scan([
    outcome("virustotal", "error", { reason: "rate_limited", retry_after: 30 }),
    outcome("rdap", "error", { reason: "timeout" }),
    outcome("dns", "skipped", { reason: "ip_literal" }),
    outcome("ct", "error"),
  ], { virustotal: { malicious_count: 9, total_engines: 70 } }), NOW).rows;
  assert.deepEqual(rows.map((r) => r.value), ["Rate limited — retry in 30s", "Timed out", "IP addresses have no host name to check", "Unavailable"]);
  assert.deepEqual(rows.map((r) => r.status), ["failed", "failed", "skipped", "failed"]);
  assert.ok(rows.every((r) => r.facts.length === 0 && !r.flag), "stale data from a failed call must not leak into the row");
});

test("no record is said as such, in the source's words when it gives a reason", () => {
  const rows = evidenceTable(scan([outcome("urlhaus", "not_found"), outcome("rdap", "not_found", { reason: "no_registration_date" })]), NOW).rows;
  assert.deepEqual(rows.map((r) => r.value), ["No record", "The registry publishes no registration date"]);
  assert.deepEqual(rows.map((r) => r.status), ["no record", "no record"]);
});

test("open ports and CVEs come from InternetDB; the lists are in the opened row", () => {
  const row = evidenceTable(scan([outcome("shodan_internetdb", "ok")], { shodan: { open_ports: [22, 443], vulns: ["CVE-2021-1"], hostnames: ["a.example"], cpes: [], tags: [] } }), NOW).rows[0];
  assert.equal(row.value, "2 open ports, 1 CVE");
  assert.deepEqual(row.facts, [{ label: "Ports", value: "22, 443" }, { label: "Hostnames", value: "a.example" }]);
  assert.equal(row.flag, true);
});

test("NVD: counts, worst score and one line per CVE", () => {
  const row = evidenceTable(scan([outcome("nvd", "ok")], { cve: { total_cves: 2, max_cvss_score: 9.8, cves: [{ cve_id: "CVE-1", cvss_v3_score: 9.8 }, { cve_id: "CVE-2" }] } }), NOW).rows[0];
  assert.equal(row.value, "2 CVEs, max CVSS 9.8");
  assert.deepEqual(row.facts.map((f) => [f.label, f.value]), [["CVE-1", "CVSS 9.8"], ["CVE-2", "unscored"]]);
  assert.equal(row.flag, true);
});

test("EPSS, KEV and SSVC say so when there is nothing to assess", () => {
  const exposure = { cves_total: 0, cves_assessed: 0, kev_count: 0, max_epss: null, cves: [] };
  const rows = evidenceTable(scan([outcome("epss", "ok"), outcome("kev", "ok"), outcome("vulnrichment", "ok")], { exposure }), NOW).rows;
  assert.deepEqual(rows.map((r) => r.value), ["No CVEs to assess", "No CVEs to check", "No CVEs to assess"]);
});

test("KEV membership is flagged", () => {
  const exposure = { cves_total: 3, cves_assessed: 3, kev_count: 1, max_epss: 0.123, cves: [] };
  const rows = evidenceTable(scan([outcome("epss", "ok"), outcome("kev", "ok")], { exposure }), NOW).rows;
  assert.equal(rows[0].value, "max 12.3 % exploitation chance");
  assert.equal(rows[1].value, "1 of 3 CVEs in KEV");
  assert.equal(rows[1].flag, true);
});

test("technologies and end-of-life are two rows; end-of-life components are listed and flagged", () => {
  const tech_fingerprint = { technologies: [{ name: "PHP", version: "5.6", categories: [], confidence: 100, eol: true, eol_date: "2018-12-31" }, { name: "nginx", version: "1.25", categories: [], confidence: 100, eol: false }, { name: "jQuery", categories: [], confidence: 50 }], eol_assessed: 2 };
  const [tech, eol] = evidenceTable(scan([outcome("tech_fingerprint", "ok"), outcome("endoflife", "ok")], { tech_fingerprint }), NOW).rows;
  assert.equal(tech.value, "3 technologies");
  assert.equal(eol.value, "1 of 2 end-of-life");
  assert.equal(eol.flag, true);
  assert.equal(eol.facts[0].label, "PHP 5.6");
});

test("TLS: an invalid certificate is flagged; the facts are kept for the opened row", () => {
  const tls = { host: "a.test", has_tls: true, chain_valid: false, verify_error: "self_signed", issuer_cn: "a.test", san_matches_host: true, not_after: "2027-01-01T00:00:00Z" };
  const row = evidenceTable(scan([outcome("tls", "ok")], { tls }), NOW).rows[0];
  assert.equal(row.value, "Invalid certificate — self-signed");
  assert.equal(row.flag, true);
  assert.ok(row.facts.some((f) => f.label === "Issuer"));
});

test("registration: a missing date is 'not published', a new domain is flagged", () => {
  const unknown = evidenceTable(scan([outcome("rdap", "ok")], { rdap: { domain: "a.test", registered_at: null, registrar: null } }), NOW).rows[0];
  assert.equal(unknown.value, "Registration date not published");
  assert.equal(unknown.flag, false);
  const fresh = evidenceTable(scan([outcome("rdap", "ok")], { rdap: { domain: "a.test", registered_at: "2025-12-20T00:00:00Z" } }), NOW).rows[0];
  assert.equal(fresh.value, "Registered 12 days ago");
  assert.equal(fresh.flag, true);
});

test("DNS shows the addresses; a failed lookup family stays unknown", () => {
  const dns = { host: "a.test", lookup_domain: "a.test", a: ["192.0.2.1"], aaaa: null, mx: null, ns: [], failed_types: ["MX"] };
  const row = evidenceTable(scan([outcome("dns", "ok")], { dns }), NOW).rows[0];
  assert.equal(row.value, "192.0.2.1");
  assert.ok(row.facts.some((f) => f.label === "Mail (MX)" && f.value.includes("unknown")));
});

test("a reputation listing is flagged and carries its record; 'not listed' is not worded as safe", () => {
  const reputation = {
    channels_applicable: 2, channels_answered: 2, listed_by: ["urlhaus"], popularity_rank: null, feed_ages: {}, notes: [],
    verdicts: [
      { source: "urlhaus", listed: true, category: "malware", match: "exact_url", score: null, detail: "payload delivery", reference: "https://urlhaus.abuse.ch/url/1/", last_seen: null, feed_age_days: null, stale: false, extra: {} },
      { source: "openphish", listed: false, category: null, match: null, score: null, detail: null, reference: null, last_seen: null, feed_age_days: 0.5, stale: false, extra: {} },
    ],
  };
  const [hit, miss] = evidenceTable(scan([outcome("urlhaus", "ok"), outcome("openphish", "ok")], { reputation }), NOW).rows;
  assert.equal(hit.value, "Listed — payload delivery");
  assert.equal(hit.flag, true);
  assert.deepEqual(hit.facts, [{ label: "Matched", value: "this exact URL" }, { label: "Record", value: "https://urlhaus.abuse.ch/url/1/" }]);
  assert.equal(miss.flag, false);
  assert.doesNotMatch(miss.value, /safe|clean/i);
});

test("Tranco: a rank is shown, no rank is 'Not ranked'", () => {
  const base = { channels_applicable: 1, channels_answered: 1, listed_by: [], verdicts: [], feed_ages: {}, notes: [] };
  assert.equal(evidenceTable(scan([outcome("tranco", "ok")], { reputation: { ...base, popularity_rank: 1234 } }), NOW).rows[0].value, "Rank #1,234");
  assert.equal(evidenceTable(scan([outcome("tranco", "ok")], { reputation: { ...base, popularity_rank: null } }), NOW).rows[0].value, "Not ranked");
});

test("the local brand check is a row without a latency", () => {
  const brand_check = { status: "lookalike", match: { brand: "HDFC Bank", matched: "hdfcbank-login", evidence: ["typo of hdfcbank"] }, official_of: null, candidates: [] };
  const row = evidenceTable(scan([], { brand_check }), NOW).rows[0];
  assert.equal(row.value, "Imitates HDFC Bank");
  assert.equal(row.flag, true);
  assert.equal(latencyText(row), DASH);
  assert.equal(evidenceTable(scan([]), NOW).rows.length, 0);
});

test("latency: cached beats a number, a missing latency is a dash", () => {
  assert.equal(latencyText({ latencyMs: 812.4, cached: false }), "812 ms");
  assert.equal(latencyText({ latencyMs: 12, cached: true }), "cached");
  assert.equal(latencyText({ latencyMs: null, cached: false }), DASH);
});

test("the summary counts only the sources that applied, and the caution never says safe", () => {
  const t = evidenceTable(scan([outcome("virustotal", "ok"), outcome("rdap", "error", { reason: "timeout" }), outcome("otx", "not_configured")], { verdict_status: "partial" }), NOW);
  assert.equal(t.summary, "Based on 1 of 2 sources");
  assert.match(t.caution!, /No findings ≠ safe/);
});

test("live rows follow the progress events and show a failure's reason", () => {
  let live = emptyLiveState();
  live = applyLiveEvent(live, { type: "start", scan_id: "x", target_type: "domain", providers: ["virustotal", "rdap", "otx"] });
  live = applyLiveEvent(live, { type: "provider", source: "virustotal", status: "ok", latency_ms: 300 });
  live = applyLiveEvent(live, { type: "provider", source: "rdap", status: "error", reason: "timeout" });
  live = applyLiveEvent(live, { type: "provider", source: "otx", status: "not_configured" });
  const rows = liveRows(live);
  assert.deepEqual(rows.map((r) => [r.source, r.status, r.value]), [["virustotal", "ok", DASH], ["rdap", "failed", "Timed out"]]);
  assert.equal(rows[0].latencyMs, 300);
});

const shap = (over: Partial<RiskExplanation> & { feature_name: string }): RiskExplanation => ({
  feature_value: 1, shap_value: 0.5, human_readable: "Imitates a protected brand: yes — raises the score by 0.50 log-odds", unit: "log-odds", probability_delta: 0.12, ...over,
});

test("SHAP rows: strongest first, log-odds with sign, the what-if in probability points", () => {
  const rows = shapRows([
    shap({ feature_name: "small", shap_value: 0.1, probability_delta: 0.01 }),
    shap({ feature_name: "big", shap_value: -1.234, probability_delta: -0.2, human_readable: "Resembles a protected brand: rule score 0.95 — lowers the score by 1.23 log-odds" }),
    shap({ feature_name: "none", shap_value: 0.05, probability_delta: null }),
  ]);
  assert.deepEqual(rows.map((r) => r.key.split("-")[0]), ["big", "small", "none"]);
  assert.equal(rows[0].text, "Resembles a protected brand: rule score 0.95");
  assert.equal(rows[0].logOdds, "−1.234");
  assert.equal(rows[0].points, "−20 pts");
  assert.equal(rows[0].raises, false);
  assert.equal(rows[0].share, 1);
  assert.equal(rows[1].points, "+1 pts");
  assert.equal(rows[2].points, null, "no what-if from the backend stays missing, never 0");
});

test("SHAP rows: capped at the top six, empty input is empty", () => {
  const many = Array.from({ length: 9 }, (_, i) => shap({ feature_name: `f${i}`, shap_value: i + 1 }));
  assert.equal(shapRows(many).length, 6);
  assert.deepEqual(shapRows(null), []);
  assert.deepEqual(shapRows(undefined), []);
});
