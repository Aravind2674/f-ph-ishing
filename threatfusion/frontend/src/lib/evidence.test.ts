/**
 * Tests for the evidence-first view model (A1-7). Plain Node test runner, no extra dependency:
 *   npm test        (= node --test "src/lib/*.test.ts" — Node ≥ 22.18 strips the types)
 *
 * What is pinned down: how many sources a score rests on, that "no findings" is never worded as "safe", that an
 * unknown feature says *why* it is unknown (which source failed, in plain words), and how live progress events fold
 * into per-source chips.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  FEATURE_SOURCES,
  applyLiveEvent,
  emptyLiveState,
  evidenceCaution,
  featureProvenance,
  humanReason,
  sourceLabel,
  summarizeEvidence,
  visibleOutcomes,
  type LiveState,
} from "./evidence.ts";
import type { ProviderOutcome } from "../api.ts";

const NOW = "2026-10-04T12:00:00Z";
const outcome = (source: string, status: ProviderOutcome["status"], extra: Partial<ProviderOutcome> = {}): ProviderOutcome => ({
  source,
  status,
  fetched_at: NOW,
  cached: false,
  ...extra,
});

const FEATURES = [
  "vt_malicious_ratio", "vt_suspicious_ratio", "vt_reputation_score", "vt_last_seen_days_ago",
  "shodan_open_port_count", "shodan_has_high_risk_port", "shodan_cve_count", "shodan_max_cvss_score",
  "shodan_has_iot_tag", "shodan_has_compromised_tag", "shodan_service_diversity_score", "shodan_high_risk_cpe_count",
  "tech_count", "tech_has_known_eol_component", "tech_avg_confidence", "tech_stack_diversity_count",
  "tech_has_eol_cms_version", "ssl_cert_valid", "domain_age_days",
];

// ── "based on N of M sources" ───────────────────────────────────────────────
test("a score says how many sources it rests on", () => {
  const outcomes = [
    outcome("virustotal", "ok"),
    outcome("shodan_internetdb", "ok"),
    outcome("nvd", "error", { reason: "rate_limited", retry_after: 42 }),
    outcome("tech_fingerprint", "ok"),
    outcome("tls", "ok"),
    outcome("rdap", "not_found"),
    outcome("dns", "error", { reason: "timeout" }),
  ];
  const s = summarizeEvidence(outcomes);
  assert.equal(s.answered, 4);
  assert.equal(s.applicable, 7);
  assert.equal(s.text, "Based on 4 of 7 sources");
  assert.equal(s.level, "partial");
  assert.deepEqual(s.missing.map((m) => m.source), ["nvd", "rdap", "dns"]);
  assert.match(s.missing[0].detail, /Rate limited — retry in 42s/);
});

test("skipped sources are not applicable and are not counted against the score", () => {
  const s = summarizeEvidence([
    outcome("virustotal", "ok"),
    outcome("tls", "skipped", { reason: "disabled" }),
    outcome("rdap", "skipped", { reason: "no_registered_domain" }),
  ]);
  assert.equal(s.text, "Based on 1 of 1 sources");
  assert.equal(s.level, "complete");
});

test("no answering source reads as no evidence, not as zero risk", () => {
  const none = summarizeEvidence([outcome("virustotal", "error", { reason: "auth" }), outcome("dns", "error", { reason: "timeout" })]);
  assert.equal(none.level, "none");
  assert.equal(none.text, "Based on 0 of 2 sources");
  assert.equal(summarizeEvidence(undefined).text, "No sources were queried");
  assert.equal(summarizeEvidence([]).level, "none");
});

test("'no record' counts as missing evidence", () => {
  const s = summarizeEvidence([outcome("virustotal", "ok"), outcome("nvd", "error", { reason: "timeout" }), outcome("rdap", "not_found")]);
  assert.equal(s.answered, 1);
  assert.equal(s.applicable, 3);
});

test("a source without a key is hidden, not listed as 'not configured', and not counted", () => {
  const outcomes = [outcome("virustotal", "ok"), outcome("urlhaus", "not_configured"), outcome("abuseipdb", "not_configured")];
  const s = summarizeEvidence(outcomes);
  assert.equal(s.text, "Based on 1 of 1 sources");
  assert.deepEqual(s.missing, []);
  assert.deepEqual(visibleOutcomes(outcomes).map((o) => o.source), ["virustotal"]);
  assert.deepEqual(visibleOutcomes(undefined), []);
});

// ── wording ─────────────────────────────────────────────────────────────────
test("'no findings' is never worded as 'safe'", () => {
  for (const verdict of ["ok", "partial"] as const) {
    const text = evidenceCaution(verdict)!;
    assert.match(text, /No findings ≠ safe/);
    assert.doesNotMatch(text, /\bis safe\b|\bsafe to\b|\bnothing to worry\b/i);
  }
  assert.match(evidenceCaution("unknown")!, /no reputation evidence/i);
  assert.equal(evidenceCaution(undefined), null);
});

test("reason codes are explained in plain words", () => {
  assert.equal(humanReason(null), null);
  assert.equal(humanReason("timeout"), "Timed out");
  assert.equal(humanReason("rate_limited"), "Rate limited");
  assert.equal(humanReason("rate_limited", 90), "Rate limited — retry in 90s");
  assert.equal(humanReason("auth"), "Credential rejected (check the API key)");
  assert.equal(humanReason("disabled"), "Switched off in settings");
  assert.match(humanReason("blocked:blocked_address")!, /safety policy/);
  assert.match(humanReason("private_name")!, /never sent to third parties/);
  assert.equal(humanReason("partial:3/5"), "Partial — 3/5");
  assert.equal(humanReason("truncated:4/5"), "Truncated 4/5");
  assert.equal(humanReason("something_new"), "something_new", "unknown codes are shown, not hidden");
});

// ── per-feature provenance ──────────────────────────────────────────────────
test("every feature the backend produces is mapped to the source that supplies it", () => {
  for (const name of FEATURES) {
    assert.ok(FEATURE_SOURCES[name]?.length, `${name} has no provenance mapping`);
  }
  assert.deepEqual(FEATURE_SOURCES["ssl_cert_valid"], ["tls"]);
  assert.deepEqual(FEATURE_SOURCES["domain_age_days"], ["rdap"]);
  assert.ok(FEATURE_SOURCES["tech_has_known_eol_component"].includes("endoflife"));
});

test("a known feature shows its value and its source; an unknown one says why", () => {
  const features: Record<string, number | null> = Object.fromEntries(FEATURES.map((f) => [f, null]));
  features["vt_malicious_ratio"] = 0.2;
  features["domain_age_days"] = 3;
  const rows = featureProvenance(features, [
    outcome("virustotal", "ok"),
    outcome("rdap", "ok"),
    outcome("tls", "error", { reason: "timeout" }),
    outcome("endoflife", "error", { reason: "server_error" }),
  ]);
  const byName = Object.fromEntries(rows.map((r) => [r.name, r]));

  assert.equal(byName["vt_malicious_ratio"].known, true);
  assert.equal(byName["vt_malicious_ratio"].unknownWhy, null);
  assert.deepEqual(byName["vt_malicious_ratio"].sources.map((s) => [s.source, s.status]), [["virustotal", "ok"]]);

  const ssl = byName["ssl_cert_valid"];
  assert.equal(ssl.known, false);
  assert.match(ssl.unknownWhy!, /TLS certificate/);
  assert.match(ssl.unknownWhy!, /Timed out/);

  assert.match(byName["tech_has_known_eol_component"].unknownWhy!, /endoflife\.date/);
  assert.match(byName["shodan_open_port_count"].unknownWhy!, /not collected/i, "a source that never ran is said to be 'not collected'");
});

test("an unknown feature blames a failed source before a missing one", () => {
  const rows = featureProvenance({ shodan_max_cvss_score: null }, [
    outcome("shodan_internetdb", "ok"),
    outcome("nvd", "not_configured"),
  ]);
  assert.match(rows[0].unknownWhy!, /NVD/);
  assert.match(rows[0].unknownWhy!, /not configured/i);
});

test("features absent from older scans do not crash the table", () => {
  assert.deepEqual(featureProvenance(undefined, []), []);
  assert.deepEqual(featureProvenance(null, []), []);
});

// ── live progress ───────────────────────────────────────────────────────────
test("live events fold into per-source chips", () => {
  let s: LiveState = emptyLiveState();
  s = applyLiveEvent(s, { type: "start", scan_id: "x", target_type: "domain", providers: ["virustotal", "tls"] });
  assert.deepEqual(s.order, ["virustotal", "tls"]);
  assert.equal(s.chips["virustotal"].status, "pending");

  s = applyLiveEvent(s, { type: "provider", source: "virustotal", status: "running" });
  s = applyLiveEvent(s, { type: "provider", source: "tls", status: "running" });
  assert.equal(s.chips["tls"].status, "running");

  s = applyLiveEvent(s, { type: "provider", source: "virustotal", status: "ok", cached: true, latency_ms: 12, reason: null });
  assert.equal(s.chips["virustotal"].status, "ok");
  assert.equal(s.chips["virustotal"].cached, true);

  // a conditional provider (NVD only runs when InternetDB lists CVEs) appears when it starts
  s = applyLiveEvent(s, { type: "provider", source: "nvd", status: "running" });
  assert.deepEqual(s.order, ["virustotal", "tls", "nvd"]);

  s = applyLiveEvent(s, { type: "provider", source: "tls", status: "error", reason: "timeout" });
  assert.equal(s.chips["tls"].reason, "timeout");

  s = applyLiveEvent(s, { type: "stage", stage: "scoring" });
  assert.equal(s.stage, "scoring");
  assert.equal(s.finished, false);

  s = applyLiveEvent(s, { type: "done", scan_id: "x", verdict_status: "partial", success: true });
  assert.equal(s.finished, true);
  assert.equal(s.failed, false);
});

test("applyLiveEvent never mutates its input and tolerates junk", () => {
  const s0 = emptyLiveState();
  const s1 = applyLiveEvent(s0, { type: "provider", source: "dns", status: "running" });
  assert.deepEqual(s0.order, []);
  assert.deepEqual(s1.order, ["dns"]);
  const s2 = applyLiveEvent(s1, { type: "totally-new" } as never);
  assert.deepEqual(s2.order, ["dns"]);
  const failed = applyLiveEvent(s1, { type: "error", scan_id: "x", message: "The scan failed." });
  assert.equal(failed.failed, true);
  assert.equal(failed.finished, true);
});

test("source labels are human, unknown sources fall back to their id", () => {
  assert.equal(sourceLabel("virustotal"), "VirusTotal");
  assert.equal(sourceLabel("endoflife"), "endoflife.date");
  assert.equal(sourceLabel("brand_new_source"), "brand_new_source");
});
