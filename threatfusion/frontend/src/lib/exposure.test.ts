/** Tests for the exploit-exposure view model (B11): unknown is said, severity is not exposure, feeds show their age. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { CATEGORY_MEANING, exposureView, feedAgeText } from "./exposure.ts";
import { humanReason, sourceLabel } from "./evidence.ts";
import type { ExposureAssessment, ExposureCve } from "../api.ts";

const cve = (over: Partial<ExposureCve> & { cve_id: string }): ExposureCve => ({
  cvss: null, epss: null, epss_percentile: null, epss_date: null, in_kev: null, kev_ransomware: null, kev_date_added: null,
  ssvc_exploitation: null, ssvc_automatable: null, ssvc_technical_impact: null, category: null, probability: null, basis: [], ...over,
});

const base = (over: Partial<ExposureAssessment> = {}): ExposureAssessment => ({
  score: 99, category: "Act", cves_total: 2, cves_assessed: 2, complete: true, kev_count: 1, max_epss: 0.94,
  cves: [], notes: [], method: "SSVC-style … not CISA's official decision tree", feed_ages: { kev: 0.4 }, ...over,
});

test("no assessment, no panel", () => {
  assert.equal(exposureView(null), null);
  assert.equal(exposureView(undefined), null);
});

test("the headline says what the score is — the chance at least one listed CVE is exploited — not 'risk'", () => {
  const v = exposureView(base())!;
  assert.equal(v.scoreText, "99%");
  assert.match(v.caption, /at least one/i);
  assert.match(v.caption, /exploited/i);
  assert.equal(v.category, "Act");
  assert.equal(v.coverage, "All 2 CVEs assessed");
});

test("an unassessable host reads 'Unknown', never 0%", () => {
  const v = exposureView(base({ score: null, category: null, cves_assessed: 0, complete: false, feed_ages: {} }))!;
  assert.equal(v.scoreText, "Unknown");
  assert.equal(v.category, null);
  assert.equal(v.coverage, "Based on 0 of 2 CVEs");
});

test("a host with no listed CVEs is a genuine 0%, labelled as such", () => {
  const v = exposureView(base({ score: 0, category: null, cves_total: 0, cves_assessed: 0, complete: true }))!;
  assert.equal(v.scoreText, "0%");
  assert.equal(v.coverage, "No vulnerabilities listed for this host");
});

test("partial coverage is stated", () => {
  const v = exposureView(base({ cves_assessed: 1, complete: false }))!;
  assert.equal(v.coverage, "Based on 1 of 2 CVEs");
});

test("small scores are not rounded away to zero", () => {
  assert.equal(exposureView(base({ score: 0.04 }))!.scoreText, "<1%");
  assert.equal(exposureView(base({ score: 12.6 }))!.scoreText, "13%");
});

test("each CVE row shows severity beside — not inside — the exploitation evidence", () => {
  const v = exposureView(base({
    cves: [cve({
      cve_id: "CVE-2021-44228", cvss: 10, epss: 0.94358, epss_percentile: 0.99991, in_kev: true, kev_ransomware: true,
      ssvc_exploitation: "active", ssvc_automatable: "yes", ssvc_technical_impact: "total", category: "Act", probability: 0.99,
    })],
  }))!;
  const r = v.rows[0];
  assert.equal(r.cve, "CVE-2021-44228");
  assert.equal(r.cvss, "10.0");
  assert.equal(r.epss, "94.4% · top 0.01%");
  assert.equal(r.kev, "In KEV · ransomware use");
  assert.equal(r.ssvc, "Exploitation active · Automatable yes · Impact total");
  assert.equal(r.category, "Act");
  assert.equal(r.probability, "99%");
});

test("KEV and EPSS keep three states in the row", () => {
  const rows = exposureView(base({
    cves: [
      cve({ cve_id: "CVE-A", in_kev: false, epss: 0.0004, epss_percentile: 0.08, category: "Track", probability: 0.0004 }),
      cve({ cve_id: "CVE-B", in_kev: null }),
      cve({ cve_id: "CVE-C", in_kev: true, kev_ransomware: false }),
    ],
  }))!.rows;
  assert.equal(rows[0].kev, "Not in KEV");
  assert.equal(rows[0].epss, "0.04% · top 92%");
  assert.equal(rows[1].kev, "KEV unknown");
  assert.equal(rows[1].epss, "unknown");
  assert.equal(rows[1].category, "not assessable");
  assert.equal(rows[1].probability, "unknown");
  assert.equal(rows[1].ssvc, "—");
  assert.equal(rows[2].kev, "In KEV");
  assert.equal(rows[0].cvss, "n/a");
});

test("every category has a plain-language meaning, ordered by urgency", () => {
  assert.deepEqual(Object.keys(CATEGORY_MEANING), ["Track", "Track*", "Attend", "Act"]);
  for (const text of Object.values(CATEGORY_MEANING)) assert.ok(text.length > 10);
  assert.match(CATEGORY_MEANING["Act"], /now|immediately|urgent/i);
});

test("the method is carried so the label 'SSVC-style' is never mistaken for CISA's decision", () => {
  const v = exposureView(base())!;
  assert.match(v.method, /not CISA/);
});

test("feed ages are in plain words and unknown stays unknown", () => {
  assert.equal(feedAgeText("KEV catalogue", 0.2), "KEV catalogue refreshed less than a day ago");
  assert.equal(feedAgeText("KEV catalogue", 3.4), "KEV catalogue refreshed 3 days ago");
  assert.equal(feedAgeText("KEV catalogue", 90), "KEV catalogue refreshed 3 months ago");
  assert.equal(feedAgeText("KEV catalogue", null), "KEV catalogue age unknown");
  assert.equal(exposureView(base({ feed_ages: { kev: 3.4 } }))!.feedLine, "KEV catalogue refreshed 3 days ago");
  assert.equal(exposureView(base({ feed_ages: {} }))!.feedLine, null);
});

test("the new sources have labels and their feed reason codes are explained", () => {
  assert.equal(sourceLabel("epss"), "EPSS");
  assert.equal(sourceLabel("kev"), "CISA KEV");
  assert.equal(sourceLabel("vulnrichment"), "CISA Vulnrichment");
  assert.match(humanReason("feed_unavailable")!, /not downloaded/i);
  assert.match(humanReason("stale_feed")!, /out of date/i);
  assert.match(humanReason("suspicious_shrink")!, /truncated/i);
});
