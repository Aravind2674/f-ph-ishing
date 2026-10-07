/** Headline verdict view model (revamp T3b/T3c): null renders as "—" never 0; the headline names the channel that drove it. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { DASH, scoreText, verdictView } from "./verdict.ts";
import type { ScanResult } from "../api.ts";

type Input = Parameters<typeof verdictView>[0];
const base = (over: Partial<Input> = {}): Input => ({
  baseline_score: 0.12, baseline_label: "Low", ml_score: 0.95, ml_label: "Critical", headline_band: "Critical", driven_by: "url_model",
  agreement: false, baseline_terms: [], url_risk: null, ...over,
});

test("a missing score is a dash, never zero", () => {
  assert.equal(scoreText(null), DASH);
  assert.equal(scoreText(undefined), DASH);
  assert.equal(scoreText(0), "0");                 // a real zero is still shown as 0
  const v = verdictView(base({ baseline_score: null, baseline_label: "Unknown", ml_score: null, ml_label: "Unknown", headline_band: null, driven_by: null, agreement: null }));
  assert.equal(v.headline, DASH);
  assert.deepEqual(v.channels.map((c) => c.text), [DASH, DASH]);
  assert.deepEqual(v.channels.map((c) => c.band), [null, null]);
  assert.equal(v.reason, "No channel produced a score");
});

test("scores are shown as computed (0..1 -> 0..100), not adjusted to agree", () => {
  const v = verdictView(base({ baseline_score: 0.034, ml_score: 0.9999 }));
  assert.equal(v.channels[0].text, "100");
  assert.equal(v.channels[1].text, "3");
  assert.equal(v.disagree, true);
});

test("URL model drives: the reason names the provider band", () => {
  const v = verdictView(base());
  assert.equal(v.headline, "Critical");
  assert.equal(v.reason, "Flagged by the URL model — provider evidence is Low");
});

test("provider evidence drives: says the URL text looks benign and lists the top reasons", () => {
  const v = verdictView(base({
    baseline_score: 0.8, baseline_label: "Critical", ml_score: 0.03, ml_label: "Low", headline_band: "Critical", driven_by: "provider_evidence",
    baseline_terms: [{ text: "6 antivirus engines flag it", weight: 0.5 }, { text: "RDP port open", weight: 0.15 }, { text: "newly registered", weight: 0.04 }, { text: "ten ports open", weight: 0.01 }],
  }));
  assert.equal(v.reason, "Flagged by provider evidence — URL text looks benign");
  assert.deepEqual(v.providerReasons, ["6 antivirus engines flag it", "RDP port open", "newly registered"]);
  assert.equal(v.disagree, true);
});

test("no provider answered: the URL model carries the verdict and says so", () => {
  const v = verdictView(base({ baseline_score: null, baseline_label: "Unknown", agreement: null }));
  assert.equal(v.reason, "Flagged by the URL model — no provider evidence");
  assert.equal(v.disagree, false);                 // nothing to disagree with
  assert.equal(v.channels[1].text, DASH);
});

test("both channels in one band", () => {
  const v = verdictView(base({ baseline_score: 0.8, baseline_label: "Critical", driven_by: "both", agreement: true }));
  assert.equal(v.reason, "Both channels agree");
  assert.equal(v.disagree, false);
});

test("a low headline is not described as flagged", () => {
  const v = verdictView(base({ baseline_score: 0.05, baseline_label: "Low", ml_score: 0.04, ml_label: "Low", headline_band: "Low", driven_by: "both", agreement: true }));
  assert.equal(v.reason, "Low on every channel that answered");
});

test("a low URL band with no provider answering is not described as a clearance", () => {
  const v = verdictView(base({ baseline_score: null, baseline_label: "Unknown", ml_score: 0.02, ml_label: "Low", headline_band: "Low", driven_by: "url_model", agreement: null, verdict_status: "unknown" }));
  assert.equal(v.reason, "URL text looks benign; no provider answered, so this is not a clearance");
});

test("the URL model's what-if at realistic prevalence is carried through", () => {
  const url_risk = { at_prevalence: { "1%": 0.12, "0.1%": 0.014 }, flagged: true } as unknown as ScanResult["url_risk"];
  assert.equal(verdictView(base({ url_risk })).prevalence, "At 1 % phishing: 12 %");
  assert.equal(verdictView(base()).prevalence, null);
});
