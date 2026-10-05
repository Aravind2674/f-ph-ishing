/** Tests for the calibrated URL-text card (A2): prevalence is stated, unavailable is not zero, units are shown. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { percentText, urlRiskView } from "./urlrisk.ts";
import type { RiskExplanation, UrlRiskAssessment } from "../api.ts";

const base = (over: Partial<UrlRiskAssessment> = {}): UrlRiskAssessment => ({
  applicable: true, score: 0.91, raw_score: 0.88, cnn_score: 0.84, baseline_score: 0.62, fused_score: 0.93, fusion_contributions: { xgb: 2.1, cnn: 1.2 },
  headline_score: 0.93, flagged: true, threshold: 0.47, threshold_basis: "false-positive rate ≤ 1 % on validation data",
  at_prevalence: { "1%": 0.12, "0.1%": 0.014 }, baseline_terms: [{ text: "the host imitates a protected brand", weight: 0.35 }],
  model_name: "url_xgb", model_version: "xgb-68874bb2", notes: ["This scores the URL text only."], ...over,
});
const ev = (over: Partial<RiskExplanation> & { feature_name: string }): RiskExplanation => ({
  feature_value: 1, shap_value: 0.5, human_readable: "Imitates a protected brand: yes — raises the score by 0.50 log-odds", unit: "log-odds",
  probability_delta: 0.12, group: "brand", ...over,
});

test("no assessment (or not applicable) means no card", () => {
  assert.equal(urlRiskView(null), null);
  assert.equal(urlRiskView(undefined), null);
  assert.equal(urlRiskView(base({ applicable: false })), null);
});

test("percent text never draws unknown as zero and never rounds a tiny probability to 0", () => {
  assert.equal(percentText(null), "not available");
  assert.equal(percentText(0.004), "<1 %");
  assert.equal(percentText(0.9993), ">99 %");
  assert.equal(percentText(0.5), "50 %");
});

test("the headline is followed by what the score means at realistic prevalence", () => {
  const v = urlRiskView(base())!;
  assert.equal(v.scoreText, "93 %");
  assert.deepEqual(v.prevalence, [{ label: "If 1% of URLs are phishing", value: "12 %" }, { label: "If 0.1% of URLs are phishing", value: "1 %" }]);
  assert.match(v.notes[0], /URL text only/);
});

test("the flag is tied to a stated operating point", () => {
  const v = urlRiskView(base())!;
  assert.equal(v.flagged, true);
  assert.match(v.verdict, /Flagged/);
  assert.match(v.basis, /false-positive rate ≤ 1 %/);
  assert.match(urlRiskView(base({ flagged: false }))!.verdict, /Not flagged/);
});

test("channels carry their role, the fused one is the headline, and an unavailable channel is said so", () => {
  const v = urlRiskView(base({ cnn_score: null }))!;
  const by = Object.fromEntries(v.channels.map((c) => [c.key, c]));
  assert.equal(by.fused.headline, true);
  assert.equal(by.cnn.value, "not available");
  assert.match(by.baseline.role, /weights fixed before any training/);
  const noFusion = urlRiskView(base({ fused_score: null }))!;
  assert.equal(noFusion.channels.find((c) => c.key === "xgb")!.headline, true, "without fusion the tree model is the headline");
});

test("evidence shows the unit and a what-if in probability points, strongest first", () => {
  const v = urlRiskView(base(), [
    ev({ feature_name: "small", shap_value: 0.1, probability_delta: 0.01 }),
    ev({ feature_name: "big", shap_value: -1.234, probability_delta: -0.2, human_readable: "Resembles a protected brand: rule score 0.95 — lowers the score by 1.23 log-odds" }),
  ])!;
  assert.equal(v.evidence[0].feature, "big");
  assert.equal(v.evidence[0].direction, "lowers");
  assert.equal(v.evidence[0].logOdds, "−1.23 log-odds");
  assert.match(v.evidence[0].whatIf!, /raise the probability by about 20 points/);
  assert.equal(v.evidence[0].text, "Resembles a protected brand: rule score 0.95");
  assert.match(v.evidence[1].whatIf!, /lower the probability by about 1 point$/);
});

test("the baseline's fired rules are listed with their weights", () => {
  assert.deepEqual(urlRiskView(base())!.rules, [{ text: "the host imitates a protected brand", weight: "+0.35" }]);
});
