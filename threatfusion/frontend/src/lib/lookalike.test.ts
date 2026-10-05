/** Tests for the brand-impersonation view model (B4): evidence is shown, "no match" is not "safe", the score is a rule score. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { KIND_LABEL, coverageText, lookalikeView } from "./lookalike.ts";
import type { BrandCheck, LookalikeMatch } from "../api.ts";

const match = (over: Partial<LookalikeMatch> = {}): LookalikeMatch => ({
  brand: "PayPal", brand_domain: "paypal.com", sector: "payments", country: null, source: "curated", kind: "leetspeak",
  similarity: 0.95, distance: null, matched: "paypa1", mixed_script: false,
  evidence: ["'1' (U+0031 DIGIT ONE) looks like 'l'"], ...over,
});
const check = (over: Partial<BrandCheck> = {}): BrandCheck => ({
  status: "no_match", match: null, official_of: null, candidates: [], brands_checked: 110, popular_checked: 0, threshold: 0.8, notes: [], ...over,
});

test("no check, no card", () => {
  assert.equal(lookalikeView(null), null);
  assert.equal(lookalikeView(undefined), null);
});

test("a flag names the brand, the trick, the real domain and shows the evidence", () => {
  const v = lookalikeView(check({ status: "lookalike", match: match() }))!;
  assert.equal(v.status, "lookalike");
  assert.match(v.headline, /Looks like PayPal, but is not its domain/);
  assert.match(v.detail, /paypal\.com/);
  assert.equal(v.match?.kind, KIND_LABEL.leetspeak);
  assert.deepEqual(v.match?.evidence, ["'1' (U+0031 DIGIT ONE) looks like 'l'"]);
  assert.equal(v.match?.sector, "payments");
});

test("the similarity is presented as a rule score for the kind of trick, never as a probability", () => {
  const v = lookalikeView(check({ status: "lookalike", match: match({ similarity: 0.92, kind: "brand_keyword" }) }))!;
  assert.equal(v.match?.rule, "rule score 0.92");
  assert.doesNotMatch(JSON.stringify(v), /probab|%|confidence/i);
});

test("a genuine brand domain is said to be genuine, without an alarm", () => {
  const v = lookalikeView(check({ status: "official", official_of: "Microsoft" }))!;
  assert.equal(v.status, "official");
  assert.match(v.headline, /Microsoft's own domains/);
  assert.equal(v.match, null);
});

test("'no match' is not 'safe': it says what was compared and what it cannot see", () => {
  const v = lookalikeView(check())!;
  assert.equal(v.status, "no_match");
  assert.match(v.headline, /No resemblance/);
  assert.match(v.detail, /not a safety verdict/i);
  assert.doesNotMatch(v.headline + v.detail, /\bsafe\b(?! verdict)/i);
  assert.match(v.coverage, /110 protected brands/);
});

test("coverage mentions the popular-site extension only when it was used, and the threshold", () => {
  assert.doesNotMatch(coverageText(check()), /popular/);
  assert.match(coverageText(check({ popular_checked: 5000 })), /\+ 5000 popular sites/);
  assert.match(coverageText(check({ threshold: 0.95 })), /≥ 0\.95/);
});

test("weaker candidates below the threshold are listed with their kind", () => {
  const v = lookalikeView(check({ candidates: [match({ brand: "HDFC Bank", kind: "same_name_other_tld", similarity: 0.7 })] }))!;
  assert.deepEqual(v.candidates, [{ brand: "HDFC Bank", kind: KIND_LABEL.same_name_other_tld, rule: "rule score 0.70" }]);
});

test("every kind the backend can send has a plain-language label", () => {
  for (const k of ["homoglyph", "leetspeak", "typo", "separator", "brand_keyword", "brand_in_subdomain", "same_name_other_tld", "contains_brand"] as const) {
    assert.ok(KIND_LABEL[k] && KIND_LABEL[k].length > 3, k);
  }
});

test("a mixed-script host is marked on the match", () => {
  assert.equal(lookalikeView(check({ status: "lookalike", match: match({ mixed_script: true, kind: "homoglyph" }) }))!.match?.mixedScript, true);
});
