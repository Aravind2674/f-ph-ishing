/** Tests for the India message check and report kit (B16): not a verdict, evidence shown, nothing submitted for the user. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { kitView, messageView } from "./india.ts";
import type { ReportKit, TextAnalysis } from "../api.ts";

const analysis = (over: Partial<TextAnalysis> = {}): TextAnalysis => ({
  risk: "high", score: 0.95, matches: [{ id: "kyc_expiry", category: "kyc", label: "Your KYC / account will be blocked", weight: 0.8, evidence: "account will be blocked today", why: "Banks do not block accounts over an SMS link.", advice: "Open your bank's app yourself." }],
  urls: [{ url: "http://sbi-kyc-update.in", host: "sbi-kyc-update.in", shortener: false, brand_check: { status: "lookalike", match: null, official_of: null, candidates: [], brands_checked: 110, popular_checked: 0, threshold: 0.8, notes: [] }, note: "Imitates State Bank of India; the real site is sbi.co.in." }],
  advice: ["Open your bank's app yourself.", "If you lost money or shared a code, call 1930 now and tell your bank."], arithmetic: "strongest: kyc 0.80 + 0.05 x 3 other categories = 0.95",
  limits: ["This checks the words against known scam patterns. It is not a verdict."], language: "en", truncated: false, ...over,
});

test("no analysis, no card", () => assert.equal(messageView(null), null));

test("the result is a rule score, never a probability, and carries its arithmetic and limits", () => {
  const v = messageView(analysis())!;
  assert.match(v.scoreText, /rule score, not a probability/);
  assert.match(v.arithmetic, /0\.80 \+ 0\.05 x 3/);
  assert.match(v.limits[0], /not a verdict/);
  assert.equal(v.headline, "This message strongly resembles a known scam");
});

test("every flag shows the triggering words, why it matters and what to do", () => {
  const f = messageView(analysis())!.flags[0];
  assert.equal(f.evidence, "account will be blocked today");
  assert.match(f.why, /do not block accounts/);
  assert.match(f.advice, /bank's app/);
});

test("no match is never worded as safe", () => {
  const v = messageView(analysis({ risk: "none", score: 0, matches: [], urls: [], advice: [] }))!;
  assert.match(v.headline, /does not make it safe/);
  assert.doesNotMatch(v.headline, /^No known scam pattern found\.?$/);
});

test("links are classified for display", () => {
  const v = messageView(analysis({ urls: [
    { url: "bit.ly/x", host: "bit.ly", shortener: true, brand_check: null, note: "A link shortener hides where the link really goes." },
    { url: "https://example.org", host: "example.org", shortener: false, brand_check: null, note: null },
  ] }))!;
  assert.deepEqual(v.links.map((l) => l.kind), ["shortener", "plain"]);
});

const kit = (over: Partial<ReportKit> = {}): ReportKit => ({
  kind: "message", summary_text: "I am reporting a suspected scam message (seen 04 Oct 2026, 04:30 PM IST).", steps: ["Call 1930 now"],
  channels: [
    { id: "helpline_1930", name: "National Cyber Crime Helpline", how: "Call 1930", url: null, use_when: "Money has left your account.", note: "Have the transaction id ready." },
    { id: "cybercrime_portal", name: "National Cyber Crime Reporting Portal", how: "cybercrime.gov.in", url: "https://cybercrime.gov.in", use_when: "A formal complaint.", note: null },
  ],
  reminders: ["ThreatFusion does not submit anything for you: copy the text, add what only you know, and file it yourself."], generated_at: "2026-10-04T16:30:00+05:30", ...over,
});

test("the kit marks the helpline as urgent, keeps the order and never claims to submit", () => {
  const v = kitView(kit(), true)!;
  assert.equal(v.title, "Money lost? Do these in order");
  assert.deepEqual(v.channels.map((c) => c.urgent), [true, false]);
  assert.equal(v.channels[0].how, "Call 1930");
  assert.match(v.reminders[0], /does not submit anything for you/);
  assert.equal(kitView(kit(), false)!.title, "How to report this");
  assert.equal(kitView(null), null);
});
