/** Tests for the independent-reputation card (B2): who said what, "not listed" is not "safe", feeds show their age. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { ageText, reputationView } from "./reputation.ts";
import { sourceLabel } from "./evidence.ts";
import type { ReputationSummary, ReputationVerdict } from "../api.ts";

const verdict = (over: Partial<ReputationVerdict> & { source: string }): ReputationVerdict => ({
  listed: false, category: null, match: null, score: null, detail: null, reference: null, last_seen: null, feed_age_days: null,
  stale: false, extra: {}, ...over,
});
const summary = (over: Partial<ReputationSummary> = {}): ReputationSummary => ({
  channels_applicable: 10, channels_answered: 9, listed_by: [], verdicts: [], popularity_rank: null, feed_ages: {}, notes: [], ...over,
});

test("no summary, no card", () => {
  assert.equal(reputationView(null), null);
  assert.equal(reputationView(undefined), null);
});

test("a listing names the channels and counts them against the ones that applied", () => {
  const v = reputationView(summary({
    listed_by: ["openphish", "urlhaus"],
    verdicts: [verdict({ source: "openphish", listed: true, category: "phishing", match: "exact_url", feed_age_days: 0.1 }),
               verdict({ source: "urlhaus", listed: true, category: "malware", match: "host", reference: "https://urlhaus.abuse.ch/url/1/" })],
  }))!;
  assert.equal(v.listed, true);
  assert.match(v.headline, /Listed by 2 of 10 channels: OpenPhish, URLhaus/);
  assert.equal(v.rows[0].kind, "listed");
  assert.equal(v.rows[0].match, "this exact URL");
  assert.equal(v.rows.find((r) => r.source === "urlhaus")!.reference, "https://urlhaus.abuse.ch/url/1/");
});

test("'not listed' is absence of evidence, never 'safe'", () => {
  const v = reputationView(summary())!;
  assert.equal(v.listed, false);
  assert.match(v.headline, /absence of evidence/);
  assert.doesNotMatch(v.headline, /\bsafe\b|\bclean\b|\bbenign\b/i);
  assert.equal(v.answered, "9 of 10 channels answered");
});

test("popularity and scanner context are never presented as a listing", () => {
  const v = reputationView(summary({
    popularity_rank: 1234,
    verdicts: [verdict({ source: "tranco", category: "popular", detail: "x is ranked #1,234" }),
               verdict({ source: "greynoise", category: "scanner", detail: "noise" }),
               verdict({ source: "otx", category: "threat_intel", detail: "3 pulses" })],
  }))!;
  assert.equal(v.listed, false);
  assert.match(v.popularity ?? "", /#1,234.*prior, not a verdict/);
  const kinds = Object.fromEntries(v.rows.map((r) => [r.source, r.kind]));
  assert.deepEqual(kinds, { otx: "record", greynoise: "context", tranco: "context" });
  assert.equal(v.rows.find((r) => r.source === "otx")!.statement, "Has a record, not flagged");
});

test("listed rows sort first, then records, then context", () => {
  const v = reputationView(summary({
    listed_by: ["safebrowsing"],
    verdicts: [verdict({ source: "tranco", category: "popular" }), verdict({ source: "otx", category: "threat_intel" }),
               verdict({ source: "safebrowsing", listed: true, category: "social_engineering" })],
  }))!;
  assert.deepEqual(v.rows.map((r) => r.source), ["safebrowsing", "otx", "tranco"]);
});

test("a local list shows its age; an out-of-date list says so; a never-downloaded one says that", () => {
  const v = reputationView(summary({
    feed_ages: { openphish: 0.125, phishtank: 1.4, tranco: null },
    verdicts: [verdict({ source: "phishtank", category: "phishing", listed: true, stale: true, feed_age_days: 1.4 })],
    listed_by: ["phishtank"],
  }))!;
  const text = Object.fromEntries(v.feeds.map((f) => [f.source, f.text]));
  assert.equal(text.openphish, "3 hours old");
  assert.match(text.phishtank, /34 hours old — out of date/);
  assert.equal(text.tranco, "never downloaded");
  assert.equal(v.rows[0].stale, true);
});

test("ageText reads naturally", () => {
  assert.equal(ageText(null), null);
  assert.equal(ageText(0.01), "under 1 hour old");
  assert.equal(ageText(1 / 24), "1 hour old");
  assert.equal(ageText(0.5), "12 hours old");
  assert.equal(ageText(3), "3 days old");
  assert.equal(ageText(1.2), "29 hours old");
});

test("gaps and notes from the backend are passed through", () => {
  const v = reputationView(summary({ channels_answered: 6, notes: ["4 of 10 channels gave no answer (urlhaus): unknown, not clean."] }))!;
  assert.equal(v.answered, "6 of 10 channels answered");
  assert.match(v.notes[0], /unknown, not clean/);
});

test("every channel has a plain-language name", () => {
  for (const s of ["openphish", "phishtank", "urlhaus", "threatfox", "safebrowsing", "urlscan", "otx", "abuseipdb", "greynoise", "tranco"]) {
    assert.notEqual(sourceLabel(s), s, s);
  }
});
