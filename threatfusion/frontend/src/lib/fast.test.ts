/** Tests for the fast-tier card (B1): local-only is stated, "nothing found" is not "safe", gaps are visible. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { fastView } from "./fast.ts";
import type { FastVerdict } from "../api.ts";

const verdict = (over: Partial<FastVerdict> = {}): FastVerdict => ({
  status: "nothing_found", level: "none", reasons: ["Nothing found in the local checks."], target_type: "domain", canonical_host: "example.org",
  registered_domain: "example.org", listed_by: [], popularity_rank: null, brand_check: null, url_risk_score: 0.1, url_risk_flagged: false,
  list_gaps: [], cached_scan: null, latency_ms: 42.4, tier: "fast", ...over,
});

test("no verdict, or an invalid target, means no card", () => {
  assert.equal(fastView(null), null);
  assert.equal(fastView(undefined), null);
  assert.equal(fastView(verdict({ status: "invalid", level: "none" })), null);
});

test("it always says the checks were local and how fast they were", () => {
  const v = fastView(verdict())!;
  assert.match(v.caption, /Local checks only/);
  assert.match(v.caption, /42 ms/);
  assert.match(v.caption, /nothing about this target was sent anywhere/);
});

test("'nothing found' is never a clean bill of health while the full scan runs", () => {
  const running = fastView(verdict())!;
  assert.equal(running.headline, "Nothing found in the local checks");
  assert.match(running.slowTierNote, /may find more/);
  assert.match(running.slowTierNote, /not a clean bill of health/);
  assert.doesNotMatch(running.headline, /\bsafe\b|\bclean\b/i);
  assert.match(fastView(verdict(), false)!.slowTierNote, /finished/);
});

test("levels have their own headline and chips name the evidence", () => {
  const block = fastView(verdict({ level: "block", status: "listed", listed_by: ["openphish", "phishtank"] }))!;
  assert.equal(block.headline, "On a phishing list");
  assert.deepEqual(block.chips, ["listed: openphish, phishtank"]);
  const warn = fastView(verdict({
    level: "warn", status: "suspicious", url_risk_flagged: true,
    brand_check: { status: "lookalike", match: { brand: "HDFC Bank" } as any, official_of: null, candidates: [], brands_checked: 110, popular_checked: 0, threshold: 0.8, notes: [] },
  }))!;
  assert.equal(warn.headline, "Looks suspicious");
  assert.deepEqual(warn.chips, ["imitates HDFC Bank", "URL text flagged"]);
  assert.equal(fastView(verdict({ level: "info", status: "official" }))!.headline, "A known brand's own domain");
});

test("an unreadable local list is shown as a gap, a recent scan and the popularity prior as context", () => {
  const v = fastView(verdict({ list_gaps: ["openphish"], popularity_rank: 1234, cached_scan: { scan_id: "x", baseline_label: "Low" } as any }))!;
  assert.ok(v.chips.includes("not available: openphish list"));
  assert.ok(v.chips.includes("popularity rank #1,234"));
  assert.ok(v.chips.includes("scanned before: Low risk"));
});

test("a target the fast tier cannot check says so instead of 'nothing found'", () => {
  const v = fastView(verdict({ status: "not_assessable", level: "none", reasons: ["Private or local names are never checked against outside lists."] }))!;
  assert.equal(v.headline, "Not checked by the fast tier");
});
