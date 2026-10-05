// Tests for the extension's pure logic (B15). Run: `node --test "extension/tests/*.test.mjs"` from threatfusion/.
import test from "node:test";
import assert from "node:assert/strict";
import {
  VerdictCache, apiHeaders, badgeFor, bannerHeadline, bannerReasons, checkable, fastRequestBody, feedbackBody, isPrivateHost, needsBanner,
} from "../lib.mjs";

test("only ordinary web pages are checked", () => {
  assert.deepEqual(checkable("https://Www.Example.com/a?b=1#c"), { host: "www.example.com", url: "https://www.example.com/a?b=1#c" });
  for (const u of ["chrome://settings", "about:blank", "file:///etc/passwd", "chrome-extension://abc/popup.html", "ftp://example.com", "not a url", ""]) {
    assert.equal(checkable(u), null, u);
  }
});

test("private and local names never leave the browser", () => {
  for (const h of ["localhost", "printer", "nas.local", "router.lan", "10.0.0.5", "192.168.1.10", "172.16.0.1", "172.31.255.1", "127.0.0.1", "169.254.1.1", "[::1]", "fe80::1", "intranet.corp", "site.test", "x.example", ""]) {
    assert.equal(isPrivateHost(h), true, h);
  }
  for (const u of ["http://localhost/", "http://printer/", "http://nas.local/", "http://10.0.0.5/", "http://192.168.1.10:8080/", "http://[::1]/", "http://intranet.corp/"]) {
    assert.equal(checkable(u), null, u);
  }
  for (const h of ["example.com", "8.8.8.8", "172.32.0.1", "sub.example.co.uk", "xn--pypal-4ve.com"]) assert.equal(isPrivateHost(h), false, h);
});

test("by default only the host name is sent; the full URL only on opt-in", () => {
  const page = checkable("https://login.example.com/reset?token=SECRET#frag");
  assert.deepEqual(fastRequestBody(page), { target: "login.example.com", target_type: "domain" });
  assert.equal(JSON.stringify(fastRequestBody(page)).includes("SECRET"), false);
  const full = fastRequestBody(page, { fullUrl: true });
  assert.equal(full.send_full_url, true);
  assert.match(full.target, /token=SECRET/);
});

test("a banner is shown for a warning or a listing, never for nothing found or a brand's own domain", () => {
  assert.equal(needsBanner({ level: "block" }), true);
  assert.equal(needsBanner({ level: "warn" }), true);
  assert.equal(needsBanner({ level: "info" }), false);
  assert.equal(needsBanner({ level: "none" }), false);
  assert.equal(needsBanner(null), false);
});

test("the badge never says safe", () => {
  assert.equal(badgeFor({ level: "block" }).text, "!!");
  assert.equal(badgeFor({ level: "warn" }).text, "!");
  for (const v of [{ level: "none" }, { level: "info" }, null]) {
    const b = badgeFor(v);
    assert.equal(b.text, "");
    assert.doesNotMatch(b.title, /\bsafe\b/i);
  }
  assert.match(badgeFor({ level: "none" }).title, /not a guarantee/);
});

test("the headline names the impersonated brand and its real domain", () => {
  const v = { level: "warn", brand_check: { match: { brand: "HDFC Bank", brand_domain: "hdfcbank.com" } }, reasons: ["a", "b", "c", "d"] };
  assert.equal(bannerHeadline(v), "This site may be pretending to be HDFC Bank. The real site is hdfcbank.com.");
  assert.equal(bannerHeadline({ level: "block", brand_check: null }), "This page is on a phishing list.");
  assert.equal(bannerHeadline({ level: "warn", brand_check: null }), "This page looks suspicious.");
  assert.deepEqual(bannerReasons(v), ["a", "b", "c"]);
  assert.deepEqual(bannerReasons(null), []);
});

test("the cache expires entries and stays bounded", () => {
  let now = 0;
  const c = new VerdictCache(1000, () => now, 3);
  c.set("a", 1);
  assert.equal(c.get("a"), 1);
  now = 1001;
  assert.equal(c.get("a"), undefined);
  for (const k of ["b", "c", "d", "e"]) c.set(k, k);
  assert.equal(c.get("b"), undefined, "the oldest entry was evicted");
  assert.equal(c.get("e"), "e");
});

test("a report carries the host only by default, a capped note and what the verdict said", () => {
  const page = checkable("https://shop.example.com/cart?id=9");
  const body = feedbackBody(page, { level: "warn", status: "suspicious", url_risk_score: 0.9, listed_by: [] }, "false_positive", { note: "x".repeat(900) });
  assert.equal(body.target, "shop.example.com");
  assert.equal(body.send_full_url, false);
  assert.equal(body.note.length, 500);
  assert.equal(body.source, "extension");
  assert.deepEqual(body.verdict_snapshot, { level: "warn", status: "suspicious", url_risk_score: 0.9, listed_by: [] });
  assert.equal(feedbackBody(page, null, "false_negative", { fullUrl: true }).target, "https://shop.example.com/cart?id=9");
});

test("the token goes in a header only when there is one", () => {
  assert.equal(apiHeaders("").Authorization, undefined);
  assert.equal(apiHeaders("abc").Authorization, "Bearer abc");
});
