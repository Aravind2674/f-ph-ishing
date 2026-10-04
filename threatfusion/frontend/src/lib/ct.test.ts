/** Tests for the certificate-transparency card (B3): a young history is flagged, unknown is said, caveats are shown. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { ctView } from "./hostsignals.ts";
import { humanReason, sourceLabel } from "./evidence.ts";
import type { CtInfo } from "../api.ts";

const ct = (over: Partial<CtInfo> = {}): CtInfo => ({
  host: "x.example.com", certs_total: 3, first_seen: "2026-09-30T10:00:00Z", truncated: false, cert_first_seen_days: 4,
  cert_count_30d: 3, latest_issuer: "Let's Encrypt", issuer_is_free_dv: true, san_brand_hits: [], san_brand_keyword_hits: 0, ...over,
});

test("no record, no card", () => {
  assert.equal(ctView(null), null);
  assert.equal(ctView(undefined), null);
});

test("a days-old certificate history is flagged, with the reason", () => {
  const v = ctView(ct())!;
  assert.match(v.headline, /First certificate logged 4 days ago/);
  assert.equal(v.ok, false);
  assert.ok(v.facts.find((f) => f.label === "First seen in CT")?.flag);
  assert.ok(v.facts.some((f) => /just before going live/.test(f.value)));
});

test("an established history is neutral-to-good and never flagged", () => {
  const v = ctView(ct({ cert_first_seen_days: 2400, cert_count_30d: 1, latest_issuer: "DigiCert Inc", issuer_is_free_dv: false }))!;
  assert.match(v.headline, /6 years ago/);
  assert.equal(v.ok, true);
  assert.ok(!v.facts.find((f) => f.label === "First seen in CT")?.flag);
});

test("a free DV issuer is described as common on legitimate sites too, not as a verdict", () => {
  const v = ctView(ct())!;
  const issuer = v.facts.find((f) => f.label === "Newest issuer")!;
  assert.match(issuer.value, /common on legitimate sites too/);
  assert.ok(!issuer.flag);
});

test("unknown is said, never zero", () => {
  const v = ctView(ct({ cert_first_seen_days: null, cert_count_30d: null, first_seen: null, latest_issuer: null, issuer_is_free_dv: null }))!;
  assert.equal(v.ok, null);
  assert.equal(v.facts.find((f) => f.label === "First seen in CT")?.value, "unknown");
  assert.ok(!v.facts.some((f) => f.label === "Last 30 days"));
});

test("a truncated history says the counts are lower bounds", () => {
  const v = ctView(ct({ truncated: true, certs_total: 300, cert_count_30d: 12 }))!;
  assert.match(v.facts.find((f) => f.label === "Certificates")!.value, /at least 300.*more exist/);
  assert.match(v.facts.find((f) => f.label === "Last 30 days")!.value, /at least 12/);
});

test("brand-like names on the certificate are listed", () => {
  const v = ctView(ct({ san_brand_keyword_hits: 4, san_brand_hits: ["a -> PayPal", "b -> PayPal", "c -> HDFC Bank", "d -> Amazon"] }))!;
  const f = v.facts.find((x) => x.label === "Brand-like names on the certificate")!;
  assert.ok(f.flag);
  assert.match(f.value, /a -> PayPal; b -> PayPal; c -> HDFC Bank … \+1/);
});

test("it always says CT-first-seen is not the registration date", () => {
  assert.ok(ctView(ct())!.facts.some((f) => /not the registration date/.test(f.value)));
});

test("the source has a plain-language label and the new reason is humanised", () => {
  assert.equal(sourceLabel("ct"), "Certificate transparency");
  assert.match(humanReason("response_too_large") ?? "", /too large/);
});
