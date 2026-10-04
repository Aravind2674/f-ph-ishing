/** Tests for the host-signal view models (A1-7): unknown is said, never invented. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { dnsView, humanDuration, registrationView, sortTechs, techView, tlsView, type CardView } from "./hostsignals.ts";
import type { DnsInfo, RdapInfo, TlsInfo } from "../api.ts";

const NOW = new Date("2026-10-04T12:00:00Z");
const fact = (v: CardView | null, label: string) => v!.facts.find((f) => f.label === label)!;

test("durations are human", () => {
  assert.equal(humanDuration(0.2), "less than a day");
  assert.equal(humanDuration(1.4), "1 day");
  assert.equal(humanDuration(2), "2 days");
  assert.equal(humanDuration(90), "3 months");
  assert.equal(humanDuration(3650), "10 years");
});

const goodTls: TlsInfo = {
  host: "example.com", has_tls: true, chain_valid: true, san_matches_host: true,
  not_before: "2026-09-20T00:00:00Z", not_after: "2026-12-19T00:00:00Z",
  issuer_org: "Let's Encrypt", issuer_type: "free_dv", tls_version: "TLSv1.3", key_type: "EC", key_bits: 256,
};

test("a valid certificate says so, with issuer type and time to expiry", () => {
  const v = tlsView(goodTls, NOW)!;
  assert.equal(v.headline, "Valid certificate");
  assert.equal(v.ok, true);
  assert.equal(fact(v, "Issuance").value, "Free domain-validated (DV)");
  assert.match(fact(v, "Expires").value, /2026-12-19 \(in 2 months\)/);
  assert.equal(fact(v, "Key").value, "EC 256");
});

test("an expired certificate is flagged and explained, never shown as valid", () => {
  const v = tlsView({ ...goodTls, chain_valid: false, verify_error: "expired", not_after: "2026-10-01T00:00:00Z" }, NOW)!;
  assert.equal(v.ok, false);
  assert.match(v.headline, /Invalid certificate — the certificate has expired/);
  assert.equal(fact(v, "Expires").flag, true);
  assert.match(fact(v, "Expires").value, /expired 3 days ago/);
});

test("wrong-host, self-signed and unknown-issuer are each named", () => {
  assert.match(tlsView({ ...goodTls, chain_valid: false, verify_error: "hostname_mismatch", san_matches_host: false }, NOW)!.headline, /different host name/);
  assert.match(tlsView({ ...goodTls, chain_valid: false, verify_error: "self_signed" }, NOW)!.headline, /self-signed/);
  assert.match(tlsView({ ...goodTls, chain_valid: false, verify_error: "unknown_issuer" }, NOW)!.headline, /not trusted/);
  assert.equal(fact(tlsView({ ...goodTls, chain_valid: false, san_matches_host: false }, NOW), "Names").flag, true);
});

test("no TLS at all is its own state; no probe is null", () => {
  assert.equal(tlsView({ host: "x", has_tls: false }, NOW)!.headline, "No TLS service answered on port 443");
  assert.equal(tlsView(null, NOW), null);
  assert.equal(tlsView(undefined, NOW), null);
});

test("a registration date turns into a human age; a missing one is 'not published', never zero", () => {
  const fresh: RdapInfo = { domain: "x.com", registered_at: "2026-10-02T12:00:00Z", registrar: "R", source: "rdap" };
  const v = registrationView(fresh, NOW)!;
  assert.equal(v.headline, "Registered 2 days ago");
  assert.equal(v.ok, false);
  assert.equal(fact(v, "Registered").flag, true);
  assert.ok(v.facts.some((f) => /phishing/.test(f.value)));

  const old = registrationView({ domain: "x.com", registered_at: "1995-08-14T04:00:00Z" }, NOW)!;
  assert.match(old.headline, /Registered 31 years ago/);
  assert.equal(old.ok, true);

  const none = registrationView({ domain: "x.com", registered_at: null }, NOW)!;
  assert.equal(none.headline, "Registration date not published");
  assert.equal(none.ok, null);
  assert.match(fact(none, "Registered").value, /age unknown/);
  assert.equal(registrationView(null, NOW), null);
});

test("whois fallback is labelled", () => {
  assert.match(fact(registrationView({ domain: "a.xx", registered_at: "2026-01-01T00:00:00Z", source: "whois" }, NOW), "Source").value, /WHOIS/);
});

test("DNS keeps three states: values, none, and lookup failed", () => {
  const dns: DnsInfo = {
    host: "www.example.com", lookup_domain: "example.com",
    a: ["93.184.216.34"], aaaa: [], mx: [], ns: ["a.ns", "b.ns"], txt: null, caa: null,
    spf: null, dmarc: true, dmarc_policy: "reject", asn: 15133, asn_org: "EDGECAST", asn_country: "US", failed_types: ["caa", "txt"],
  };
  const v = dnsView(dns)!;
  assert.equal(fact(v, "Addresses").value, "93.184.216.34");
  assert.equal(fact(v, "Mail (MX)").value, "none");
  assert.equal(fact(v, "SPF").value, "unknown (lookup failed)");
  assert.equal(fact(v, "DMARC").value, "policy reject");
  assert.equal(fact(v, "CAA").value, "unknown (lookup failed)");
  assert.equal(fact(v, "Hosting").value, "AS15133 · EDGECAST · US");
  assert.equal(v.headline, "DNS answered, 2 lookups failed");
  assert.equal(v.ok, null);
  assert.equal(dnsView(null), null);
});

test("no published SPF/DMARC reads as 'none published'", () => {
  const v = dnsView({ host: "x", lookup_domain: "x.com", a: ["1.2.3.4"], mx: [], spf: false, dmarc: false, caa: [], failed_types: [] })!;
  assert.equal(fact(v, "SPF").value, "none published");
  assert.equal(fact(v, "DMARC").value, "none published");
  assert.equal(fact(v, "CAA").value, "none");
  assert.equal(v.ok, null, "DNS facts are context, never labelled good");
});

test("technology end-of-life status", () => {
  assert.deepEqual(
    techView({ name: "PHP", version: "5.6.40", categories: [], confidence: 100, eol: true, eol_date: "2018-12-31", latest_version: "5.6.40" }),
    { name: "PHP", version: "5.6.40", badge: "end-of-life", text: "End-of-life since 2018-12-31 · latest 5.6.40", confidence: 100, implied: false },
  );
  assert.equal(techView({ name: "PHP", version: "8.4.1", categories: [], confidence: 100, eol: false, eol_date: "2028-12-31" }).text, "Supported until 2028-12-31");
  assert.equal(techView({ name: "jQuery", version: "3.6.0", categories: [], confidence: 100, eol: null }).text, "Lifecycle unknown");
  assert.equal(techView({ name: "Nginx", categories: [], confidence: 100 }).text, "No version detected");
  assert.equal(techView({ name: "PHP", categories: [], confidence: 50, implied: true }).implied, true);
});

test("end-of-life components are listed first", () => {
  const sorted = sortTechs([
    { name: "B", version: "1", categories: [], confidence: 100, eol: false },
    { name: "A", version: "1", categories: [], confidence: 100 },
    { name: "Z", version: "1", categories: [], confidence: 100, eol: true },
  ]);
  assert.deepEqual(sorted.map((t) => t.name), ["Z", "B", "A"]);
});
