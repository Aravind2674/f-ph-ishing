/**
 * hostsignals.ts — view models for the evidence cards (A1-7): TLS certificate, registration (RDAP), DNS and the
 * technology stack with its end-of-life status.
 *
 * Pure formatting only. The one rule they all follow: **unknown is said, never invented**. A `null` stays "unknown"
 * (or "lookup failed"), `[]` stays "none", and a missing registration date is "not published" — never "0 days".
 */
import type { CtInfo, DetectedTechnology, DnsInfo, RdapInfo, TlsInfo } from "../api.ts";

export interface Fact {
  label: string;
  value: string;
  /** Draws attention (an invalid certificate, a brand-new domain, an end-of-life component). */
  flag?: boolean;
}

export interface CardView {
  headline: string;
  /** true = good, false = a problem, null = neutral/unknown. Shown with icon + wording, never with colour alone. */
  ok: boolean | null;
  facts: Fact[];
}

const DAY_MS = 86_400_000;

export function daysBetween(from: string, to: Date): number {
  return (to.getTime() - new Date(from).getTime()) / DAY_MS;
}

export function humanDuration(days: number): string {
  const d = Math.abs(days);
  if (d < 1) return "less than a day";
  if (d < 2) return "1 day";
  if (d < 60) return `${Math.floor(d)} days`;
  if (d < 730) return `${Math.floor(d / 30)} months`;
  return `${Math.floor(d / 365)} years`;
}

const shortDate = (iso: string): string => new Date(iso).toISOString().slice(0, 10);

// ── TLS ─────────────────────────────────────────────────────────────────────
export function verifyErrorText(code: string | null | undefined): string {
  switch (code) {
    case "expired": return "the certificate has expired";
    case "self_signed": return "self-signed";
    case "self_signed_in_chain": return "self-signed certificate in the chain";
    case "unknown_issuer": return "the issuer is not trusted";
    case "hostname_mismatch": return "the certificate is for a different host name";
    case null:
    case undefined: return "verification failed";
    default: return `verification failed (${code})`;
  }
}

export function issuerTypeText(type: string | null | undefined): string {
  switch (type) {
    case "free_dv": return "Free domain-validated (DV)";
    case "paid_dv": return "Paid domain-validated (DV)";
    case "ov": return "Organisation-validated (OV)";
    case "ev": return "Extended validation (EV)";
    default: return "Unknown";
  }
}

export function tlsView(tls: TlsInfo | null | undefined, now: Date = new Date()): CardView | null {
  if (!tls) return null;
  if (!tls.has_tls) {
    return { headline: "No TLS service answered on port 443", ok: false, facts: [] };
  }
  const expired = tls.not_after ? new Date(tls.not_after).getTime() <= now.getTime() : false;
  const valid = tls.chain_valid === true && tls.san_matches_host !== false && !expired;
  const facts: Fact[] = [];
  const issuer = tls.issuer_org || tls.issuer_cn;
  facts.push({ label: "Issuer", value: issuer ?? "unknown" });
  facts.push({ label: "Issuance", value: issuerTypeText(tls.issuer_type) });
  if (tls.not_after) {
    const days = daysBetween(tls.not_after, now);
    facts.push({
      label: "Expires",
      value: expired ? `${shortDate(tls.not_after)} (expired ${humanDuration(days)} ago)` : `${shortDate(tls.not_after)} (in ${humanDuration(-days)})`,
      flag: expired,
    });
  }
  if (tls.not_before) {
    facts.push({ label: "Issued", value: `${humanDuration(daysBetween(tls.not_before, now))} ago` });
  }
  facts.push({
    label: "Names",
    value: tls.san_matches_host == null ? "unknown" : tls.san_matches_host ? "cover this host" : "do not cover this host",
    flag: tls.san_matches_host === false,
  });
  if (tls.tls_version) facts.push({ label: "Protocol", value: tls.tls_version });
  if (tls.key_type) facts.push({ label: "Key", value: tls.key_bits ? `${tls.key_type} ${tls.key_bits}` : tls.key_type });
  return {
    headline: valid ? "Valid certificate" : `Invalid certificate — ${expired && !tls.verify_error ? "expired" : verifyErrorText(tls.verify_error)}`,
    ok: valid,
    facts,
  };
}

// ── Registration (RDAP / WHOIS) ─────────────────────────────────────────────
export function registrationView(rdap: RdapInfo | null | undefined, now: Date = new Date()): CardView | null {
  if (!rdap) return null;
  const facts: Fact[] = [];
  let headline = "Registration date not published";
  let ok: boolean | null = null;
  if (rdap.registered_at) {
    const days = daysBetween(rdap.registered_at, now);
    const fresh = days < 30;
    headline = `Registered ${humanDuration(days)} ago`;
    ok = !fresh;
    facts.push({ label: "Registered", value: shortDate(rdap.registered_at), flag: fresh });
    if (fresh) facts.push({ label: "Note", value: "Newly registered domains are a common phishing trait", flag: true });
  } else {
    facts.push({ label: "Registered", value: "not published — age unknown" });
  }
  if (rdap.expires_at) facts.push({ label: "Expires", value: shortDate(rdap.expires_at) });
  facts.push({ label: "Registrar", value: rdap.registrar ?? "unknown" });
  if (rdap.statuses?.length) facts.push({ label: "Status", value: rdap.statuses.join(", ") });
  if (rdap.nameservers?.length) facts.push({ label: "Name servers", value: rdap.nameservers.join(", ") });
  facts.push({ label: "Source", value: rdap.source === "whois" ? "WHOIS (this TLD has no RDAP)" : "RDAP" });
  return { headline, ok, facts };
}

// ── DNS ─────────────────────────────────────────────────────────────────────
/** null = the lookup failed, [] = the zone has none, otherwise the values. */
function triList(list: string[] | null | undefined, max = 4): string {
  if (list == null) return "unknown (lookup failed)";
  if (list.length === 0) return "none";
  return list.length > max ? `${list.slice(0, max).join(", ")} … +${list.length - max}` : list.join(", ");
}

function triBool(value: boolean | null | undefined, yes: string, no: string): string {
  return value == null ? "unknown (lookup failed)" : value ? yes : no;
}

export function dnsView(dns: DnsInfo | null | undefined): CardView | null {
  if (!dns) return null;
  const addresses =
    dns.a == null && dns.aaaa == null ? null : [...(dns.a ?? []), ...(dns.aaaa ?? [])];
  const facts: Fact[] = [
    { label: "Addresses", value: triList(addresses) },
    { label: "Mail (MX)", value: triList(dns.mx, 3) },
    { label: "Name servers", value: triList(dns.ns, 3) },
    { label: "SPF", value: triBool(dns.spf, "published", "none published") },
    {
      label: "DMARC",
      value: dns.dmarc == null ? "unknown (lookup failed)" : dns.dmarc ? `policy ${dns.dmarc_policy ?? "unspecified"}` : "none published",
    },
    { label: "CAA", value: dns.caa == null ? "unknown (lookup failed)" : dns.caa.length ? "published" : "none" },
    {
      label: "Hosting",
      value: dns.asn ? `AS${dns.asn}${dns.asn_org ? ` · ${dns.asn_org}` : ""}${dns.asn_country ? ` · ${dns.asn_country}` : ""}` : "unknown",
    },
  ];
  const failed = dns.failed_types?.length ?? 0;
  return {
    headline: failed ? `DNS answered, ${failed} lookup${failed > 1 ? "s" : ""} failed` : "DNS records collected",
    ok: null, // informational: DNS facts are context, not a verdict
    facts,
  };
}

// ── Certificate transparency (B3) ───────────────────────────────────────────
export function ctView(ct: CtInfo | null | undefined): CardView | null {
  if (!ct) return null;
  const facts: Fact[] = [];
  const days = ct.cert_first_seen_days;
  const fresh = days != null && days < 30;
  let headline = "No certificate history available";
  let ok: boolean | null = null;
  if (days != null) {
    headline = `First certificate logged ${humanDuration(days)} ago`;
    ok = !fresh;
    facts.push({ label: "First seen in CT", value: ct.first_seen ? shortDate(ct.first_seen) : "unknown", flag: fresh });
  } else {
    facts.push({ label: "First seen in CT", value: "unknown" });
  }
  const lower = ct.truncated ? "at least " : "";
  facts.push({ label: "Certificates", value: `${lower}${ct.certs_total} logged${ct.truncated ? " (more exist)" : ""}` });
  if (ct.cert_count_30d != null) {
    facts.push({ label: "Last 30 days", value: `${lower}${ct.cert_count_30d} issued`, flag: ct.cert_count_30d >= 3 });
  }
  if (ct.latest_issuer) {
    const free = ct.issuer_is_free_dv == null ? "" : ct.issuer_is_free_dv ? " (free / automated DV — common on legitimate sites too)" : "";
    facts.push({ label: "Newest issuer", value: `${ct.latest_issuer}${free}` });
  }
  if (ct.san_brand_keyword_hits > 0) {
    facts.push({
      label: "Brand-like names on the certificate",
      value: ct.san_brand_hits.slice(0, 3).join("; ") + (ct.san_brand_hits.length > 3 ? ` … +${ct.san_brand_hits.length - 3}` : ""),
      flag: true,
    });
  }
  if (fresh) facts.push({ label: "Note", value: "Phishing sites usually get their first certificate just before going live", flag: true });
  facts.push({ label: "Note", value: "First seen in CT is not the registration date: a domain can exist for years without a certificate" });
  return { headline, ok, facts };
}

// ── Technology stack & end-of-life ──────────────────────────────────────────
export interface TechView {
  name: string;
  version: string | null;
  badge: "end-of-life" | "supported" | "unknown";
  text: string;
  confidence: number;
  implied: boolean;
}

export function techView(t: DetectedTechnology): TechView {
  let badge: TechView["badge"] = "unknown";
  let text = t.version ? "Lifecycle unknown" : "No version detected";
  if (t.eol === true) {
    badge = "end-of-life";
    text = `End-of-life${t.eol_date ? ` since ${t.eol_date}` : ""}${t.latest_version ? ` · latest ${t.latest_version}` : ""}`;
  } else if (t.eol === false) {
    badge = "supported";
    text = `Supported${t.eol_date ? ` until ${t.eol_date}` : ""}`;
  }
  return { name: t.name, version: t.version ?? null, badge, text, confidence: t.confidence, implied: !!t.implied };
}

/** End-of-life components first, then by name. */
export function sortTechs(techs: DetectedTechnology[]): TechView[] {
  const order = { "end-of-life": 0, supported: 1, unknown: 2 } as const;
  return techs.map(techView).sort((a, b) => order[a.badge] - order[b.badge] || a.name.localeCompare(b.name));
}
