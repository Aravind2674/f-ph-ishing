/**
 * lib.mjs — the extension's pure logic (B15). No browser APIs here, so `node --test` can cover it.
 *
 * What the extension does on every top-level navigation (via the service worker, background.js):
 *   1. decide whether the page may be checked at all (http/https only; never local / private names);
 *   2. send ONLY the host name (or the full URL if the user opted in) to the user's own ThreatFusion backend on localhost —
 *      `POST /scan/fast`, the local-only tier: the backend answers from local lists, the brand check and the URL-text
 *      models and sends nothing about the page to any third party;
 *   3. show the answer: a toolbar badge, and — for a look-alike, a blocklist hit or flagged URL text — a banner with the real
 *      brand's domain, plus a warning on password fields.
 * "Nothing found" is never shown as "safe": no badge for it.
 */

export const API_BASE = "http://127.0.0.1:8000";
export const CACHE_TTL_MS = 10 * 60 * 1000;

const PRIVATE_SUFFIXES = [".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet", ".test", ".invalid", ".example"];

/** True for names that must never leave the browser (single-label, private suffixes, private / loopback IPv4 and IPv6 literals). */
export function isPrivateHost(host) {
  const h = String(host || "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!h) return true;
  if (h === "localhost" || !h.includes(".") && !h.includes(":")) return true;
  if (PRIVATE_SUFFIXES.some((s) => h.endsWith(s))) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
    const [a, b] = h.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  if (h.includes(":")) return h === "::1" || h.startsWith("fe80") || h.startsWith("fc") || h.startsWith("fd") || h === "::";
  return false;
}

/** Parse a tab URL; return `{ host, url }` if it may be checked, else `null`. */
export function checkable(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  if (isPrivateHost(u.hostname)) return null;
  return { host: u.hostname.toLowerCase(), url: u.href };
}

/** The `POST /scan/fast` body: only the host unless the user opted in to sending the full URL. */
export function fastRequestBody(page, { fullUrl = false } = {}) {
  return fullUrl ? { target: page.url, target_type: "url", send_full_url: true } : { target: page.host, target_type: "domain" };
}

/** Should the page get a banner? Only `warn` and `block` — never "nothing found". */
export function needsBanner(verdict) {
  return !!verdict && (verdict.level === "warn" || verdict.level === "block");
}

/** Toolbar badge for a verdict; `null` text = no badge (nothing found is not shown as safe). */
export function badgeFor(verdict) {
  if (!verdict) return { text: "", title: "ThreatFusion" };
  if (verdict.level === "block") return { text: "!!", title: "ThreatFusion: listed as phishing" };
  if (verdict.level === "warn") return { text: "!", title: "ThreatFusion: this page looks suspicious" };
  if (verdict.level === "info") return { text: "", title: "ThreatFusion: a known brand's own domain" };
  return { text: "", title: "ThreatFusion: nothing found locally (not a guarantee)" };
}

/** One plain-English headline for the banner. */
export function bannerHeadline(verdict) {
  if (!verdict) return "";
  if (verdict.level === "block") return "This page is on a phishing list.";
  const brand = verdict.brand_check && verdict.brand_check.match;
  if (brand) return `This site may be pretending to be ${brand.brand}. The real site is ${brand.brand_domain}.`;
  if (verdict.level === "warn") return "This page looks suspicious.";
  return "";
}

/** Reasons to show under the headline (the backend's own words, capped). */
export function bannerReasons(verdict, max = 3) {
  return (verdict && verdict.reasons ? verdict.reasons : []).slice(0, max);
}

/** A tiny TTL cache keyed by host (or URL), so one site does not cause a request per navigation. */
export class VerdictCache {
  constructor(ttlMs = CACHE_TTL_MS, now = () => Date.now(), max = 500) {
    this.ttl = ttlMs;
    this.now = now;
    this.max = max;
    this.map = new Map();
  }
  get(key) {
    const hit = this.map.get(key);
    if (!hit) return undefined;
    if (this.now() - hit.at > this.ttl) {
      this.map.delete(key);
      return undefined;
    }
    return hit.value;
  }
  set(key, value) {
    if (this.map.size >= this.max) this.map.delete(this.map.keys().next().value);
    this.map.set(key, { at: this.now(), value });
  }
}

/** The `POST /feedback` body for the Report button. Host only unless the user opted in. */
export function feedbackBody(page, verdict, label, { fullUrl = false, note = "" } = {}) {
  return {
    target: fullUrl ? page.url : page.host,
    target_type: fullUrl ? "url" : "domain",
    send_full_url: !!fullUrl,
    label,
    note: String(note || "").slice(0, 500) || undefined,
    source: "extension",
    verdict_snapshot: verdict ? { level: verdict.level, status: verdict.status, url_risk_score: verdict.url_risk_score ?? null, listed_by: verdict.listed_by ?? [] } : undefined,
  };
}

export const DASHBOARD_URL = "http://localhost:5173";

/** The dashboard link for "Open in ThreatFusion": it pre-fills the scan form (the dashboard never scans from a link). */
export function dashboardLink(page, { fullUrl = false } = {}) {
  const link = new URL(DASHBOARD_URL);
  link.searchParams.set("target", fullUrl ? page.url : page.host);
  link.searchParams.set("type", fullUrl ? "url" : "domain");
  return link.href;
}

const pct = (p) => `${Math.round(p * 100)} %`;
const SOURCE_NAMES = { openphish: "OpenPhish", phishtank: "PhishTank", urlhaus: "URLhaus", threatfox: "ThreatFox", safebrowsing: "Google Safe Browsing", otx: "AlienVault OTX", abuseipdb: "AbuseIPDB", urlscan: "urlscan.io", greynoise: "GreyNoise" };

/**
 * What the popup shows for a finished scan: the headline band and the top three reasons, strongest evidence first
 * (a listing, a look-alike, antivirus detections, flagged URL text, then the provider-evidence terms by weight).
 * An unknown band stays "Unknown" and says so; "nothing found" is never worded as safe.
 */
export function popupView(result) {
  const r = result || {};
  const band = r.headline_band && r.headline_band !== "Unknown" ? r.headline_band : null;
  const reasons = [];
  const listed = (r.reputation && r.reputation.listed_by) || [];
  if (listed.length) reasons.push(`Listed by ${listed.map((s) => SOURCE_NAMES[s] || s).join(", ")}`);
  const brand = r.brand_check && r.brand_check.status === "lookalike" && r.brand_check.match;
  if (brand) reasons.push(`Imitates ${brand.brand} — the real site is ${brand.brand_domain}`);
  const vt = r.virustotal;
  if (vt && vt.malicious_count > 0) reasons.push(vt.total_engines ? `${vt.malicious_count} of ${vt.total_engines} antivirus engines flag it` : `${vt.malicious_count} antivirus engines flag it`);
  if (r.url_risk && r.url_risk.flagged && r.url_risk.headline_score != null) reasons.push(`URL text looks like phishing (${pct(r.url_risk.headline_score)})`);
  for (const t of [...(r.baseline_terms || [])].sort((a, b) => b.weight - a.weight)) reasons.push(t.text);
  const top = [...new Set(reasons)].slice(0, 3);
  if (band === null) return { band: "Unknown", reasons: top.length ? top : ["No evidence — risk unknown"] };
  return { band, reasons: top.length ? top : ["Nothing found"] };
}

/** Headers for the local backend: the API token lives in this browser profile's storage. */
export function apiHeaders(token) {
  const h = { "Content-Type": "application/json" };
  if (token) h.Authorization = "Bearer " + token;
  return h;
}
