import type { ScanEvent } from "./lib/evidence.ts";

export interface ScanRequest {
  target: string;
  target_type: "domain" | "ip" | "url" | "file_hash";
  // Privacy opt-in (A0-10): by default a URL scan sends third parties only scheme://host/path
  // (query string, fragment and credentials are dropped). true = send the URL exactly as typed.
  send_full_url?: boolean;
  // Optional client-chosen id (8-64 chars of A-Z a-z 0-9 _ -). Lets the dashboard open the live progress stream
  // (GET /scan/{id}/events) BEFORE it POSTs the scan. The server generates one when omitted; reuse -> 409.
  scan_id?: string;
}

export interface RiskExplanation {
  feature_name: string;
  feature_value: number | null; // null = unknown (provider did not answer)
  shap_value: number;
  human_readable: string;
}

// A suspicious URL substring surfaced by the character-level neural model
// (via saliency). Mirrors backend NeuralExplanation.
export interface NeuralExplanation {
  substring: string;
  start: number;
  end: number;
  importance: number;
  human_readable: string;
}

export interface AttackChainNode {
  cve_id: string;
  cvss_score: number | null;
  epss_score: number;
  is_in_kev: boolean;
  exploit_db_id: string | null;
  pre_conditions: string[];
  post_conditions: string[];
  description: string;
}

export interface AttackPath {
  path_id: string;
  nodes: AttackChainNode[];
  total_risk_score: number;
  summary: string;
}

// Provenance of one provider call (A0-1). `status` is the truth about the lookup:
// "no record" (not_found) and "lookup failed" (error) are different things.
export type ProviderStatus = "ok" | "not_found" | "error" | "skipped" | "not_configured";

export interface ProviderOutcome {
  source: string;
  status: ProviderStatus;
  http_status?: number | null;
  reason?: string | null; // auth | rate_limited | timeout | network | server_error | parse_error | …
  fetched_at: string;
  cached: boolean;
  latency_ms?: number | null;
  mock: boolean;
  retry_after?: number | null; // seconds until the provider's quota allows another call (rate_limited)
}

// What the scanner actually looked up after canonicalisation (A1-6). `url` is the public form (no query/credentials).
export interface CanonicalTarget {
  kind: string;
  host?: string | null;
  registered_domain?: string | null;
  subdomain?: string;
  ip?: string | null;
  port?: number | null;
  scheme?: string | null;
  url?: string | null;
  has_userinfo?: boolean;
  hash?: string | null;
  hash_type?: string | null;
}

export interface FeatureCoverage {
  has_virustotal: boolean;
  has_shodan: boolean;
  has_cve: boolean;
  has_tech: boolean;
  // Host signals (A1-3); absent on scans stored before they existed.
  has_tls?: boolean;
  has_rdap?: boolean;
  has_dns?: boolean;
}

// ── Host signals & technologies (A1-3 / A1-4). `null` anywhere = unknown, never "none/false". ──
export interface TlsInfo {
  host: string;
  has_tls: boolean; // false = nothing on :443 speaks TLS (refused / plain HTTP)
  chain_valid?: boolean | null;
  verify_error?: string | null; // expired | self_signed | self_signed_in_chain | unknown_issuer | hostname_mismatch | verify_failed:<code>
  not_before?: string | null;
  not_after?: string | null;
  san_matches_host?: boolean | null;
  san_names?: string[];
  self_signed?: boolean | null;
  subject_cn?: string | null;
  issuer_cn?: string | null;
  issuer_org?: string | null;
  validation_level?: string | null; // dv | ov | ev | iv
  issuer_type?: string | null; // free_dv | paid_dv | ov | ev | unknown
  tls_version?: string | null;
  key_type?: string | null;
  key_bits?: number | null;
}

export interface RdapInfo {
  domain: string;
  registered_at?: string | null; // null = the registry publishes no registration date (age unknown, not 0)
  expires_at?: string | null;
  last_changed_at?: string | null;
  registrar?: string | null;
  statuses?: string[];
  nameservers?: string[];
  source?: string; // rdap | whois
  server?: string | null;
}

export interface DnsInfo {
  host: string;
  lookup_domain: string;
  // Three-state per family: a list (possibly empty = none exist) or null = the lookup failed.
  a?: string[] | null;
  aaaa?: string[] | null;
  mx?: string[] | null;
  ns?: string[] | null;
  txt?: string[] | null;
  caa?: string[] | null;
  spf?: boolean | null;
  spf_record?: string | null;
  dmarc?: boolean | null;
  dmarc_policy?: string | null;
  asn?: number | null;
  asn_org?: string | null;
  asn_prefix?: string | null;
  asn_country?: string | null;
  failed_types?: string[];
}

export interface DetectedTechnology {
  name: string;
  version?: string | null;
  categories: string[];
  confidence: number; // Wappalyzer's real confidence (50 for an implied technology)
  implied?: boolean;
  // Lifecycle from endoflife.date: true = end-of-life, false = supported, null/absent = unknown.
  eol?: boolean | null;
  eol_date?: string | null;
  eol_cycle?: string | null;
  latest_version?: string | null;
}

export interface TechFingerprintResult {
  technologies: DetectedTechnology[];
  headers_analyzed?: number;
  scripts_analyzed?: number;
  eol_assessed?: number;
}

export interface ScanResult {
  scan_id: string;
  target: string;
  target_type: string;
  timestamp: string;
  canonical?: CanonicalTarget | null; // absent on scans stored before A1-6
  // null = not computed (no evidence / model not loaded) — never shown as 0.
  baseline_score: number | null;
  // Band of baseline_score ("Unknown" if no evidence). The baseline is the headline score:
  // the XGBoost model is experimental (VirusTotal features only) until retrained (A2-1).
  baseline_label?: string | null;
  ml_score: number | null;
  ml_label: string; // "Unknown" when ml_score is null
  ml_status?: "ok" | "model_not_loaded" | "insufficient_evidence" | null;
  // ok = every applicable source answered | partial | unknown = no reputation evidence
  verdict_status?: "ok" | "partial" | "unknown";
  verdict_reason?: string | null;
  provider_results?: ProviderOutcome[];
  feature_coverage?: FeatureCoverage | null;
  // Provenance stored with every scan (A0-6): which models/feature semantics produced it.
  model_versions?: Record<string, string>; // sha256[:12] from the model manifest, or "not_loaded"
  feature_schema_version?: number;
  app_version?: string | null;
  mock_mode?: boolean;
  // Neural fusion model (char-CNN + tabular). Optional — present only when the
  // trained checkpoint is available on the backend.
  neural_score?: number | null;
  neural_label?: string | null;
  neural_url_score?: number | null;
  neural_explanations?: NeuralExplanation[];
  explanations: RiskExplanation[];
  attack_paths?: AttackPath[];
  summary: string;
  virustotal: any;
  shodan: any;
  tech_fingerprint: TechFingerprintResult | null;
  tls?: TlsInfo | null;
  rdap?: RdapInfo | null;
  dns?: DnsInfo | null;
  // The 19 engineered features; null = unknown (its source did not answer). See lib/evidence.ts for provenance.
  features?: Record<string, number | null> | null;
  cve: any;
  data_sources_succeeded: string[];
  data_sources_failed: string[];
  // Sources that answered "no record of this target" (an answer, but no evidence).
  data_sources_not_found?: string[];
  // Providers that were NOT called because they are not configured (missing or
  // placeholder credential). Different from "failed": nothing was attempted.
  data_sources_skipped?: string[];
}

export interface ScanResponse {
  success: boolean;
  result: ScanResult | null;
  error: string | null;
}

export interface ScanHistoryItem {
  scan_id: string;
  target: string;
  target_type: string;
  timestamp: string;
  baseline_score: number | null;
  baseline_label?: string | null;
  ml_score: number | null;
  ml_label: string | null;
  neural_score?: number | null;
  neural_label?: string | null;
}

// Mirrors backend HealthResponse (GET /health). `mock_mode` lets the UI show a
// clear mock/live indicator so a viewer always knows whether data is synthetic.
export interface ProviderHealth {
  configured: boolean;
  mock: boolean;
  // configured | placeholder | missing | keyless | local | mock  (never a credential value)
  state: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  mock_mode: boolean;
  providers?: Record<string, ProviderHealth>;
}

// ── Phase 2/3 — neural HTTP attack classifier ────────────────────────────────
export interface PayloadFinding {
  input: string;
  location: string;
  label: string;
  is_attack: boolean;
  confidence: number;
  suspicious_span: string | null;
  probs: Record<string, number>;
}

export interface AnalyzeResponse {
  success: boolean;
  model_loaded: boolean;
  findings: PayloadFinding[];
  summary: string;
  error: string | null;
}

export interface ValueFinding {
  location: string;
  value: string;
  label: string;
  is_attack: boolean;
  confidence: number;
  suspicious_span: string | null;
}

export interface RequestFinding {
  method: string;
  url: string;
  is_attack: boolean;
  worst_label: string;
  worst_location: string;
  worst_confidence: number;
  suspicious_span: string | null;
  values_analyzed: number;
  attack_values: number;
  details: ValueFinding[];
}

export interface TrafficAnalyzeResponse {
  success: boolean;
  model_loaded: boolean;
  analyzed: number;
  flagged: number;
  findings: RequestFinding[];
  summary: string;
  error: string | null;
}

// ── Phase 4 — active verification ─────────────────────────────────────────────
export interface ProbeResult {
  param: string;
  technique: string;
  confirmed: boolean;
  confidence: number;
  evidence: string;
  payload: string;
}

export interface VerifyResponse {
  success: boolean;
  authorized: boolean;
  target: string;
  tested_params: string[];
  confirmed_count: number;
  probes: ProbeResult[];
  summary: string;
  error: string | null;
  // e.g. "authorized_hosts in the request is ignored" — scope is server configuration.
  notice?: string | null;
}

// ── Network Layer types (mirror app/network/models.py) ──────────────────

export interface SignalContribution {
  name: string;
  label: string;
  available: boolean;
  points: number;
  detail: string;
  reason?: string | null;
}

export interface AppLayerSubScore {
  available: boolean;
  reason?: string | null;
  target?: string | null;
  target_type?: string | null;
  baseline_score?: number | null;
  ml_score?: number | null;
  ml_label?: string | null;
  vt_malicious_count?: number | null;
  vt_total_engines?: number | null;
  flagged: boolean;
  top_explanations: string[];
  live: boolean;
}

export interface WigleResult {
  available: boolean;
  reason?: string | null;
  bssid?: string | null;
  found: boolean;
  total_observations: number;
  first_seen?: string | null;
  last_seen?: string | null;
  known_ssids: string[];
}

export interface BaselineComparison {
  device_known: boolean;
  observations: number;
  established: boolean;
  known_domains_sample: string[];
  known_domain_count: number;
  observed_domain?: string | null;
  is_new_domain: boolean;
  deviation_detail: string;
}

export interface AlertEvidence {
  signals: SignalContribution[];
  app_layer?: AppLayerSubScore | null;
  wigle?: WigleResult | null;
  baseline?: BaselineComparison | null;
  raw: Record<string, any>;
}

export type NetworkSeverity = "Low" | "Medium" | "High" | "Critical";

export type NetworkAlertType =
  | "deauth_flood"
  | "rogue_ap"
  | "evil_twin"
  | "new_device"
  | "cross_layer_hit"
  | "behavioral_deviation"
  | "arp_spoof";

export interface NetworkAlert {
  alert_id: string;
  timestamp: string;
  alert_type: NetworkAlertType;
  severity: NetworkSeverity;
  fused_score: number;
  title: string;
  device_mac?: string | null;
  device_name?: string | null;
  device_ip?: string | null;
  involved: string[];
  trigger_type: string;
  evidence: AlertEvidence;
  recommended_actions: string[];
}

export interface DeviceProfile {
  mac: string;
  ip?: string | null;
  hostname?: string | null;
  vendor?: string | null;
  first_seen: string;
  last_seen: string;
  dns_observations: number;
  distinct_domains: number;
  top_domains: string[];
  ports: number[];
}

export interface SensorStatus {
  available: boolean | null;
  running: boolean;
  reason?: string | null;
}

export interface MonitorStatus {
  running: boolean;
  sensors: Record<string, SensorStatus>;
  alert_count: number;
  device_count: number;
  started_at?: string | null;
}

const API_BASE = "http://127.0.0.1:8000";

// ── API token (A0-8) ────────────────────────────────────────────────────────
// Every route except /health needs `Authorization: Bearer <token>`. The token is generated by the
// backend on first start and stored outside the repo; print it with `python -m app.core.auth` and
// paste it on the Settings page. It lives in this browser's localStorage only.
const TOKEN_KEY = "tf_api_token";

export const getApiToken = (): string => {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
};

export const setApiToken = (token: string): void => {
  try {
    if (token.trim()) localStorage.setItem(TOKEN_KEY, token.trim());
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (private mode) — token stays unset */
  }
};

const authHeaders = (extra: Record<string, string> = {}): Record<string, string> => {
  const token = getApiToken();
  return token ? { ...extra, Authorization: `Bearer ${token}` } : { ...extra };
};

// Turn a failed response into a useful Error (401 → tell the user how to fix it).
const apiError = async (res: Response): Promise<Error> => {
  let detail = "";
  try {
    const body = await res.json();
    detail = typeof body?.detail === "string" ? body.detail : "";
  } catch {
    /* non-JSON body */
  }
  if (res.status === 401) {
    return new Error(
      "API token missing or invalid — paste it on the Settings page (print it with: python -m app.core.auth)"
    );
  }
  return new Error(detail || `API error: ${res.status}`);
};

/** A fresh client-side scan id (a UUID satisfies the server's `[A-Za-z0-9_-]{8,64}` rule). */
export const newScanId = (): string => crypto.randomUUID();

/**
 * Follow one scan live: per-provider status events from GET /scan/{id}/events (Server-Sent Events).
 *
 * Open it BEFORE POSTing the scan (pass the same `scan_id`). Like the alert stream it trades the Bearer token for a
 * single-use ticket (POST /scan/events-ticket) because EventSource cannot send headers. Progress is a nicety: if the
 * stream cannot be opened the scan still completes through the POST response, so failures only call `onClose`.
 */
export const subscribeScanEvents = (
  scanId: string,
  onEvent: (event: ScanEvent) => void,
  onClose?: () => void,
): { close: () => void } => {
  let es: EventSource | null = null;
  let closed = false;
  const finish = () => {
    es?.close();
    es = null;
    if (!closed) onClose?.();
  };

  (async () => {
    try {
      const res = await fetch(`${API_BASE}/scan/events-ticket`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: "{}",
      });
      if (!res.ok) throw await apiError(res);
      const { ticket } = (await res.json()) as { ticket: string };
      if (closed) return;
      es = new EventSource(`${API_BASE}/scan/${encodeURIComponent(scanId)}/events?ticket=${encodeURIComponent(ticket)}`);
      for (const type of ["start", "provider", "stage", "done", "error", "timeout"] as const) {
        es.addEventListener(type, (ev) => {
          try {
            onEvent(JSON.parse((ev as MessageEvent).data) as ScanEvent);
          } catch {
            /* malformed frame — the next one will arrive */
          }
          if (type === "done" || type === "error" || type === "timeout") finish();
        });
      }
      es.onerror = finish; // tickets are single-use: no auto-reconnect, the POST response is authoritative
    } catch {
      finish();
    }
  })();

  return {
    close: () => {
      closed = true;
      es?.close();
      es = null;
    },
  };
};

export const submitScan = async (request: ScanRequest): Promise<ScanResponse> => {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(request),
  });
  if (!res.ok) {
    // The backend explains validation failures (e.g. unresolvable domain) in
    // the body as {message} or {detail}; surface that instead of a bare status.
    let reason = "";
    try {
      const body = await res.json();
      reason = body?.message ?? (typeof body?.detail === "string" ? body.detail : "");
    } catch {
      /* non-JSON error body */
    }
    throw new Error(reason || `API error: ${res.status}`);
  }
  return res.json();
};

export const fetchHistory = async (): Promise<ScanHistoryItem[]> => {
  const res = await fetch(`${API_BASE}/scan/history`, { headers: authHeaders() });
  if (!res.ok) {
    throw await apiError(res);
  }
  return res.json();
};

// Lightweight liveness probe used by the dashboard shell to render the
// mock/live badge. Additive only — existing call signatures are untouched.
export const fetchHealth = async (): Promise<HealthResponse> => {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw await apiError(res);
  }
  return res.json();
};

// Phase 2 — classify a single payload / query string / URL with the neural
// HTTP attack classifier.
export const analyzePayload = async (text: string): Promise<AnalyzeResponse> => {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    throw await apiError(res);
  }
  return res.json();
};

// Phase 3 — score a batch of captured requests or a HAR export.
export const analyzeTraffic = async (
  payload: { requests?: unknown[]; har?: unknown }
): Promise<TrafficAnalyzeResponse> => {
  const res = await fetch(`${API_BASE}/traffic/analyze`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw await apiError(res);
  }
  return res.json();
};

// Phase 4 — actively confirm injection points (scope-gated by the SERVER: it is disabled
// unless an operator enables it and lists the allowed hosts).
// NOTE: the server decides the scope (VERIFY_ALLOWED_HOSTS); the UI no longer sends any
// "authorised hosts" — a caller must not be able to authorise itself.
export const verifyTarget = async (target: string): Promise<VerifyResponse> => {
  const res = await fetch(`${API_BASE}/verify`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ target }),
  });
  if (!res.ok) {
    // e.g. 429 {"detail": "Too many verification runs against …; retry in 42s."}
    let detail = "";
    try {
      const body = await res.json();
      detail = typeof body?.detail === "string" ? body.detail : "";
    } catch {
      /* non-JSON error body */
    }
    if (res.status === 401) throw await apiError(res);
    throw new Error(detail || `API error: ${res.status}`);
  }
  return res.json();
};

// ── Network Layer API ───────────────────────────────────────────────────

export const fetchNetworkStatus = async (): Promise<MonitorStatus> => {
  const res = await fetch(`${API_BASE}/network/status`, { headers: authHeaders() });
  if (!res.ok) throw await apiError(res);
  return res.json();
};

export const startMonitor = async (): Promise<MonitorStatus> => {
  const res = await fetch(`${API_BASE}/network/monitor/start`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: "{}",
  });
  if (!res.ok) throw await apiError(res);
  return res.json();
};

export const stopMonitor = async (): Promise<MonitorStatus> => {
  const res = await fetch(`${API_BASE}/network/monitor/stop`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: "{}",
  });
  if (!res.ok) throw await apiError(res);
  return res.json();
};

export const fetchAlerts = async (severity?: string): Promise<NetworkAlert[]> => {
  const qs = severity ? `?severity=${encodeURIComponent(severity)}` : "";
  const res = await fetch(`${API_BASE}/network/alerts${qs}`, { headers: authHeaders() });
  if (!res.ok) throw await apiError(res);
  return res.json();
};

export const fetchAlert = async (id: string): Promise<NetworkAlert> => {
  const res = await fetch(`${API_BASE}/network/alerts/${id}`, { headers: authHeaders() });
  if (!res.ok) throw await apiError(res);
  return res.json();
};

// Erase every stored device profile, per-device domain history and alert (irreversible).
export const deleteNetworkData = async (): Promise<Record<string, number>> => {
  const res = await fetch(`${API_BASE}/network/data`, {
    method: "DELETE",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: "{}",
  });
  if (!res.ok) throw await apiError(res);
  return res.json();
};

export const fetchDevices = async (): Promise<DeviceProfile[]> => {
  const res = await fetch(`${API_BASE}/network/devices`, { headers: authHeaders() });
  if (!res.ok) throw await apiError(res);
  return res.json();
};

/**
 * Subscribe to the live Server-Sent Events alert stream.
 *
 * EventSource cannot send an Authorization header, and a token in the URL would end up in server
 * access logs. So we trade the token for a short-lived, single-use ticket (POST /network/stream-ticket)
 * and open /network/stream?ticket=…. A ticket can be used once, so a dropped connection is re-opened
 * here with a *fresh* ticket and exponential backoff (native auto-reconnect would reuse the spent one).
 * Returns a handle; call `.close()` on unmount.
 */
export const subscribeAlerts = (
  onAlert: (alert: NetworkAlert) => void,
  onOpen?: () => void,
  onError?: () => void,
): { close: () => void } => {
  let es: EventSource | null = null;
  let closed = false;
  let delay = 1000;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const retry = () => {
    onError?.();
    if (closed) return;
    timer = setTimeout(connect, delay);
    delay = Math.min(delay * 2, 15000);
  };

  const connect = async () => {
    if (closed) return;
    try {
      const res = await fetch(`${API_BASE}/network/stream-ticket`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: "{}",
      });
      if (!res.ok) throw await apiError(res);
      const { ticket } = (await res.json()) as { ticket: string };
      if (closed) return;
      es = new EventSource(`${API_BASE}/network/stream?ticket=${encodeURIComponent(ticket)}`);
      es.addEventListener("alert", (ev) => {
        try {
          onAlert(JSON.parse((ev as MessageEvent).data));
        } catch {
          /* malformed frame — ignore, next one will arrive */
        }
      });
      es.onopen = () => {
        delay = 1000;
        onOpen?.();
      };
      es.onerror = () => {
        es?.close();
        es = null;
        retry();
      };
    } catch {
      retry();
    }
  };

  connect();
  return {
    close: () => {
      closed = true;
      if (timer) clearTimeout(timer);
      es?.close();
      es = null;
    },
  };
};
