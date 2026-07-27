export interface ScanRequest {
  target: string;
  target_type: "domain" | "ip" | "url" | "file_hash";
}

export interface RiskExplanation {
  feature_name: string;
  feature_value: number;
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

export interface ScanResult {
  scan_id: string;
  target: string;
  target_type: string;
  timestamp: string;
  baseline_score: number;
  ml_score: number;
  ml_label: string;
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
  tech_fingerprint: any;
  cve: any;
  data_sources_succeeded: string[];
  data_sources_failed: string[];
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
  baseline_score: number;
  ml_score: number;
  ml_label: string;
  neural_score?: number | null;
  neural_label?: string | null;
}

// Mirrors backend HealthResponse (GET /health). `mock_mode` lets the UI show a
// clear mock/live indicator so a viewer always knows whether data is synthetic.
export interface HealthResponse {
  status: string;
  version: string;
  mock_mode: boolean;
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

export const submitScan = async (request: ScanRequest): Promise<ScanResponse> => {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
};

export const fetchHistory = async (): Promise<ScanHistoryItem[]> => {
  const res = await fetch(`${API_BASE}/scan/history`);
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
};

// Lightweight liveness probe used by the dashboard shell to render the
// mock/live badge. Additive only — existing call signatures are untouched.
export const fetchHealth = async (): Promise<HealthResponse> => {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
};

// Phase 2 — classify a single payload / query string / URL with the neural
// HTTP attack classifier.
export const analyzePayload = async (text: string): Promise<AnalyzeResponse> => {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
};

// Phase 3 — score a batch of captured requests or a HAR export.
export const analyzeTraffic = async (
  payload: { requests?: unknown[]; har?: unknown }
): Promise<TrafficAnalyzeResponse> => {
  const res = await fetch(`${API_BASE}/traffic/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
};

// Phase 4 — actively confirm injection points (scope-gated: localhost or
// explicitly authorised hosts only).
export const verifyTarget = async (
  target: string,
  authorized_hosts: string[] = []
): Promise<VerifyResponse> => {
  const res = await fetch(`${API_BASE}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, authorized_hosts }),
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
};

// ── Network Layer API ───────────────────────────────────────────────────

export const fetchNetworkStatus = async (): Promise<MonitorStatus> => {
  const res = await fetch(`${API_BASE}/network/status`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
};

export const startMonitor = async (): Promise<MonitorStatus> => {
  const res = await fetch(`${API_BASE}/network/monitor/start`, { method: "POST" });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
};

export const stopMonitor = async (): Promise<MonitorStatus> => {
  const res = await fetch(`${API_BASE}/network/monitor/stop`, { method: "POST" });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
};

export const fetchAlerts = async (severity?: string): Promise<NetworkAlert[]> => {
  const qs = severity ? `?severity=${encodeURIComponent(severity)}` : "";
  const res = await fetch(`${API_BASE}/network/alerts${qs}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
};

export const fetchAlert = async (id: string): Promise<NetworkAlert> => {
  const res = await fetch(`${API_BASE}/network/alerts/${id}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
};

export const fetchDevices = async (): Promise<DeviceProfile[]> => {
  const res = await fetch(`${API_BASE}/network/devices`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
};

/**
 * Subscribe to the live Server-Sent Events alert stream. Returns the
 * EventSource so the caller can `.close()` it on unmount. New alerts arrive
 * on the "alert" event; connection health flips via onOpen/onError.
 */
export const subscribeAlerts = (
  onAlert: (alert: NetworkAlert) => void,
  onOpen?: () => void,
  onError?: () => void,
): EventSource => {
  const es = new EventSource(`${API_BASE}/network/stream`);
  es.addEventListener("alert", (ev) => {
    try {
      onAlert(JSON.parse((ev as MessageEvent).data));
    } catch {
      /* malformed frame — ignore, next one will arrive */
    }
  });
  if (onOpen) es.onopen = onOpen;
  if (onError) es.onerror = onError;
  return es;
};
