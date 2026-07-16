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
}

const API_BASE = "http://localhost:8000";

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
