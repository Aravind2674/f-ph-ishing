/**
 * network.ts — what the Network view says, as pure functions (no React, no DOM) so it is tested with `node --test`.
 *
 * Rules the view keeps: the state is never "capturing" before a real packet was seen (the backend decides, this only words it); a machine
 * that cannot capture shows its reason and its one-line fix and nothing decorative; an unknown number is "—", never 0; a sensor that cannot
 * work says why.
 */
import type { CaptureState, MonitorStatus, NetworkAlert, SensorStatus } from "../api.ts";

export const DASH = "—";
export type Tone = "ok" | "warn" | "bad" | "idle";

export const ALERT_TYPE_LABEL: Record<string, string> = {
  rogue_ap: "Access point",
  evil_twin: "Evil twin",
  new_device: "New device",
  cross_layer_hit: "Flagged domain",
  behavioral_deviation: "New behaviour",
  arp_spoof: "ARP spoofing",
  arp_flood: "ARP flood",
  arp_multi_ip: "One MAC, many IPs",
  tls_fingerprint: "TLS fingerprint",
  dga_suspect: "NXDOMAIN burst",
  beaconing: "Beaconing",
  dns_anomaly: "Odd DNS name",
  deauth_flood: "Deauth flood", // no longer produced; alerts stored by older versions still show
};

export function alertTypeLabel(type: string): string {
  return ALERT_TYPE_LABEL[type] ?? type.replace(/_/g, " ");
}

const STATE_LABEL: Record<CaptureState, string> = {
  no_scapy: "scapy missing",
  no_npcap: "Npcap not found",
  not_elevated: "Run as Administrator",
  no_interface: "No interface",
  ready: "Ready",
  starting: "Starting",
  capturing: "Capturing",
  no_traffic: "No traffic",
  error: "Error",
};

const STATE_TONE: Record<CaptureState, Tone> = {
  no_scapy: "bad", no_npcap: "bad", not_elevated: "bad", no_interface: "bad", ready: "idle", starting: "idle", capturing: "ok", no_traffic: "warn", error: "bad",
};

export interface CaptureView {
  label: string;
  tone: Tone;
  state: CaptureState | "unreachable";
  reason: string | null;
  fix: string | null;
  interfaceName: string | null;
  rate: string;
  packets: string;
  dropped: string;
  running: boolean;
  /** The button after a failure says "Check again": the backend re-runs the checks on every start. */
  startLabel: "Start" | "Check again";
  canStart: boolean;
  canStop: boolean;
}

const count = (n: number | null | undefined): string => (n == null ? DASH : n.toLocaleString("en-US"));

export function captureView(status: MonitorStatus | null | undefined): CaptureView {
  if (status === undefined) {                                         // the first answer has not arrived yet (the first check can take seconds)
    return {
      label: "Checking", tone: "idle", state: "unreachable", reason: null, fix: null, interfaceName: null, rate: DASH, packets: DASH, dropped: DASH,
      running: false, startLabel: "Start", canStart: false, canStop: false,
    };
  }
  if (!status) {
    return {
      label: "Backend unreachable", tone: "bad", state: "unreachable", reason: "The ThreatFusion API did not answer.",
      fix: "Start it from backend/: uvicorn app.main:app", interfaceName: null, rate: DASH, packets: DASH, dropped: DASH, running: false,
      startLabel: "Start", canStart: false, canStop: false,
    };
  }
  const cap = status.capture;
  const state = (cap?.state ?? "ready") as CaptureState;
  const failure = STATE_TONE[state] === "bad";
  return {
    label: cap ? STATE_LABEL[state] ?? state : "Unknown",
    tone: cap ? STATE_TONE[state] ?? "idle" : "idle",
    state,
    reason: cap && state !== "capturing" ? cap.reason : null,
    fix: cap?.fix ?? null,
    interfaceName: cap?.selected_interface ?? null,
    rate: status.running && cap?.packets_per_second != null ? `${cap.packets_per_second.toFixed(1)} pkt/s` : DASH,
    packets: status.running ? count(cap?.packets_seen ?? 0) : DASH,
    dropped: count(status.dropped_events ?? 0),
    running: status.running,
    startLabel: failure ? "Check again" : "Start",
    canStart: !status.running,
    canStop: status.running,
  };
}

export interface SensorRow {
  name: string;
  label: string;
  state: "running" | "unavailable" | "not started" | "stopped";
  tone: Tone;
  packets: string;
  events: string;
  note: string | null;
}

const SENSOR_LABEL: Record<string, string> = { arp: "ARP", dns: "DNS", tls: "TLS hellos", wifi: "Wi-Fi scan" };

function sensorState(s: SensorStatus): SensorRow["state"] {
  if (s.available === false) return "unavailable";
  if (s.available === null || s.available === undefined) return "not started";
  return s.running ? "running" : "stopped";
}

export function sensorRows(status: MonitorStatus | null | undefined): SensorRow[] {
  if (!status) return [];
  return Object.entries(status.sensors).map(([name, s]) => {
    const state = sensorState(s);
    return {
      name, label: SENSOR_LABEL[name] ?? name, state,
      tone: state === "running" ? "ok" : state === "unavailable" ? "bad" : "idle",
      packets: s.packets == null ? DASH : count(s.packets),
      events: count(s.events ?? 0),
      note: state === "unavailable" ? [s.reason, s.fix].filter(Boolean).join(" — ") || "No reason was reported" : s.reason && state !== "running" ? s.reason : null,
    };
  });
}

/** Newest first, de-duplicated by id (an alert can arrive over SSE and over the list endpoint), capped. */
export function mergeAlert(list: NetworkAlert[], alert: NetworkAlert, max = 1000): NetworkAlert[] {
  if (list.some((a) => a.alert_id === alert.alert_id)) return list;
  return [alert, ...list].slice(0, max);
}

export function deviceLabel(a: Pick<NetworkAlert, "device_name" | "device_mac" | "device_ip" | "involved">): string {
  return a.device_name || a.device_mac || a.device_ip || a.involved?.[0] || DASH;
}

export interface AlertRow {
  id: string;
  time: string;
  severity: NetworkAlert["severity"];
  type: string;
  deviceName: string | null;
  deviceMac: string | null;
  deviceIp: string | null;
  fallbackDevice: string;
  summary: string;
  score: string;
  target: string | null;
  packets: string;
}

export function alertRows(alerts: NetworkAlert[], severity: NetworkAlert["severity"] | "All" = "All"): AlertRow[] {
  return alerts
    .filter((a) => severity === "All" || a.severity === severity)
    .map((a) => {
      // Try to extract a domain or target from involved (e.g. DNS names, URLs)
      const target = a.involved?.find(x => x.includes(".") && !x.includes(":")) || null;
      
      const raw = a.evidence?.raw || {};
      const pktCount = raw.packets ?? raw.count ?? raw.packet_count ?? a.evidence?.baseline?.observations ?? a.evidence?.wigle?.total_observations;
      const packets = typeof pktCount === "number" ? pktCount.toLocaleString("en-US") : DASH;

      return {
        id: a.alert_id, 
        time: a.timestamp, 
        severity: a.severity, 
        type: alertTypeLabel(a.alert_type), 
        deviceName: a.device_name ?? null,
        deviceMac: a.device_mac ?? null,
        deviceIp: a.device_ip ?? null,
        fallbackDevice: deviceLabel(a),
        summary: a.title, 
        score: String(Math.round(a.fused_score)),
        target,
        packets,
      };
    });
}

export function connectionView(connected: boolean, everConnected: boolean): { label: string; tone: Tone } {
  if (connected) return { label: "Live", tone: "ok" };
  return everConnected ? { label: "Reconnecting", tone: "warn" } : { label: "Connecting", tone: "idle" };
}
