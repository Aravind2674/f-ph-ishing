/** Network view model (revamp T2e): honest states, one-line fixes, "—" for unknown, resumable alert list. `npm test` */
import test from "node:test";
import assert from "node:assert/strict";
import { DASH, alertRows, alertTypeLabel, captureView, connectionView, deviceLabel, mergeAlert, sensorRows } from "./network.ts";
import type { CaptureInfo, MonitorStatus, NetworkAlert } from "../api.ts";

const capture = (over: Partial<CaptureInfo> = {}): CaptureInfo => ({
  state: "ready", ok: true, reason: "Capture prerequisites are met; no capture is running yet.", fix: null, selected_interface: "Wi-Fi", interfaces: [],
  details: {}, packets_seen: 0, packets_per_second: null, ...over,
});
const status = (over: Partial<MonitorStatus> = {}): MonitorStatus => ({
  running: false, sensors: {}, alert_count: 0, device_count: 0, capture: capture(), scope_note: "…", dropped_events: 0, ...over,
});
const alert = (over: Partial<NetworkAlert> = {}): NetworkAlert => ({
  alert_id: "a1", timestamp: "2026-10-07T10:00:00Z", alert_type: "evil_twin", severity: "High", fused_score: 64.4, title: "Possible evil-twin for 'X'",
  device_mac: null, device_ip: null, involved: ["aa:bb:cc:dd:ee:ff", "X"], trigger_type: "t", evidence: { signals: [], raw: {} }, recommended_actions: [], ...over,
});

test("no Npcap: the label, the reason and the one-line fix — and nothing claims to be running", () => {
  const v = captureView(status({ capture: capture({ state: "no_npcap", ok: false, reason: "Npcap is not installed.", fix: "Npcap not found — install it from npcap.com" }) }));
  assert.equal(v.label, "Npcap not found");
  assert.equal(v.tone, "bad");
  assert.equal(v.fix, "Npcap not found — install it from npcap.com");
  assert.equal(v.running, false);
  assert.equal(v.startLabel, "Check again");
  assert.deepEqual([v.rate, v.packets], [DASH, DASH]);
});

test("not elevated says so", () => {
  const v = captureView(status({ capture: capture({ state: "not_elevated", ok: false, reason: "lacks privileges", fix: "Run as Administrator: start the backend from an elevated terminal." }) }));
  assert.equal(v.label, "Run as Administrator");
  assert.match(v.fix!, /^Run as Administrator/);
});

test("starting is not capturing; capturing shows a real packet count and rate", () => {
  const starting = captureView(status({ running: true, capture: capture({ state: "starting", reason: "waiting for the first packet" }) }));
  assert.equal(starting.label, "Starting");
  assert.equal(starting.tone, "idle");
  assert.equal(starting.reason, "waiting for the first packet");
  const live = captureView(status({ running: true, capture: capture({ state: "capturing", reason: "Capturing on Wi-Fi", packets_seen: 12345, packets_per_second: 8.04 }) }));
  assert.deepEqual([live.label, live.tone, live.packets, live.rate, live.reason], ["Capturing", "ok", "12,345", "8.0 pkt/s", null]);
  assert.equal(live.canStop, true);
  assert.equal(live.canStart, false);
});

test("a rate that is not known yet is a dash, never 0", () => {
  const v = captureView(status({ running: true, capture: capture({ state: "capturing", packets_seen: 3, packets_per_second: null }) }));
  assert.equal(v.rate, DASH);
});

test("no traffic is a warning with the fix", () => {
  const v = captureView(status({ running: true, capture: capture({ state: "no_traffic", reason: "10 s without a packet", fix: "Check the interface" }) }));
  assert.deepEqual([v.label, v.tone, v.fix], ["No traffic", "warn", "Check the interface"]);
});

test("before the first answer the view says it is checking — not that the backend is unreachable", () => {
  const v = captureView(undefined);
  assert.deepEqual([v.label, v.reason, v.fix, v.canStart], ["Checking", null, null, false]);
  assert.notEqual(v.label, captureView(null).label);
});

test("an unreachable backend is said plainly and cannot be started from here", () => {
  const v = captureView(null);
  assert.deepEqual([v.label, v.state, v.canStart, v.canStop], ["Backend unreachable", "unreachable", false, false]);
  assert.match(v.fix!, /uvicorn/);
});

test("dropped events are shown as a number, including 0", () => {
  assert.equal(captureView(status({ dropped_events: 0 })).dropped, "0");
  assert.equal(captureView(status({ dropped_events: 1500 })).dropped, "1,500");
});

test("sensors: running, unavailable with reason and fix, not started", () => {
  const rows = sensorRows(status({ sensors: {
    arp: { available: true, running: true, packets: 40, events: 3 },
    dns: { available: true, running: true, packets: 0, events: 0 },
    wifi: { available: false, running: true, reason: "Windows refused the Wi-Fi scan", fix: "Turn on Location for desktop apps" },
    tls: { available: null, running: false, reason: "not started" },
  } }));
  const by = Object.fromEntries(rows.map((r) => [r.name, r]));
  assert.deepEqual([by.arp.state, by.arp.packets, by.arp.events], ["running", "40", "3"]);
  assert.equal(by.dns.packets, "0", "a running sensor that has seen nothing really has seen 0");
  assert.equal(by.wifi.state, "unavailable");
  assert.equal(by.wifi.packets, DASH, "polling sensors have no packet count");
  assert.equal(by.wifi.note, "Windows refused the Wi-Fi scan — Turn on Location for desktop apps");
  assert.deepEqual([by.tls.state, by.tls.tone], ["not started", "idle"]);
  assert.deepEqual(sensorRows(null), []);
});

test("alerts merge newest first without duplicates and stay capped", () => {
  const a = alert({ alert_id: "a" }), b = alert({ alert_id: "b" });
  let list = mergeAlert([], a);
  list = mergeAlert(list, b);
  assert.deepEqual(list.map((x) => x.alert_id), ["b", "a"]);
  assert.equal(mergeAlert(list, a), list, "the same alert arriving again (SSE replay after a reconnect) changes nothing");
  assert.equal(mergeAlert(list, alert({ alert_id: "c" }), 2).length, 2);
});

test("rows are filtered by severity and worded for people", () => {
  const rows = alertRows([alert({ alert_id: "1", severity: "High" }), alert({ alert_id: "2", severity: "Low", alert_type: "dga_suspect", device_mac: "aa:aa:aa:aa:aa:aa" })]);
  assert.equal(rows.length, 2);
  assert.deepEqual([rows[1].type, rows[1].fallbackDevice, rows[0].score], ["NXDOMAIN burst", "aa:aa:aa:aa:aa:aa", "64"]);
  assert.deepEqual(alertRows([alert({ severity: "High" }), alert({ alert_id: "z", severity: "Low" })], "Low").map((r) => r.id), ["z"]);
});

test("device label falls back from name to mac to ip to the first involved item, then a dash", () => {
  assert.equal(deviceLabel({ device_name: "Printer", device_mac: "m", device_ip: "i", involved: ["x"] }), "Printer");
  assert.equal(deviceLabel({ device_name: null, device_mac: null, device_ip: "10.0.0.2", involved: [] }), "10.0.0.2");
  assert.equal(deviceLabel({ device_name: null, device_mac: null, device_ip: null, involved: ["bssid"] }), "bssid");
  assert.equal(deviceLabel({ device_name: null, device_mac: null, device_ip: null, involved: [] }), DASH);
});

test("type labels cover every type the backend produces, and old stored ones", () => {
  for (const t of ["rogue_ap", "evil_twin", "new_device", "cross_layer_hit", "behavioral_deviation", "arp_spoof", "arp_flood", "arp_multi_ip", "tls_fingerprint", "dga_suspect", "beaconing", "dns_anomaly", "deauth_flood"]) {
    assert.notEqual(alertTypeLabel(t), t, t);
  }
  assert.equal(alertTypeLabel("something_new"), "something new");
});

test("connection state is visible: connecting, live, reconnecting", () => {
  assert.equal(connectionView(false, false).label, "Connecting");
  assert.equal(connectionView(true, true).label, "Live");
  assert.deepEqual(connectionView(false, true), { label: "Reconnecting", tone: "warn" });
});
