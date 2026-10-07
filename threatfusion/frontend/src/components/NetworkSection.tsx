/**
 * Network view: capture status, live alerts, devices and access points.
 *
 * State lives here; the pieces are in ./network and the wording is in lib/network.ts (tested).
 * The alert stream resumes from the last alert it saw (see subscribeAlerts), so a restart or a dropped connection loses nothing.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  deleteNetworkData,
  fetchAccessPoints,
  fetchAlerts,
  fetchDevices,
  fetchNetworkStatus,
  markAccessPointKnown,
  startMonitor,
  stopMonitor,
  subscribeAlerts,
  type AccessPointRow,
  type DeviceProfile,
  type MonitorStatus,
  type NetworkAlert,
} from "@/api";
import { captureView, mergeAlert, sensorRows } from "@/lib/network";
import { Button } from "@/components/ui/button";
import { NetworkAlertDetail } from "./NetworkAlertDetail";
import { AccessPointTable } from "./network/AccessPointTable";
import { AlertTable } from "./network/AlertTable";
import { DeviceTable } from "./network/DeviceTable";
import { StatusStrip } from "./network/StatusStrip";

type Tab = "alerts" | "devices" | "aps";
const TABS: { id: Tab; label: string }[] = [
  { id: "alerts", label: "Alerts" },
  { id: "devices", label: "Devices" },
  { id: "aps", label: "Access points" },
];

export function NetworkSection() {
  const [tab, setTab] = useState<Tab>("alerts");
  const [alerts, setAlerts] = useState<NetworkAlert[]>([]);
  const [status, setStatus] = useState<MonitorStatus | null | undefined>(undefined);   // undefined = no answer yet
  const [devices, setDevices] = useState<DeviceProfile[]>([]);
  const [aps, setAps] = useState<AccessPointRow[]>([]);
  const [selected, setSelected] = useState<NetworkAlert | null>(null);
  const [connected, setConnected] = useState(false);
  const [everConnected, setEverConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const running = useRef(false);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await fetchNetworkStatus();
      running.current = s.running;
      setStatus(s);
    } catch {
      setStatus(null);
    }
  }, []);

  // status: every 2 s while capturing, every 10 s otherwise
  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      await refreshStatus();
      if (alive) timer = setTimeout(tick, running.current ? 2_000 : 10_000);
    };
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [refreshStatus]);

  useEffect(() => {
    fetchAlerts().then(setAlerts).catch(() => {});
  }, []);

  useEffect(() => {
    const sub = subscribeAlerts(
      (alert) => setAlerts((prev) => mergeAlert(prev, alert)),
      () => {
        setConnected(true);
        setEverConnected(true);
      },
      () => setConnected(false),
    );
    return () => sub.close();
  }, []);

  // devices and access points load when their tab is open, and refresh while it stays open
  useEffect(() => {
    if (tab === "alerts") return;
    let alive = true;
    const load = () => {
      if (tab === "devices") fetchDevices().then((d) => alive && setDevices(d)).catch(() => {});
      else fetchAccessPoints().then((a) => alive && setAps(a)).catch(() => {});
    };
    load();
    const t = setInterval(load, 15_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [tab]);

  const act = useCallback(async (fn: () => Promise<MonitorStatus>) => {
    setBusy(true);
    setMessage(null);
    try {
      const s = await fn();
      running.current = s.running;
      setStatus(s);
    } catch (e: any) {
      setMessage(e?.message || "The request failed");
    } finally {
      setBusy(false);
    }
  }, []);

  const mark = useCallback(async (bssid: string, known: boolean) => {
    await markAccessPointKnown(bssid, known);
    setAps(await fetchAccessPoints());
  }, []);

  const erase = useCallback(async () => {
    if (!window.confirm("Erase all stored network data (devices, domains, alerts, access points)? This cannot be undone.")) return;
    try {
      const c = await deleteNetworkData();
      setAlerts([]);
      setDevices([]);
      setAps([]);
      setMessage(`Erased ${c.devices ?? 0} devices, ${c.domains ?? 0} domain records, ${c.alerts ?? 0} alerts, ${c.access_points ?? 0} access points.`);
    } catch (e: any) {
      setMessage(e?.message || "Could not erase network data");
    }
  }, []);

  const view = useMemo(() => captureView(status), [status]);
  const sensors = useMemo(() => sensorRows(status), [status]);
  const wifi = status ? status.sensors?.wifi : undefined;

  if (selected) return <NetworkAlertDetail alert={selected} onBack={() => setSelected(null)} />;

  return (
    <div className="flex flex-col gap-5">
      <StatusStrip
        view={view}
        sensors={sensors}
        connected={connected}
        everConnected={everConnected}
        busy={busy}
        onStart={() => act(startMonitor)}
        onStop={() => act(stopMonitor)}
      />
      {message && <p className="text-sm text-muted">{message}</p>}

      <div role="tablist" className="flex gap-1 border-b border-line">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === t.id ? "border-accent-2 text-foreground" : "border-transparent text-muted hover:text-foreground"}`}
          >
            {t.label}
            {t.id === "alerts" && alerts.length > 0 && <span className="ml-1.5 font-mono text-xs text-subtle">{alerts.length}</span>}
          </button>
        ))}
      </div>

      {tab === "alerts" && <AlertTable alerts={alerts} onOpen={setSelected} />}
      {tab === "devices" && <DeviceTable devices={devices} />}
      {tab === "aps" && (
        <AccessPointTable
          aps={aps}
          error={wifi && wifi.available === false ? wifi.reason ?? "Wi-Fi scanning is unavailable" : null}
          fix={wifi?.fix ?? null}
          onMark={mark}
        />
      )}

      <div className="flex items-center justify-between border-t border-line pt-4 text-xs text-subtle">
        <span className="max-w-xl">{status ? status.scope_note : null}</span>
        <Button variant="ghost" size="sm" onClick={erase}>Erase stored data</Button>
      </div>
    </div>
  );
}
