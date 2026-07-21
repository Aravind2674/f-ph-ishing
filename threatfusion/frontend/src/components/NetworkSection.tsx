/**
 * NetworkSection — container for the ThreatFusion Network Layer.
 *
 * Owns all network view state (alerts, monitor status, selection, filter)
 * and the live SSE subscription, then delegates rendering to:
 *   - <NetworkFeed/>          (Screen A — live alert feed)
 *   - <NetworkAlertDetail/>   (Screen B — full evidence breakdown)
 *
 * Mirrors the state-in-parent pattern used by <App/> for scan/history, so
 * no new routing or state library is introduced.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  fetchAlerts,
  fetchNetworkStatus,
  startMonitor as apiStart,
  stopMonitor as apiStop,
  subscribeAlerts,
  type MonitorStatus,
  type NetworkAlert,
} from "@/api";
import { NetworkFeed } from "./NetworkFeed";
import { NetworkAlertDetail } from "./NetworkAlertDetail";

const STATUS_POLL_MS = 10_000;

export function NetworkSection() {
  const [alerts, setAlerts] = useState<NetworkAlert[]>([]);
  const [status, setStatus] = useState<MonitorStatus | null>(null);
  const [selected, setSelected] = useState<NetworkAlert | null>(null);
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await fetchNetworkStatus());
    } catch {
      setStatus(null);
    }
  }, []);

  // Initial load + status polling.
  useEffect(() => {
    let alive = true;
    fetchAlerts()
      .then((a) => alive && setAlerts(a))
      .catch(() => {});
    refreshStatus();
    const t = setInterval(refreshStatus, STATUS_POLL_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [refreshStatus]);

  // Live SSE subscription — newest alerts prepended, de-duplicated by id.
  useEffect(() => {
    const es = subscribeAlerts(
      (alert) => {
        setAlerts((prev) =>
          prev.some((a) => a.alert_id === alert.alert_id)
            ? prev
            : [alert, ...prev].slice(0, 1000)
        );
      },
      () => setConnected(true),
      () => setConnected(false)
    );
    esRef.current = es;
    return () => {
      es.close();
      esRef.current = null;
    };
  }, []);

  const handleStart = useCallback(async () => {
    setBusy(true);
    try {
      setStatus(await apiStart());
    } catch {
      /* surfaced via status card */
    } finally {
      setBusy(false);
    }
  }, []);

  const handleStop = useCallback(async () => {
    setBusy(true);
    try {
      setStatus(await apiStop());
    } catch {
      /* surfaced via status card */
    } finally {
      setBusy(false);
    }
  }, []);

  if (selected) {
    return (
      <NetworkAlertDetail alert={selected} onBack={() => setSelected(null)} />
    );
  }

  return (
    <NetworkFeed
      alerts={alerts}
      status={status}
      connected={connected}
      busy={busy}
      onOpen={setSelected}
      onStart={handleStart}
      onStop={handleStop}
    />
  );
}
