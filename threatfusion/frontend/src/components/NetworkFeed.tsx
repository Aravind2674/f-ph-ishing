/**
 * NetworkFeed — Screen A: real-time scrolling list of network events.
 *
 * Newest on top, live-updating via SSE (handled by the parent). Each row
 * carries a monochrome severity chip, a short title, the involved device
 * name/MAC, a relative timestamp and the fused score — reusing the exact
 * risk visual language (RiskMeter / SeverityTag) from the scan side.
 *
 * Includes a severity filter, an honest per-sensor capability strip (so a
 * degraded sensor is visible, never hidden), and a quiet "all clear" empty
 * state.
 */
import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Radar,
  Crosshair,
  X,
  ShieldCheck,
  ShieldAlert,
  Network as NetworkIcon,
} from "lucide-react";
import type { MonitorStatus, NetworkAlert, NetworkSeverity } from "@/api";
import { cn, timeAgo } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RiskMeter, SeverityTag } from "@/components/RiskIndicators";

interface NetworkFeedProps {
  alerts: NetworkAlert[];
  status: MonitorStatus | null;
  connected: boolean;
  busy: boolean;
  onOpen: (alert: NetworkAlert) => void;
  onStart: () => void;
  onStop: () => void;
}

const ALERT_TYPE_LABEL: Record<string, string> = {
  deauth_flood: "Deauth flood",
  rogue_ap: "Rogue AP",
  evil_twin: "Evil twin",
  new_device: "New device",
  cross_layer_hit: "Cross-layer hit",
  behavioral_deviation: "Behavioural deviation",
  arp_spoof: "ARP spoofing",
};

const SENSOR_ICON: Record<string, typeof NetworkIcon> = {
  arp: NetworkIcon,
  dns: NetworkIcon,
  wifi: Radar,
  dot11: ShieldAlert,
};

const SENSOR_LABEL: Record<string, string> = {
  arp: "ARP",
  dns: "DNS",
  wifi: "WiFi scan",
  dot11: "802.11 deauth",
};

const FILTERS: (NetworkSeverity | "All")[] = ["All", "Critical", "High", "Medium", "Low"];

export function NetworkFeed({
  alerts,
  status,
  connected,
  busy,
  onOpen,
  onStart,
  onStop,
}: NetworkFeedProps) {
  const [filter, setFilter] = useState<NetworkSeverity | "All">("All");

  const filtered = useMemo(
    () => (filter === "All" ? alerts : alerts.filter((a) => a.severity === filter)),
    [alerts, filter]
  );

  const running = status?.running ?? false;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col gap-5"
    >
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-1 flex items-center gap-2">
            <h2 className="text-xl font-semibold tracking-tight text-foreground">
              Network Monitor
            </h2>
            <LiveDot running={running} connected={connected} />
          </div>
          <p className="text-sm text-muted">
            Real-time defensive monitoring of your own network, fused with App-Layer intel.
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          {running ? (
            <Button variant="outline" size="sm" onClick={onStop} disabled={busy}>
              <X className="size-3.5" />
              Stop capture
            </Button>
          ) : (
            <Button variant="subtle" size="sm" onClick={onStart} disabled={busy}>
              <Crosshair className="size-3.5" />
              Start capture
            </Button>
          )}
        </div>
      </div>

      {/* ── Honest sensor capability strip ─────────────────────────────── */}
      <SensorStrip status={status} />

      {/* ── Severity filter ────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {FILTERS.map((f) => {
          const active = filter === f;
          const count =
            f === "All" ? alerts.length : alerts.filter((a) => a.severity === f).length;
          return (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-wide2 transition-colors",
                active
                  ? "border-line-strong bg-surface-2 text-foreground"
                  : "border-line text-muted hover:text-foreground"
              )}
            >
              {f}
              <span className="tabular-nums text-subtle">{count}</span>
            </button>
          );
        })}
      </div>

      {/* ── Alert feed ─────────────────────────────────────────────────── */}
      {filtered.length === 0 ? (
        <AllClear running={running} />
      ) : (
        <div className="flex flex-col gap-2">
          {filtered.map((alert) => (
            <AlertRow key={alert.alert_id} alert={alert} onOpen={onOpen} />
          ))}
        </div>
      )}
    </motion.div>
  );
}

function LiveDot({ running, connected }: { running: boolean; connected: boolean }) {
  const live = running && connected;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide2",
        live ? "text-foreground" : "text-subtle"
      )}
      title={
        live
          ? "Capturing and streaming live"
          : running
          ? "Capturing (stream reconnecting)"
          : "Capture stopped"
      }
    >
      <span
        className={cn(
          "size-1.5 rounded-full",
          live ? "animate-pulse bg-foreground" : "ring-1 ring-subtle"
        )}
      />
      {live ? "Live" : running ? "Running" : "Idle"}
    </span>
  );
}

function SensorStrip({ status }: { status: MonitorStatus | null }) {
  const sensors = status?.sensors ?? {};
  const keys = Object.keys(sensors);
  if (keys.length === 0) {
    return (
      <Card className="flex items-center gap-2 p-4">
        <Radar className="size-4 text-subtle" />
        <span className="text-xs text-subtle">
          Monitor status unavailable — is the backend running on 127.0.0.1:8000?
        </span>
      </Card>
    );
  }
  return (
    <Card>
      <div className="grid grid-cols-2 divide-y divide-line sm:grid-cols-4 sm:divide-x sm:divide-y-0">
        {keys.map((k) => {
          const s = sensors[k];
          const Icon = SENSOR_ICON[k] ?? Radar;
          // available: true = up, false = degraded, null = not started
          const state =
            s.available === true && s.running
              ? "active"
              : s.available === false
              ? "degraded"
              : "idle";
          return (
            <div key={k} className="flex flex-col gap-1.5 p-4" title={s.reason ?? undefined}>
              <div className="flex items-center justify-between">
                <span className="tf-eyebrow">{SENSOR_LABEL[k] ?? k}</span>
                <Icon className="size-4 text-subtle" />
              </div>
              <span
                className={cn(
                  "inline-flex items-center gap-1.5 font-mono text-xs",
                  state === "active"
                    ? "text-foreground"
                    : state === "degraded"
                    ? "text-muted"
                    : "text-subtle"
                )}
              >
                <span
                  className={cn(
                    "size-1.5 rounded-full",
                    state === "active"
                      ? "bg-foreground"
                      : state === "degraded"
                      ? "ring-1 ring-muted"
                      : "ring-1 ring-subtle"
                  )}
                />
                {state === "active" ? "Active" : state === "degraded" ? "Degraded" : "Idle"}
              </span>
              {s.reason && state !== "active" && (
                <span className="line-clamp-2 text-[11px] leading-snug text-subtle">
                  {s.reason}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function AlertRow({
  alert,
  onOpen,
}: {
  alert: NetworkAlert;
  onOpen: (a: NetworkAlert) => void;
}) {
  const device = alert.device_name || alert.device_mac || alert.involved[0] || "—";
  return (
    <motion.button
      layout
      initial={{ opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      onClick={() => onOpen(alert)}
      className="w-full text-left"
    >
      <Card
        interactive
        className="flex items-center gap-4 p-4"
      >
        <SeverityTag
          score={alert.fused_score / 100}
          label={alert.severity}
          showIcon
          className="w-[92px] shrink-0"
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium text-foreground">
              {alert.title}
            </span>
            <Badge variant="subtle" className="shrink-0">
              {ALERT_TYPE_LABEL[alert.alert_type] ?? alert.alert_type}
            </Badge>
          </div>
          <div className="mt-0.5 flex items-center gap-2 font-mono text-[11px] text-subtle">
            <span className="truncate">{device}</span>
            <span>·</span>
            <span className="shrink-0">{timeAgo(alert.timestamp)}</span>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2.5">
          <RiskMeter score={alert.fused_score / 100} label={alert.severity} />
          <span className="w-8 text-right font-mono text-sm tabular-nums text-foreground">
            {Math.round(alert.fused_score)}
          </span>
        </div>
      </Card>
    </motion.button>
  );
}

function AllClear({ running }: { running: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-line py-20 text-center">
      <div className="flex size-14 items-center justify-center rounded-lg border border-line bg-surface-2">
        <ShieldCheck className="size-6 text-subtle" />
      </div>
      <div>
        <p className="text-sm font-medium text-foreground">All clear</p>
        <p className="mx-auto mt-1 max-w-sm text-xs text-subtle">
          {running
            ? "Monitoring your network — no suspicious activity detected yet. New alerts appear here the moment a real signal fires."
            : "Capture is stopped. Start capture to begin watching your network in real time."}
        </p>
      </div>
    </div>
  );
}
