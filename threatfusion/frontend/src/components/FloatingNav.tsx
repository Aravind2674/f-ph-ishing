/**
 * FloatingNav — ThreatFusion wrapper around the Aceternity FloatingNavbar shell.
 *
 * Mounted once inside DashboardLayout. Nav items map to the existing view state
 * owned by <App/> (scan / history / settings) — no new router introduced here.
 * The solid white "Run scan" pill is the single deliberate fill inversion
 * allowed by the design system.
 */
import { useState } from "react";
import {
  Crosshair,
  History as HistoryIcon,
  Settings as SettingsIcon,
  Radar,
  Network as NetworkIcon,
  Menu,
  X,
  Command as CommandIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { FloatingNavbar } from "@/components/ui/floating-navbar";
import type { HealthResponse } from "@/api";

export type NavView = "scan" | "network" | "history" | "settings";

interface FloatingNavProps {
  activeTab: NavView;
  onNavigate: (view: NavView) => void;
  onRunScan: () => void;
  onOpenCommand: () => void;
  health: HealthResponse | null | "error";
}

const NAV: {
  id: NavView;
  label: string;
  icon: typeof Crosshair;
}[] = [
  { id: "scan", label: "Console", icon: Crosshair },
  { id: "network", label: "Network", icon: NetworkIcon },
  { id: "history", label: "History", icon: HistoryIcon },
  { id: "settings", label: "Settings", icon: SettingsIcon },
];

/** Compact mock/live indicator — solid dot = live, hollow ring = mock. */
function ModeDot({ health }: { health: HealthResponse | null | "error" }) {
  if (health === "error") {
    return (
      <span
        className="hidden items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide2 text-subtle sm:inline-flex"
        title="API unreachable"
      >
        <span className="size-1.5 rounded-full ring-1 ring-subtle" />
        Offline
      </span>
    );
  }
  if (!health) {
    return (
      <span className="hidden items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide2 text-subtle sm:inline-flex">
        <span className="size-1.5 animate-pulse rounded-full bg-subtle" />
        …
      </span>
    );
  }
  const mock = health.mock_mode;
  return (
    <span
      className={cn(
        "hidden items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide2 sm:inline-flex",
        mock ? "text-muted" : "text-foreground"
      )}
      title={mock ? "Serving synthetic/mock data" : "Serving live intelligence"}
    >
      <span
        className={cn(
          "size-1.5 rounded-full",
          mock ? "ring-1 ring-muted" : "bg-foreground"
        )}
      />
      {mock ? "Mock" : "Live"}
    </span>
  );
}

export function FloatingNav({
  activeTab,
  onNavigate,
  onRunScan,
  onOpenCommand,
  health,
}: FloatingNavProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  const go = (view: NavView) => {
    onNavigate(view);
    setMobileOpen(false);
  };

  return (
    <>
      <FloatingNavbar>
        {/* ── Brand (sans wordmark — chrome, not data) ───────────────── */}
        <button
          type="button"
          onClick={() => go("scan")}
          className="flex shrink-0 items-center gap-2.5 rounded-full pr-1 text-left transition-opacity hover:opacity-90"
          aria-label="ThreatFusion home"
        >
          <span className="flex size-8 items-center justify-center rounded-lg border border-line-strong bg-surface-2">
            <Radar className="size-4 text-foreground" />
          </span>
          <span className="hidden font-sans text-sm font-semibold tracking-tight text-foreground sm:inline">
            Threat<span className="text-muted">Fusion</span>
          </span>
        </button>

        {/* ── Desktop nav links ──────────────────────────────────────── */}
        <nav className="hidden items-center gap-0.5 md:flex">
          {NAV.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => go(item.id)}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full px-3.5 py-1.5 text-sm transition-colors",
                  active
                    ? "bg-surface-2 font-medium text-foreground"
                    : "text-muted hover:text-foreground"
                )}
              >
                <Icon className="size-3.5 opacity-70" />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* ── Right cluster: mode · ⌘K · CTA ─────────────────────────── */}
        <div className="flex shrink-0 items-center gap-2">
          <ModeDot health={health} />

          <button
            type="button"
            onClick={onOpenCommand}
            className="hidden size-8 items-center justify-center rounded-full border border-line text-muted transition-colors hover:border-line-strong hover:text-foreground sm:inline-flex"
            aria-label="Open command palette"
            title="Command (⌘K)"
          >
            <CommandIcon className="size-3.5" />
          </button>

          {/* Mobile menu toggle — keeps logo + CTA visible below md. */}
          <button
            type="button"
            onClick={() => setMobileOpen((o) => !o)}
            className="inline-flex size-8 items-center justify-center rounded-full border border-line text-muted transition-colors hover:text-foreground md:hidden"
            aria-label={mobileOpen ? "Close menu" : "Open menu"}
          >
            {mobileOpen ? <X className="size-4" /> : <Menu className="size-4" />}
          </button>

          {/* Primary inversion: solid white pill. */}
          <button
            type="button"
            onClick={() => {
              onRunScan();
              setMobileOpen(false);
            }}
            className="inline-flex h-8 items-center justify-center rounded-full bg-foreground px-3.5 text-xs font-semibold text-background transition-opacity hover:opacity-90 active:scale-[0.98] sm:px-4 sm:text-sm"
          >
            Run scan
          </button>
        </div>
      </FloatingNavbar>

      {/* ── Mobile dropdown (links only; logo + CTA stay in the pill) ── */}
      {mobileOpen && (
        <div className="fixed inset-x-0 top-[4.5rem] z-[4999] px-3 md:hidden">
          <div className="mx-auto max-w-5xl overflow-hidden rounded-2xl border border-line bg-surface/95 shadow-glow-sm backdrop-blur-xl">
            <nav className="flex flex-col p-2">
              {NAV.map((item) => {
                const Icon = item.icon;
                const active = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => go(item.id)}
                    className={cn(
                      "flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-colors",
                      active
                        ? "bg-surface-2 font-medium text-foreground"
                        : "text-muted hover:bg-surface-2/60 hover:text-foreground"
                    )}
                  >
                    <Icon className="size-4" />
                    {item.label}
                  </button>
                );
              })}
              <button
                type="button"
                onClick={() => {
                  onOpenCommand();
                  setMobileOpen(false);
                }}
                className="mt-1 flex items-center gap-3 rounded-xl border-t border-line px-3 py-2.5 text-sm text-muted hover:text-foreground"
              >
                <CommandIcon className="size-4" />
                Command palette
                <kbd className="ml-auto rounded border border-line px-1.5 font-mono text-[10px] text-subtle">
                  ⌘K
                </kbd>
              </button>
            </nav>
          </div>
        </div>
      )}
    </>
  );
}
