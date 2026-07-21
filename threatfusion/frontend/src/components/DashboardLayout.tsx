import React, { useCallback, useEffect, useState } from "react";
import {
  Crosshair,
  History as HistoryIcon,
  Settings as SettingsIcon,
  Command as CommandIcon,
  Radar,
  Menu,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { fetchHealth, type HealthResponse } from "@/api";
import { CommandPalette } from "./CommandPalette";

type View = "scan" | "history" | "settings";

interface DashboardLayoutProps {
  children: React.ReactNode;
  activeTab?: View;
  onTabChange?: (tab: View) => void;
}

const NAV: { id: View; label: string; icon: typeof Crosshair }[] = [
  { id: "scan", label: "Scan", icon: Crosshair },
  { id: "history", label: "History", icon: HistoryIcon },
  { id: "settings", label: "Settings", icon: SettingsIcon },
];

/** Small left-nav item; active state is drawn with a fill + a left marker, no hue. */
function NavItem({
  item,
  active,
  onClick,
}: {
  item: (typeof NAV)[number];
  active: boolean;
  onClick: () => void;
}) {
  const Icon = item.icon;
  return (
    <button
      onClick={onClick}
      className={cn(
        "group relative flex items-center gap-3 rounded-md px-3 py-2.5 text-sm transition-colors",
        active
          ? "bg-surface-2 text-foreground"
          : "text-muted hover:bg-surface-2/60 hover:text-foreground"
      )}
    >
      {/* Active marker — a thin white bar, not a coloured accent. */}
      <span
        className={cn(
          "absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-full bg-foreground transition-opacity",
          active ? "opacity-100" : "opacity-0"
        )}
      />
      <Icon className="size-4" />
      <span className={active ? "font-medium" : ""}>{item.label}</span>
    </button>
  );
}

/**
 * Mock/live indicator. Deliberately monochrome: "LIVE" is a solid dot, "MOCK"
 * is a hollow ring, "OFFLINE" is a crossed marker. State is read from /health.
 */
function ModeIndicator({ health }: { health: HealthResponse | null | "error" }) {
  if (health === "error") {
    return (
      <span className="flex items-center gap-2 rounded-md border border-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-wide2 text-subtle">
        <span className="size-1.5 rounded-full ring-1 ring-subtle" />
        API Offline
      </span>
    );
  }
  if (!health) {
    return (
      <span className="flex items-center gap-2 rounded-md border border-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-wide2 text-subtle">
        <span className="size-1.5 rounded-full bg-subtle animate-pulse" />
        Connecting
      </span>
    );
  }
  const mock = health.mock_mode;
  return (
    <span
      className={cn(
        "flex items-center gap-2 rounded-md border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wide2",
        mock ? "border-line text-muted" : "border-line-strong text-foreground"
      )}
      title={mock ? "Serving synthetic/mock data" : "Serving live intelligence"}
    >
      <span
        className={cn(
          "size-1.5 rounded-full",
          mock ? "ring-1 ring-muted" : "bg-foreground"
        )}
      />
      {mock ? "Mock Data" : "Live"}
      <span className="text-subtle">· v{health.version}</span>
    </span>
  );
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({
  children,
  activeTab = "scan",
  onTabChange,
}) => {
  const [health, setHealth] = useState<HealthResponse | null | "error">(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // Poll health once on mount for the mock/live badge (best-effort).
  useEffect(() => {
    let alive = true;
    fetchHealth()
      .then((h) => alive && setHealth(h))
      .catch(() => alive && setHealth("error"));
    return () => {
      alive = false;
    };
  }, []);

  // Global ⌘K / Ctrl+K shortcut to toggle the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const navigate = useCallback(
    (v: View) => {
      onTabChange?.(v);
      setMobileNavOpen(false);
    },
    [onTabChange]
  );

  const Brand = (
    <div className="flex items-center gap-3 px-3">
      <div className="flex size-9 items-center justify-center rounded-md border border-line-strong bg-surface-2">
        <Radar className="size-5 text-foreground" />
      </div>
      <div className="leading-tight">
        <div className="font-mono text-sm font-semibold tracking-tight text-foreground">
          THREAT<span className="text-muted">FUSION</span>
        </div>
        <div className="tf-eyebrow">Attack-Surface Risk Fusion</div>
      </div>
    </div>
  );

  const NavList = (
    <nav className="flex flex-col gap-1 px-3">
      <div className="tf-eyebrow px-3 pb-2 pt-1">Console</div>
      {NAV.map((item) => (
        <NavItem
          key={item.id}
          item={item}
          active={activeTab === item.id}
          onClick={() => navigate(item.id)}
        />
      ))}
    </nav>
  );

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* ── Sidebar (desktop) ─────────────────────────────────────────── */}
      <aside className="fixed left-0 top-0 z-40 hidden h-screen w-64 flex-col border-r border-line bg-surface/60 py-5 backdrop-blur-xl md:flex">
        <div className="mb-8">{Brand}</div>
        {NavList}
        <div className="mt-auto px-6">
          <div className="tf-eyebrow mb-2">Session</div>
          <ModeIndicator health={health} />
        </div>
      </aside>

      {/* ── Mobile nav drawer ─────────────────────────────────────────── */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div
            className="absolute inset-0 bg-background/70 backdrop-blur-sm"
            onClick={() => setMobileNavOpen(false)}
          />
          <div className="absolute left-0 top-0 h-full w-64 border-r border-line bg-surface py-5">
            <div className="mb-6 flex items-center justify-between pr-3">
              {Brand}
              <button
                onClick={() => setMobileNavOpen(false)}
                className="text-muted hover:text-foreground"
                aria-label="Close navigation"
              >
                <X className="size-5" />
              </button>
            </div>
            {NavList}
          </div>
        </div>
      )}

      {/* ── Top bar ───────────────────────────────────────────────────── */}
      <header className="fixed right-0 top-0 z-30 flex h-16 w-full items-center justify-between border-b border-line bg-background/80 px-4 backdrop-blur-xl md:w-[calc(100%-16rem)] md:px-6">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileNavOpen(true)}
            className="text-muted hover:text-foreground md:hidden"
            aria-label="Open navigation"
          >
            <Menu className="size-5" />
          </button>
          <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-wide2 text-subtle">
            <span className="hidden sm:inline">ThreatFusion</span>
            <span className="hidden sm:inline text-subtle/50">/</span>
            <span className="text-foreground">{activeTab}</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Command palette trigger — mirrors the ⌘K shortcut. */}
          <button
            onClick={() => setPaletteOpen(true)}
            className="group flex items-center gap-2 rounded-md border border-line bg-surface-2 px-2.5 py-1.5 text-xs text-muted transition-colors hover:border-line-strong hover:text-foreground"
          >
            <CommandIcon className="size-3.5" />
            <span className="hidden sm:inline">Command</span>
            <kbd className="rounded border border-line bg-surface px-1 font-mono text-[10px] text-subtle">
              ⌘K
            </kbd>
          </button>
          <div className="md:hidden">
            <ModeIndicator health={health} />
          </div>
        </div>
      </header>

      {/* ── Workspace ─────────────────────────────────────────────────── */}
      <main className="min-h-screen px-4 pb-16 pt-24 md:ml-64 md:px-8">
        <div className="mx-auto w-full max-w-6xl">{children}</div>
      </main>

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onNavigate={navigate}
        onNewScan={() => navigate("scan")}
      />
    </div>
  );
};
