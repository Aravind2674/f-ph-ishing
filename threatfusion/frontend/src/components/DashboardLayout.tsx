/**
 * DashboardLayout — application shell for ThreatFusion.
 *
 * Chrome layers (bottom → top):
 *   SiteMeteorsBackground (-z-10, mounted in App)
 *   page content (full width)
 *   FloatingNav (z-5000, sole navigation surface — brand / sections / CTA / command)
 *
 * View state still lives in <App/>; this layout only renders chrome and
 * forwards navigation callbacks.
 */
import React, { useCallback, useEffect, useState } from "react";
import { fetchHealth, type HealthResponse } from "@/api";
import { CommandPalette } from "./CommandPalette";
import { FloatingNav, type NavView } from "./FloatingNav";

interface DashboardLayoutProps {
  children: React.ReactNode;
  activeTab?: NavView;
  onTabChange?: (tab: NavView) => void;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({
  children,
  activeTab = "scan",
  onTabChange,
}) => {
  const [health, setHealth] = useState<HealthResponse | null | "error">(null);
  const [paletteOpen, setPaletteOpen] = useState(false);

  // Poll health once on mount to detect an unreachable API (best-effort).
  useEffect(() => {
    let alive = true;
    fetchHealth()
      .then((h) => alive && setHealth(h))
      .catch(() => alive && setHealth("error"));
    return () => {
      alive = false;
    };
  }, []);

  // Global ⌘K / Ctrl+K shortcut — command-palette feel without new routing.
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
    (v: NavView) => {
      onTabChange?.(v);
    },
    [onTabChange]
  );

  const runScan = useCallback(() => {
    // Primary CTA always lands on the targeting console (ScanForm).
    onTabChange?.("scan");
    requestAnimationFrame(() => {
      document.getElementById("tf-target-input")?.focus();
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }, [onTabChange]);

  return (
    <div className="relative z-10 min-h-screen text-foreground">
      <FloatingNav
        activeTab={activeTab}
        onNavigate={navigate}
        onRunScan={runScan}
        onOpenCommand={() => setPaletteOpen(true)}
        health={health}
      />

      {/* Full-width workspace — floating nav is the only chrome reserving space. */}
      <main className="min-h-screen px-4 pb-20 pt-24 sm:px-6 md:px-8 md:pt-28">
        <div className="mx-auto w-full max-w-6xl">{children}</div>
      </main>

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onNavigate={navigate}
        onNewScan={runScan}
      />
    </div>
  );
};
