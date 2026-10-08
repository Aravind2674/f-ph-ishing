/**
 * SiteMeteorsBackground — full-page ambient meteors layer for ThreatFusion.
 *
 * Mounted once at the app root (not per-page / not inside DashboardLayout) so
 * it never remounts on view changes and never competes with the floating nav
 * or opaque surface cards for z-index. Recolored to low-opacity white so it
 * stays inside the monochrome design system — felt more than seen.
 *
 * The shell (DashboardLayout) is intentionally transparent so meteors show
 * through gutters/gaps; opaque --surface cards still cover them locally.
 */
"use client";
import { Meteors } from "@/components/ui/meteors";

export function SiteMeteorsBackground() {
  return (
    <div
      aria-hidden
      className="pointer-events-none fixed inset-0 -z-10 overflow-hidden"
    >
      {/*
        Spread across the viewport: the stock primitive lays meteors over an
        ~800px band, so we center a wide relative stage and keep density low.
        Opacity ~30–40% white — ambient texture only, no coloured blur blob.
      */}
      <div className="absolute left-1/2 top-0 h-full w-[min(100vw,90rem)] -translate-x-1/2">
        <Meteors number={30} className="!bg-white/40 before:!from-white/30" />
      </div>
    </div>
  );
}
