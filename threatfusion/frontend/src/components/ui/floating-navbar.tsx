/**
 * FloatingNavbar — Aceternity UI floating-navbar shell, restyled for ThreatFusion.
 *
 * IMPORTANT: scroll behaviour deliberately overrides Aceternity's stock demo.
 * Direction is tracked with a persistent lastY ref (not scrollY.getPrevious()),
 * so upward scrolls mid-page re-show the nav immediately — closer to Linear /
 * Vercel docs than Aceternity's "only near top" default.
 *
 *   - current < 80 → always visible
 *   - diff > 4     → scrolling down meaningfully → hide
 *   - diff < -4    → scrolling up (even slightly) → show immediately
 *   - dead-zone of ±4px avoids trackpad/inertial flicker
 *   - Transition: 0.2s easeOut — no overshoot
 */
import { useState, useRef } from "react";
import {
  motion,
  AnimatePresence,
  useScroll,
  useMotionValueEvent,
} from "framer-motion";
import { cn } from "@/lib/utils";

export interface FloatingNavbarProps {
  children: React.ReactNode;
  className?: string;
}

export function FloatingNavbar({ children, className }: FloatingNavbarProps) {
  const { scrollY } = useScroll();
  // Visible on first paint — the console header should never start hidden.
  const [visible, setVisible] = useState(true);
  // Persist prior scrollY across renders without re-triggering effects.
  // Updated on every scroll event so `diff` is always relative to the last
  // position, not the initial mount value. Must be a ref — not state.
  const lastY = useRef(0);

  useMotionValueEvent(scrollY, "change", (current) => {
    const previous = lastY.current;
    const diff = current - previous;

    if (current < 80) {
      // Near top of page: always show (independent of direction).
      setVisible(true);
    } else if (diff > 4) {
      // Scrolling down meaningfully: hide.
      setVisible(false);
    } else if (diff < -4) {
      // Scrolling up, even slightly: show immediately — this is the branch
      // that was missing / unreliable when relying on getPrevious().
      setVisible(true);
    }

    lastY.current = current;
  });

  return (
    <AnimatePresence mode="wait">
      <motion.div
        initial={{ opacity: 1, y: 0 }}
        animate={{
          y: visible ? 0 : -100,
          opacity: visible ? 1 : 0,
        }}
        transition={{ duration: 0.2, ease: "easeOut" }}
        // pointer-events off while hidden so it can't intercept clicks mid-exit
        style={{ pointerEvents: visible ? "auto" : "none" }}
        className={cn(
          // Floating pill shell: surface slightly above the page canvas,
          // hairline border, no colour accents.
          "fixed inset-x-0 top-4 z-[5000] mx-auto flex w-[calc(100%-1.5rem)] max-w-5xl items-center justify-between gap-3 rounded-full border border-line bg-surface/95 px-3 py-2 shadow-glow-sm backdrop-blur-xl sm:w-[calc(100%-2rem)] sm:px-4 md:top-6",
          className
        )}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
}
