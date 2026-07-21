/**
 * severity.ts — monochrome risk encoding.
 *
 * The entire ThreatFusion UI is hueless, so severity can NEVER be expressed with
 * colour. Instead every risk level maps to a bundle of non-colour signals:
 *
 *   - `bars`      : how many of 5 meter segments are filled (density)
 *   - `intensity` : opacity applied to fills/rings (0..1) so higher risk = brighter
 *   - `weight`    : Tailwind font-weight class (heavier = more severe)
 *   - `icon`      : a distinct lucide glyph (outline shield -> filled alert)
 *
 * This keeps the design defensible for the capstone viva: the mapping is explicit,
 * deterministic, and identical everywhere it is consumed.
 */

import {
  ShieldCheck,
  Shield,
  ShieldAlert,
  ShieldX,
  type LucideIcon,
} from "lucide-react";

export type SeverityLevel =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "minimal";

export interface Severity {
  level: SeverityLevel;
  /** Uppercase display label, e.g. "CRITICAL". */
  label: string;
  /** Filled segments out of `MAX_BARS`. */
  bars: number;
  /** Opacity (0..1) for rings / emphasis fills. */
  intensity: number;
  /** Tailwind font-weight class. */
  weight: string;
  /** Distinct monochrome glyph. */
  icon: LucideIcon;
}

export const MAX_BARS = 5;

const LEVELS: Record<SeverityLevel, Omit<Severity, "level">> = {
  critical: { label: "CRITICAL", bars: 5, intensity: 1.0, weight: "font-bold", icon: ShieldX },
  high: { label: "HIGH", bars: 4, intensity: 0.85, weight: "font-semibold", icon: ShieldAlert },
  medium: { label: "MEDIUM", bars: 3, intensity: 0.65, weight: "font-medium", icon: Shield },
  low: { label: "LOW", bars: 2, intensity: 0.45, weight: "font-normal", icon: ShieldCheck },
  minimal: { label: "MINIMAL", bars: 1, intensity: 0.32, weight: "font-normal", icon: ShieldCheck },
};

/**
 * Map a 0..1 model probability to a severity level.
 * Thresholds mirror the backend's rough label bands.
 */
export function levelFromScore(score01: number): SeverityLevel {
  if (score01 >= 0.8) return "critical";
  if (score01 >= 0.6) return "high";
  if (score01 >= 0.4) return "medium";
  if (score01 >= 0.2) return "low";
  return "minimal";
}

/** Normalise a backend label ("Critical", "High"...) to our level enum. */
export function levelFromLabel(label?: string | null): SeverityLevel | null {
  if (!label) return null;
  const k = label.trim().toLowerCase();
  if (k === "critical") return "critical";
  if (k === "high") return "high";
  if (k === "medium" || k === "moderate") return "medium";
  if (k === "low") return "low";
  if (k === "minimal" || k === "safe" || k === "secure" || k === "benign") return "minimal";
  return null;
}

/**
 * Resolve a full Severity bundle. Prefers the backend-provided label when it is
 * recognised, otherwise derives the band from the numeric score.
 */
export function resolveSeverity(score01: number, label?: string | null): Severity {
  const level = levelFromLabel(label) ?? levelFromScore(score01);
  return { level, ...LEVELS[level] };
}
