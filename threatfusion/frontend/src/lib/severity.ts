/**
 * severity.ts — one mapping from a risk level to colour, bar count, weight and glyph.
 *
 * Colour is never the only signal: every level also has a label, a bar count and its own glyph.
 * high/critical → danger, medium → warn, low/minimal → ok, unknown → muted (no evidence is not drawn like a low score).
 */

import {
  ShieldCheck,
  Shield,
  ShieldAlert,
  ShieldX,
  ShieldQuestion,
  type LucideIcon,
} from "lucide-react";

export type SeverityLevel =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "minimal"
  | "unknown";

export interface Severity {
  level: SeverityLevel;
  /** Uppercase display label, e.g. "CRITICAL". */
  label: string;
  /** Filled segments out of `MAX_BARS`. */
  bars: number;
  /** Tailwind font-weight class. */
  weight: string;
  /** Tailwind text colour class. */
  text: string;
  /** Tailwind background colour class (meter fill). */
  fill: string;
  icon: LucideIcon;
}

export const MAX_BARS = 5;

const LEVELS: Record<SeverityLevel, Omit<Severity, "level">> = {
  critical: { label: "CRITICAL", bars: 5, weight: "font-bold", text: "text-danger", fill: "bg-danger", icon: ShieldX },
  high: { label: "HIGH", bars: 4, weight: "font-semibold", text: "text-danger", fill: "bg-danger", icon: ShieldAlert },
  medium: { label: "MEDIUM", bars: 3, weight: "font-medium", text: "text-warn", fill: "bg-warn", icon: Shield },
  low: { label: "LOW", bars: 2, weight: "font-normal", text: "text-ok", fill: "bg-ok", icon: ShieldCheck },
  minimal: { label: "MINIMAL", bars: 1, weight: "font-normal", text: "text-ok", fill: "bg-ok", icon: ShieldCheck },
  unknown: { label: "UNKNOWN", bars: 0, weight: "font-normal", text: "text-muted", fill: "bg-muted", icon: ShieldQuestion },
};

/** Map a 0..1 model probability to a severity level (mirrors the backend's label bands). */
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
  if (k === "unknown") return "unknown";
  if (k === "minimal" || k === "safe" || k === "secure" || k === "benign") return "minimal";
  return null;
}

/** Prefers the backend-provided label when it is recognised, otherwise derives the band from the score. */
export function resolveSeverity(score01: number | null | undefined, label?: string | null): Severity {
  const level = levelFromLabel(label) ?? (score01 == null ? "unknown" : levelFromScore(score01));
  return { level, ...LEVELS[level] };
}
