/**
 * india.ts — view models for the message check and the report kit (B16).
 *
 * The promises: the result is *not a verdict* (no match is not "safe", a match may be genuine) and says so; every flag shows the
 * words that triggered it and why it matters; the score arithmetic is visible; and the report kit never claims to submit anything
 * on the user's behalf — it prepares text and lists the official channels with when to use each.
 */
import type { ReportKit, TextAnalysis } from "../api.ts";

export interface MessageView {
  risk: TextAnalysis["risk"];
  headline: string;
  scoreText: string;
  flags: { label: string; evidence: string; why: string; advice: string }[];
  links: { host: string; note: string | null; kind: "lookalike" | "shortener" | "plain" }[];
  advice: string[];
  arithmetic: string;
  limits: string[];
  truncated: boolean;
}

const HEADLINES: Record<TextAnalysis["risk"], string> = {
  high: "This message strongly resembles a known scam",
  medium: "This message resembles known scam patterns",
  low: "A weak scam signal — be careful",
  none: "No known scam pattern found (that does not make it safe)",
};

export function messageView(a: TextAnalysis | null | undefined): MessageView | null {
  if (!a) return null;
  return {
    risk: a.risk,
    headline: HEADLINES[a.risk],
    scoreText: `${a.score.toFixed(2)} (a rule score, not a probability)`,
    flags: a.matches.map((m) => ({ label: m.label, evidence: m.evidence, why: m.why, advice: m.advice })),
    links: a.urls.map((u) => ({
      host: u.host ?? u.url,
      note: u.note,
      kind: u.brand_check?.status === "lookalike" ? "lookalike" : u.shortener ? "shortener" : "plain",
    })),
    advice: a.advice,
    arithmetic: a.arithmetic,
    limits: a.limits,
    truncated: a.truncated,
  };
}

export interface KitView {
  title: string;
  summary: string;
  steps: string[];
  channels: { id: string; name: string; how: string; url: string | null; useWhen: string; note: string | null; urgent: boolean }[];
  reminders: string[];
}

export function kitView(k: ReportKit | null | undefined, lostMoney = false): KitView | null {
  if (!k) return null;
  return {
    title: lostMoney ? "Money lost? Do these in order" : "How to report this",
    summary: k.summary_text,
    steps: k.steps,
    channels: k.channels.map((c) => ({
      id: c.id, name: c.name, how: c.how, url: c.url, useWhen: c.use_when, note: c.note, urgent: c.id === "helpline_1930",
    })),
    reminders: k.reminders,
  };
}
