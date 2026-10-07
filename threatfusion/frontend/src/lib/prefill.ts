/**
 * prefill.ts — "Open in ThreatFusion" from the browser extension lands on `/?target=…&type=…`.
 * The link only pre-fills the scan form. It never starts a scan: a link must not be able to make this dashboard query third parties.
 */
export type PrefillType = "domain" | "ip" | "url" | "file_hash";

export interface Prefill {
  target: string;
  type: PrefillType;
}

const TYPES: ReadonlySet<string> = new Set(["domain", "ip", "url", "file_hash"]);
const MAX_TARGET = 2048;

export function parsePrefill(search: string): Prefill | null {
  const params = new URLSearchParams(search);
  const target = (params.get("target") ?? "").trim();
  const type = params.get("type") ?? "domain";
  if (!target || target.length > MAX_TARGET || !TYPES.has(type)) return null;
  return { target, type: type as PrefillType };
}
