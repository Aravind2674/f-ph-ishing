import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * `cn` — the standard shadcn/ui class-name helper.
 *
 * Merges conditional class lists (clsx) and then resolves Tailwind conflicts
 * (tailwind-merge) so that later utilities win, e.g. `cn("p-2", "p-4") -> "p-4"`.
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * `timeAgo` — compact relative timestamp ("12s", "3m", "2h", "5d") used by
 * the live network feed. Falls back to a locale date for anything older than
 * a week so long-lived alerts still read cleanly.
 */
export function timeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}
