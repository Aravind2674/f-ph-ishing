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
