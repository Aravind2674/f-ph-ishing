/**
 * FeatureProvenance — every engineered feature with its value *and where it came from* (A1-7).
 *
 * An unknown feature is shown as "unknown" with the reason (which source timed out / is not configured / never ran),
 * never as 0. Collapsed by default: it is the audit trail behind the score, not the headline.
 */
import { useState } from "react";
import { ChevronDown, ListChecks } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { SourceChip } from "@/components/SourceChip";
import { featureProvenance } from "@/lib/evidence";
import type { ProviderOutcome } from "@/api";

const fmt = (v: number): string => (Number.isInteger(v) ? String(v) : v.toFixed(3).replace(/0+$/, "").replace(/\.$/, ""));

export function FeatureProvenance({
  features,
  outcomes,
}: {
  features: Record<string, number | null> | null | undefined;
  outcomes: ProviderOutcome[] | undefined;
}) {
  const [open, setOpen] = useState(false);
  const rows = featureProvenance(features, outcomes);
  if (!rows.length) return null;
  const unknown = rows.filter((r) => !r.known).length;
  const byName = new Map((outcomes ?? []).map((o) => [o.source, o]));

  return (
    <Card>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 p-5 text-left"
      >
        <ListChecks className="size-4 text-muted" />
        <span className="text-sm font-semibold text-foreground">Feature provenance</span>
        <span className="tf-eyebrow ml-1">
          {rows.length - unknown} known · {unknown} unknown
        </span>
        <ChevronDown className={cn("ml-auto size-4 text-muted transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <div className="overflow-x-auto px-5 pb-5">
          <table className="w-full min-w-[34rem] border-collapse text-left font-mono text-[11px]">
            <thead>
              <tr className="border-b border-line text-subtle">
                <th className="py-2 pr-3 font-normal">Feature</th>
                <th className="py-2 pr-3 font-normal">Value</th>
                <th className="py-2 font-normal">Source</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.name} className="border-b border-line/60 align-top">
                  <td className="py-2 pr-3 text-foreground">{r.label}</td>
                  <td className="py-2 pr-3 tabular-nums">
                    {r.known ? (
                      <span className="text-foreground">{fmt(r.value as number)}</span>
                    ) : (
                      <span className="italic text-subtle">unknown</span>
                    )}
                  </td>
                  <td className="py-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      {r.sources.map((s) => {
                        const o = byName.get(s.source);
                        return (
                          <SourceChip
                            key={s.source}
                            source={s.source}
                            state={s.status}
                            reason={o?.reason}
                            retryAfter={o?.retry_after}
                            cached={o?.cached}
                            showReason={false}
                          />
                        );
                      })}
                    </div>
                    {r.unknownWhy && <p className="mt-1 text-subtle">{r.unknownWhy}</p>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
