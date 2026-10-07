/** Every engineered feature with its value and where it came from. An unknown feature says why (which source failed or never ran), never 0. */
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
  const rows = featureProvenance(features, outcomes);
  if (!rows.length) return null;
  const unknown = rows.filter((r) => !r.known).length;
  const byName = new Map((outcomes ?? []).map((o) => [o.source, o]));

  return (
    <div className="flex flex-col gap-2">
      <p className="font-mono text-xs text-subtle">
        {rows.length - unknown} known · {unknown} unknown
      </p>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[32rem] border-collapse text-left font-mono text-xs">
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
                <td className="py-2 pr-3">
                  {r.known ? <span className="text-foreground">{fmt(r.value as number)}</span> : <span className="italic text-subtle">unknown</span>}
                </td>
                <td className="py-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    {r.sources.map((s) => {
                      const o = byName.get(s.source);
                      return <SourceChip key={s.source} source={s.source} state={s.status} reason={o?.reason} retryAfter={o?.retry_after} cached={o?.cached} showReason={false} />;
                    })}
                  </div>
                  {r.unknownWhy && <p className="mt-1 text-subtle">{r.unknownWhy}</p>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
