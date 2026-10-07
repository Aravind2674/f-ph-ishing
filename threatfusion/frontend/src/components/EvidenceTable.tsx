/**
 * Evidence table: source · status · value · latency. A row with detail opens to show it. Status is colour, icon and word;
 * a flagged value also carries an icon and a screen-reader word.
 */
import { Fragment, useState } from "react";
import { motion } from "framer-motion";
import { Check, ChevronRight, Circle, CircleAlert, CircleHelp, ExternalLink, Minus } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ChipState } from "@/lib/evidence";
import { latencyText, type EvidenceRow, type EvidenceTable as EvidenceData } from "@/lib/scanview";

const STATE_TEXT: Record<ChipState, string> = {
  ok: "text-ok",
  running: "text-accent-2",
  pending: "text-subtle",
  not_found: "text-muted",
  error: "text-danger",
  skipped: "text-subtle",
  not_configured: "text-subtle",
};

function StateIcon({ state }: { state: ChipState }) {
  const cls = "size-3 shrink-0";
  switch (state) {
    case "ok": return <Check className={cls} aria-hidden />;
    case "running": return <span className="size-2 shrink-0 animate-pulse rounded-full bg-accent-2" aria-hidden />;
    case "pending": return <Circle className={cls} aria-hidden />;
    case "not_found": return <CircleHelp className={cls} aria-hidden />;
    case "error": return <CircleAlert className={cls} aria-hidden />;
    default: return <Minus className={cls} aria-hidden />;
  }
}

const isLink = (v: string) => /^https?:\/\//i.test(v);

function Facts({ row }: { row: EvidenceRow }) {
  return (
    <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-xs">
      {row.facts.map((f, i) => (
        <Fragment key={`${f.label}-${i}`}>
          <dt className="text-subtle">{f.label}</dt>
          <dd className={cn("min-w-0 break-words font-mono", f.flag ? "text-warn" : "text-muted")}>
            {isLink(f.value) ? (
              <a href={f.value} target="_blank" rel="noreferrer noopener" className="break-all underline underline-offset-2 hover:text-foreground">
                {f.value} <ExternalLink className="inline size-3 align-[-1px]" aria-hidden />
              </a>
            ) : (
              <>
                {f.flag && <span className="sr-only">Flagged: </span>}
                {f.value}
              </>
            )}
          </dd>
        </Fragment>
      ))}
    </dl>
  );
}

function Row({ row }: { row: EvidenceRow }) {
  const [open, setOpen] = useState(false);
  const expandable = row.facts.length > 0;
  return (
    <>
      <motion.tr initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="border-b border-line last:border-0">
        <td className="px-3 py-2.5">
          {expandable ? (
            <button
              type="button"
              aria-expanded={open}
              onClick={() => setOpen((o) => !o)}
              className="flex items-center gap-1.5 text-left text-sm font-medium text-foreground hover:text-accent"
            >
              <ChevronRight className={cn("size-3.5 shrink-0 text-subtle transition-transform", open && "rotate-90")} aria-hidden />
              {row.label}
            </button>
          ) : (
            <span className="block pl-5 text-sm font-medium text-foreground">{row.label}</span>
          )}
        </td>
        <td className="px-3 py-2.5">
          <span className={cn("inline-flex items-center gap-1.5 font-mono text-xs", STATE_TEXT[row.state])}>
            <StateIcon state={row.state} />
            {row.status}
          </span>
        </td>
        <td className="px-3 py-2.5">
          <span className={cn("break-words font-mono text-xs", row.flag ? "text-warn" : row.state === "ok" ? "text-foreground" : "text-muted")}>
            {row.flag && (
              <>
                <CircleAlert className="mr-1 inline size-3 align-[-1px]" aria-hidden />
                <span className="sr-only">Flagged: </span>
              </>
            )}
            {row.value}
          </span>
        </td>
        <td className="whitespace-nowrap px-3 py-2.5 text-right font-mono text-xs text-subtle">{latencyText(row)}</td>
      </motion.tr>
      {expandable && open && (
        <tr className="border-b border-line bg-surface-2/40">
          <td colSpan={4} className="px-3 py-3 pl-8">
            <Facts row={row} />
          </td>
        </tr>
      )}
    </>
  );
}

export interface EvidenceTableProps {
  rows: EvidenceRow[];
  /** Footer facts for a finished scan. */
  footer?: Pick<EvidenceData, "summary" | "notConfigured" | "caution">;
  /** A scan in flight: rows appear as sources start. */
  running?: boolean;
}

export function EvidenceTable({ rows, footer, running = false }: EvidenceTableProps) {
  return (
    <section aria-label="Evidence" className="flex flex-col gap-2">
      <div className="overflow-hidden rounded-lg border border-line bg-surface">
        <table className="w-full">
          <thead>
            <tr className="border-b border-line">
              <th className="tf-eyebrow h-9 px-3 text-left align-middle font-normal">Source</th>
              <th className="tf-eyebrow h-9 px-3 text-left align-middle font-normal">Status</th>
              <th className="tf-eyebrow h-9 px-3 text-left align-middle font-normal">Value</th>
              <th className="tf-eyebrow h-9 px-3 text-right align-middle font-normal">Latency</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <Row key={row.source} row={row} />
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p className="px-4 py-3 text-sm text-subtle">{running ? "Waiting for sources" : "No sources answered"}</p>}
      </div>
      {footer && (
        <p className="font-mono text-xs text-subtle">
          {footer.summary}
          {footer.notConfigured > 0 && ` · ${footer.notConfigured} not configured`}
          {footer.caution && ` · ${footer.caution}`}
        </p>
      )}
    </section>
  );
}
