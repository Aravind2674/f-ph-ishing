/**
 * ReportKitPanel — "how do I report this?" (B16).
 *
 * Prepares a copy-ready report and lists the official Indian channels with *when to use each* (the national cyber-fraud helpline
 * 1930 first if money was lost). ThreatFusion submits nothing for the user: the panel says so, the text holds only what ThreatFusion
 * observed, and the user adds what only they know. Monochrome: the helpline is marked urgent with a solid badge and wording.
 */
import { useState } from "react";
import { ClipboardCopy, ExternalLink, LifeBuoy } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { kitView } from "@/lib/india";
import type { ReportKit } from "@/api";

export function ReportKitPanel({ kit, lostMoney, onToggleLost }: { kit: ReportKit | null | undefined; lostMoney: boolean; onToggleLost?: (v: boolean) => void }) {
  const [copied, setCopied] = useState(false);
  const view = kitView(kit, lostMoney);
  if (!view) return null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(view.summary);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable — the text is selectable below */
    }
  };
  return (
    <Card className="flex flex-col gap-4 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <LifeBuoy className="size-4 text-muted" />
          <span className="text-sm font-semibold text-foreground">{view.title}</span>
        </div>
        {onToggleLost && (
          <label className="flex items-center gap-2 text-xs text-muted">
            <input type="checkbox" checked={lostMoney} onChange={(e) => onToggleLost(e.target.checked)} />I lost money or shared a code
          </label>
        )}
      </div>

      <ol className="flex list-decimal flex-col gap-1 pl-5 text-sm text-foreground">
        {view.steps.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>

      <div className="flex flex-col gap-2">
        {view.channels.map((c) => (
          <div key={c.id} className="rounded-md border border-line p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-foreground">{c.name}</span>
              {c.urgent && <Badge variant="solid">Call first if money was lost</Badge>}
              {c.url ? (
                <a href={c.url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 font-mono text-xs text-muted underline-offset-2 hover:text-foreground hover:underline">
                  {c.how} <ExternalLink className="size-3" />
                </a>
              ) : (
                <span className="font-mono text-xs text-muted">{c.how}</span>
              )}
            </div>
            <p className="mt-1 text-xs text-muted">{c.useWhen}</p>
            {c.note && <p className="mt-0.5 text-[11px] text-subtle">{c.note}</p>}
          </div>
        ))}
      </div>

      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="tf-eyebrow">Text to copy (add the details only you know)</span>
          <Button type="button" variant="outline" size="sm" onClick={copy}>
            <ClipboardCopy className="size-3.5" />
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
        <textarea readOnly value={view.summary} rows={7} className="w-full rounded-md border border-line bg-surface-2/40 p-3 font-mono text-[11px] text-foreground" />
      </div>

      {view.reminders.map((r) => (
        <p key={r} className="text-xs text-subtle">{r}</p>
      ))}
    </Card>
  );
}
