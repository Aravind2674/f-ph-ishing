/**
 * MessageCheck — paste an SMS / WhatsApp message and see which known Indian scam patterns it resembles (B16).
 *
 * The check is local (nothing is stored or sent anywhere) and is *not a verdict*: the card shows the words that triggered each flag,
 * why it matters, the score arithmetic and the limits. A report kit is one click away.
 */
import { useState } from "react";
import { MessageSquareWarning } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ReportKitPanel } from "@/components/ReportKitPanel";
import { analyzeMessage, buildReportKit, type ReportKit, type TextAnalysis } from "@/api";
import { cn } from "@/lib/utils";
import { messageView } from "@/lib/india";

export function MessageCheck() {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<TextAnalysis | null>(null);
  const [kit, setKit] = useState<ReportKit | null>(null);
  const [lost, setLost] = useState(false);

  const check = async () => {
    if (!text.trim()) return;
    setBusy(true);
    setError(null);
    setKit(null);
    try {
      setAnalysis(await analyzeMessage(text));
    } catch (e: any) {
      setError(e.message || "Could not check the message");
    } finally {
      setBusy(false);
    }
  };

  const prepare = async (lostMoney: boolean) => {
    setLost(lostMoney);
    try {
      setKit(await buildReportKit({ kind: "message", message_excerpt: text, lost_money: lostMoney, reasons: analysis?.matches.slice(0, 3).map((m) => `${m.label}: "${m.evidence}"`) }));
    } catch (e: any) {
      setError(e.message || "Could not prepare the report");
    }
  };

  const view = messageView(analysis);
  const alarm = view?.risk === "high" || view?.risk === "medium";

  return (
    <div className="flex flex-col gap-4">
      <Card className="flex flex-col gap-3 p-5">
        <div className="flex items-center gap-2">
          <MessageSquareWarning className="size-4 text-muted" />
          <span className="text-sm font-semibold text-foreground">Check a message</span>
          <span className="tf-eyebrow ml-1">SMS · WhatsApp · call script · local, nothing is stored</span>
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={5}
          maxLength={20000}
          placeholder="Paste the message here — for example: “Dear customer, your KYC expires today. Update now: http://…”"
          className="w-full rounded-md border border-line bg-surface-2/40 p-3 text-sm text-foreground placeholder:text-subtle"
        />
        <div className="flex items-center gap-3">
          <Button type="button" onClick={check} disabled={busy || !text.trim()}>{busy ? "Checking…" : "Check this message"}</Button>
          <span className="text-xs text-subtle">English (and common Hinglish spellings). Hindi / Tamil copy is not available yet.</span>
        </div>
        {error && <p className="font-mono text-xs text-foreground">{error}</p>}
      </Card>

      {view && (
        <Card className={cn("flex flex-col gap-3 p-5", view.risk === "high" && "border-2 border-foreground")}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <p className={cn("text-sm", alarm ? "font-semibold text-foreground" : "text-muted")}>{view.headline}</p>
            <Badge variant={alarm ? "solid" : "outline"}>{view.risk.toUpperCase()}</Badge>
          </div>
          <p className="font-mono text-[11px] text-subtle">score {view.scoreText} · {view.arithmetic}</p>
          {view.flags.length > 0 && (
            <ul className="flex flex-col gap-2">
              {view.flags.map((f) => (
                <li key={f.label} className="rounded-md border border-line p-3 text-xs">
                  <div className="font-semibold text-foreground">{f.label}</div>
                  <div className="mt-0.5 font-mono text-[11px] text-muted">“{f.evidence}”</div>
                  <div className="mt-1 text-muted">{f.why}</div>
                  <div className="mt-0.5 text-subtle">What to do: {f.advice}</div>
                </li>
              ))}
            </ul>
          )}
          {view.links.length > 0 && (
            <div className="flex flex-col gap-1 text-xs">
              <span className="tf-eyebrow">Links in the message</span>
              {view.links.map((l) => (
                <span key={l.host} className="font-mono text-[11px] text-muted">
                  {l.host}
                  {l.note ? ` — ${l.note}` : ""}
                </span>
              ))}
            </div>
          )}
          {view.advice.length > 0 && (
            <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-foreground">
              {view.advice.map((a) => (
                <li key={a}>{a}</li>
              ))}
            </ul>
          )}
          <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
            <Button type="button" variant="outline" size="sm" onClick={() => prepare(false)}>Prepare a report</Button>
            <Button type="button" variant="outline" size="sm" onClick={() => prepare(true)}>I lost money or shared a code</Button>
          </div>
          {view.limits.map((l) => (
            <p key={l} className="text-xs text-subtle">{l}</p>
          ))}
          {view.truncated && <p className="text-xs text-subtle">Only the first part of a very long message was read.</p>}
        </Card>
      )}

      {kit && <ReportKitPanel kit={kit} lostMoney={lost} onToggleLost={(v) => prepare(v)} />}
    </div>
  );
}
