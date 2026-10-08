/**
 * ReputationPanel — what the independent reputation sources say about the target (B2).
 *
 * Several sources that do not depend on VirusTotal answer side by side. This card lists *who said what* (with the source's own
 * words and a link to the public record), how old each local list is, and how many channels could not answer. It is not a
 * score: "not listed" is worded as absence of evidence. Monochrome — a listing is carried by a solid badge, the word "Listed"
 * and a heavier border; popularity and scanner context are quiet outline badges.
 */
import { BookMarked, ExternalLink } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { reputationView } from "@/lib/reputation";
import type { ReputationSummary } from "@/api";

export function ReputationPanel({ reputation }: { reputation: ReputationSummary | null | undefined }) {
  const view = reputationView(reputation);
  if (!view) return null;

  return (
    <Card className={cn("flex flex-col gap-3 p-5", view.listed && "border-2 border-foreground")}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <BookMarked className="size-4 text-muted" />
            <span className="text-sm font-semibold text-foreground">Independent reputation</span>
            <span className="tf-eyebrow ml-1">not a score · separate from the maliciousness score</span>
          </div>
          <p className={cn("mt-1 text-sm", view.listed ? "font-semibold text-foreground" : "text-muted")}>{view.headline}</p>
          <p className="mt-0.5 font-mono text-[11px] text-subtle">{view.answered}</p>
        </div>
        <Badge variant={view.listed ? "solid" : "outline"}>{view.listed ? "Listed" : "Not listed"}</Badge>
      </div>

      {view.rows.length > 0 && (
        <ul className="flex flex-col divide-y divide-line/60 border-t border-line">
          {view.rows.map((r) => (
            <li key={r.source} className="flex flex-col gap-0.5 py-2 text-xs">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className={cn("font-mono text-[11px]", r.kind === "listed" ? "font-semibold text-foreground" : "text-muted")}>{r.label}</span>
                <Badge variant={r.kind === "listed" ? "solid" : "outline"}>{r.statement}</Badge>
                {r.match && <span className="text-subtle">matched {r.match}</span>}
                {r.age && (
                  <span className={cn("font-mono text-[11px]", r.stale ? "font-semibold text-foreground" : "text-subtle")}>
                    list {r.age}
                    {r.stale ? " — out of date" : ""}
                  </span>
                )}
                {r.reference && (
                  <a href={r.reference} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-subtle underline-offset-2 hover:text-foreground hover:underline">
                    record <ExternalLink className="size-3" />
                  </a>
                )}
              </div>
              {r.detail && <p className="text-muted">{r.detail}</p>}
            </li>
          ))}
        </ul>
      )}

      {view.popularity && <p className="text-xs text-muted">{view.popularity}</p>}

      {view.feeds.length > 0 && (
        <p className="font-mono text-[11px] text-subtle">
          Local lists: {view.feeds.map((f) => `${f.label} ${f.text}`).join(" · ")}
        </p>
      )}
      {view.notes.map((n) => (
        <p key={n} className="text-xs text-subtle">{n}</p>
      ))}
    </Card>
  );
}
