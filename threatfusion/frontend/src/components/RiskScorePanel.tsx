/**
 * RiskScorePanel — the two channels side by side, then the headline.
 *
 * "URL model" and "Provider evidence" measure different things, so both scores are shown exactly as computed. The headline
 * is the higher-risk band of the two; the line under it says which channel drove it, and a Disagree tag appears when they
 * are more than 15 points apart. A missing score is "—", never 0.
 */
import { cn } from "@/lib/utils";
import { resolveSeverity } from "@/lib/severity";
import { DASH, type ChannelView, type VerdictView } from "@/lib/verdict";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

export interface RiskScorePanelProps {
  view: VerdictView;
  /** Hide the headline row (the network alert shows only the two channel scores). */
  showHeadline?: boolean;
  className?: string;
}

export function RiskScorePanel({ view, showHeadline = true, className }: RiskScorePanelProps) {
  const sev = resolveSeverity(null, view.headline === DASH ? null : view.headline);
  return (
    <div className={cn("flex flex-col gap-3", className)}>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {view.channels.map((channel) => (
          <ScoreCard
            key={channel.key}
            channel={channel}
            driving={showHeadline && (view.drivenBy === channel.key || view.drivenBy === "both")}
            note={channel.key === "url_model" ? view.prevalence : null}
          />
        ))}
      </div>

      {showHeadline && (
        <div className="flex flex-col gap-2 px-1 pt-1">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <span className={cn("font-mono text-xs uppercase tracking-wide2 text-foreground", sev.weight)}>{sev.label}</span>
            {view.disagree && <Badge variant="outline">Disagree</Badge>}
            <span className="text-xs text-muted">{view.reason}</span>
          </div>
          {view.providerReasons.length > 0 && (
            <ul className="flex flex-col gap-0.5 font-mono text-xs text-muted">
              {view.providerReasons.map((reason) => (
                <li key={reason}>· {reason}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function ScoreCard({ channel, driving, note }: { channel: ChannelView; driving: boolean; note: string | null }) {
  const unavailable = channel.value == null;
  return (
    <Card className={cn("flex flex-col gap-4 p-5", driving && "border-line-strong")}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold tracking-tight text-foreground">{channel.label}</span>
        {driving && <Badge variant="solid">Drives verdict</Badge>}
      </div>
      <p className="-mt-3 text-xs text-subtle">{channel.hint}</p>

      <div className="flex items-baseline gap-1.5">
        <span className="font-mono text-4xl font-semibold tabular-nums leading-none text-foreground">{channel.text}</span>
        {!unavailable && <span className="font-mono text-xs uppercase tracking-wide2 text-subtle">/ 100</span>}
        {channel.band && <span className="ml-auto font-mono text-xs uppercase tracking-wide2 text-muted">{channel.band}</span>}
      </div>
      <Progress value={unavailable ? 0 : Math.max(0, Math.min(100, channel.value as number))} aria-label={`${channel.label} score`} />
      {note && <p className="font-mono text-xs text-subtle">{note}</p>}
    </Card>
  );
}
