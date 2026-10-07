/**
 * The two channel scores and the line that says which one drove the verdict.
 * Both scores are shown exactly as computed; a missing score is "—", never 0. "Disagree" appears when they are more than 15 points apart.
 */
import { cn } from "@/lib/utils";
import { resolveSeverity } from "@/lib/severity";
import { type ChannelView, type VerdictView } from "@/lib/verdict";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

export interface RiskScorePanelProps {
  view: VerdictView;
  /** Show the reason line under the scores (the network alert shows only the two scores). */
  showHeadline?: boolean;
  className?: string;
}

export function RiskScorePanel({ view, showHeadline = true, className }: RiskScorePanelProps) {
  return (
    <div className={cn("flex flex-col gap-3", className)}>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {view.channels.map((channel) => (
          <Score
            key={channel.key}
            channel={channel}
            driving={showHeadline && (view.drivenBy === channel.key || view.drivenBy === "both")}
            note={channel.key === "url_model" ? view.prevalence : null}
          />
        ))}
      </div>

      {showHeadline && (
        <div className="flex flex-col gap-1">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
            {view.disagree && <Badge variant="outline">Disagree</Badge>}
            <span className="text-sm text-muted">{view.reason}</span>
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

function Score({ channel, driving, note }: { channel: ChannelView; driving: boolean; note: string | null }) {
  const unavailable = channel.value == null;
  const sev = resolveSeverity(null, channel.band);
  return (
    <div className={cn("flex flex-col gap-2 rounded-lg border bg-surface px-4 py-3", driving ? "border-accent/60" : "border-line")}>
      <div className="flex items-baseline gap-2">
        <span className="text-xs font-medium text-muted">{channel.label}</span>
        {channel.band && <span className={cn("ml-auto font-mono text-xs uppercase tracking-wide2", sev.text)}>{channel.band}</span>}
      </div>
      <div className="flex items-baseline gap-1.5">
        <span className="font-mono text-3xl font-semibold leading-none text-foreground">{channel.text}</span>
        {!unavailable && <span className="font-mono text-xs text-subtle">/ 100</span>}
      </div>
      <Progress value={unavailable ? 0 : Math.max(0, Math.min(100, channel.value as number))} aria-label={`${channel.label} score`} />
      {note && <p className="font-mono text-xs text-subtle">{note}</p>}
    </div>
  );
}
