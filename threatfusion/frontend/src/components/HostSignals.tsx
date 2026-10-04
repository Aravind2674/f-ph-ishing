/**
 * HostSignals — the evidence cards behind the host features (A1-7): the TLS certificate, the registration record
 * (real domain age), DNS, and the technology stack with end-of-life status.
 *
 * Each card carries its own source chip. If that source did not answer the card says *unavailable* and why — an
 * empty card is never drawn as a clean one.
 */
import { CalendarClock, Globe, Layers, Lock } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SourceChip } from "@/components/SourceChip";
import { dnsView, registrationView, sortTechs, tlsView, type CardView } from "@/lib/hostsignals";
import type { ChipState } from "@/lib/evidence";
import type { ProviderOutcome, ScanResult } from "@/api";

function outcomeFor(outcomes: ProviderOutcome[] | undefined, source: string): ProviderOutcome | undefined {
  return outcomes?.find((o) => o.source === source);
}

function CardShell({
  icon,
  title,
  outcome,
  source,
  view,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  outcome: ProviderOutcome | undefined;
  source: string;
  view?: CardView | null;
  children?: React.ReactNode;
}) {
  return (
    <Card className="flex flex-col gap-3 p-5">
      <div className="flex flex-wrap items-center gap-2">
        {icon}
        <span className="text-sm font-semibold text-foreground">{title}</span>
        {outcome && (
          <SourceChip
            source={source}
            state={outcome.status as ChipState}
            reason={outcome.reason}
            retryAfter={outcome.retry_after}
            cached={outcome.cached}
            mock={outcome.mock}
            latencyMs={outcome.latency_ms}
            showReason={false}
            className="ml-auto"
          />
        )}
      </div>
      {view ? (
        <>
          <p className="text-sm text-foreground">
            <span className="mr-2 font-mono text-[10px] uppercase tracking-wide2 text-subtle">
              {view.ok === true ? "good" : view.ok === false ? "attention" : "info"}
            </span>
            {view.headline}
          </p>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 font-mono text-[11px]">
            {view.facts.map((f) => (
              <div key={f.label} className="contents">
                <dt className="text-subtle">{f.label}</dt>
                <dd className={cn("break-words text-muted", f.flag && "font-semibold text-foreground")}>{f.value}</dd>
              </div>
            ))}
          </dl>
          {children}
        </>
      ) : (
        <p className="text-xs text-subtle">
          Unavailable — {outcome ? "see the source status above" : "this source was not queried for this target"}. Unknown is not
          the same as fine.
        </p>
      )}
    </Card>
  );
}

export function HostSignals({ result }: { result: ScanResult }) {
  const outcomes = result.provider_results;
  // Only for targets that have a host (domain / URL): an IP or a hash has no certificate, registrar or DNS zone.
  const applicable = ["tls", "rdap", "dns"].some((s) => outcomeFor(outcomes, s)) || result.tls || result.rdap || result.dns;
  const techOutcome = outcomeFor(outcomes, "tech_fingerprint");
  const eolOutcome = outcomeFor(outcomes, "endoflife");
  const techs = result.tech_fingerprint ? sortTechs(result.tech_fingerprint.technologies) : [];
  if (!applicable && !techOutcome) return null;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <CardShell icon={<Lock className="size-4 text-muted" />} title="TLS certificate" source="tls"
        outcome={outcomeFor(outcomes, "tls")} view={tlsView(result.tls)} />
      <CardShell icon={<CalendarClock className="size-4 text-muted" />} title="Registration" source="rdap"
        outcome={outcomeFor(outcomes, "rdap")} view={registrationView(result.rdap)} />
      <CardShell icon={<Globe className="size-4 text-muted" />} title="DNS & hosting" source="dns"
        outcome={outcomeFor(outcomes, "dns")} view={dnsView(result.dns)} />

      <Card className="flex flex-col gap-3 p-5">
        <div className="flex flex-wrap items-center gap-2">
          <Layers className="size-4 text-muted" />
          <span className="text-sm font-semibold text-foreground">Technology &amp; end-of-life</span>
          <span className="ml-auto flex flex-wrap gap-1.5">
            {techOutcome && (
              <SourceChip source="tech_fingerprint" state={techOutcome.status as ChipState} reason={techOutcome.reason}
                latencyMs={techOutcome.latency_ms} cached={techOutcome.cached} mock={techOutcome.mock} showReason={false} />
            )}
            {eolOutcome && (
              <SourceChip source="endoflife" state={eolOutcome.status as ChipState} reason={eolOutcome.reason}
                retryAfter={eolOutcome.retry_after} cached={eolOutcome.cached} mock={eolOutcome.mock} showReason={false} />
            )}
          </span>
        </div>
        {techs.length ? (
          <ul className="flex flex-col gap-1.5">
            {techs.map((t) => (
              <li key={t.name} className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px]">
                <span className={cn("text-foreground", t.badge === "end-of-life" && "font-semibold")}>
                  {t.name}
                  {t.version ? ` ${t.version}` : ""}
                </span>
                <Badge variant={t.badge === "end-of-life" ? "solid" : "outline"}>{t.badge}</Badge>
                <span className="text-subtle">
                  {t.text} · {t.confidence}% confidence{t.implied ? " · inferred" : ""}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-subtle">
            {result.tech_fingerprint
              ? "No technologies were detected on the page."
              : "Unavailable — the technology fingerprint did not answer. Unknown is not the same as fine."}
          </p>
        )}
        {result.tech_fingerprint && techs.some((t) => t.version && t.badge === "unknown") && !eolOutcome && (
          <p className="text-xs text-subtle">
            Lifecycle is only checked for products that endoflife.date tracks; the rest stay unknown.
          </p>
        )}
      </Card>
    </div>
  );
}
