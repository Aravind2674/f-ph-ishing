import React, { useState } from "react";
import { analyzePayload, analyzeTraffic, type AnalyzeResponse, type TrafficAnalyzeResponse } from "@/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

type Mode = "payload" | "traffic";

const PAYLOAD_EXAMPLES = [
  "id=1' OR '1'='1",
  "q=<script>alert(document.cookie)</script>",
  "https://x.com/p?file=../../../../etc/passwd",
  "city=Barcelona&country=Spain",
];

const TRAFFIC_EXAMPLE = [
  "GET https://shop.test/search?q=laptop&sort=price",
  "GET https://shop.test/item?id=1%27%20UNION%20SELECT%20password%20FROM%20users--",
  "GET https://shop.test/files?path=../../../../etc/passwd",
  "GET https://shop.test/about",
].join("\n");

/** Filled = attack, outlined = benign. */
function ClassBadge({ label, attack }: { label: string; attack: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide2",
        attack ? "bg-danger font-semibold text-background" : "border border-line text-subtle",
      )}
    >
      {label}
    </span>
  );
}

/** A value with its suspicious substring marked. */
function HighlightedValue({ value, span }: { value: string; span: string | null }) {
  const i = span ? value.toLowerCase().indexOf(span.toLowerCase()) : -1;
  if (!span || i < 0) return <span className="break-all font-mono text-xs text-muted">{value}</span>;
  return (
    <span className="break-all font-mono text-xs text-muted">
      {value.slice(0, i)}
      <mark className="rounded-sm bg-accent/20 px-0.5 text-foreground ring-1 ring-accent/50">{value.slice(i, i + span.length)}</mark>
      {value.slice(i + span.length)}
    </span>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1 w-14 overflow-hidden rounded-full bg-surface-2">
        <div className="h-full bg-accent" style={{ width: `${Math.round(value * 100)}%` }} />
      </div>
      <span className="font-mono text-[11px] text-subtle">{Math.round(value * 100)} %</span>
    </div>
  );
}

function buildTrafficPayload(text: string): { requests?: unknown[]; har?: unknown } {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) {
    try {
      const obj = JSON.parse(trimmed);
      if (obj?.log?.entries) return { har: obj };
    } catch {
      /* not JSON — fall through to line parsing */
    }
  }
  const requests = trimmed
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split(/\s+/);
      if (parts.length >= 2 && /^[A-Z]+$/.test(parts[0])) {
        return { method: parts[0], url: parts.slice(1).join(" "), headers: {} };
      }
      return { method: "GET", url: line, headers: {} };
    });
  return { requests };
}

export const Inspector: React.FC = () => {
  const [mode, setMode] = useState<Mode>("payload");
  const [payloadText, setPayloadText] = useState("");
  const [trafficText, setTrafficText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [payloadResult, setPayloadResult] = useState<AnalyzeResponse | null>(null);
  const [trafficResult, setTrafficResult] = useState<TrafficAnalyzeResponse | null>(null);

  const reset = () => {
    setError(null);
    setPayloadResult(null);
    setTrafficResult(null);
  };

  const run = async (text: string, go: () => Promise<void>) => {
    if (!text.trim() || loading) return;
    setLoading(true);
    reset();
    try {
      await go();
    } catch (e: any) {
      setError(e.message || "Analysis failed");
    } finally {
      setLoading(false);
    }
  };
  const runPayload = (text: string) => run(text, async () => setPayloadResult(await analyzePayload(text.trim())));
  const runTraffic = (text: string) => run(text, async () => setTrafficResult(await analyzeTraffic(buildTrafficPayload(text))));

  const notLoaded = (payloadResult && !payloadResult.model_loaded) || (trafficResult && !trafficResult.model_loaded);

  return (
    <div className="flex flex-col gap-4">
      <div role="radiogroup" aria-label="Input" className="inline-flex w-fit gap-1 rounded-md border border-line bg-background p-1">
        {([{ id: "payload", label: "Payload" }, { id: "traffic", label: "Traffic" }] as const).map((m) => (
          <button
            key={m.id}
            type="button"
            role="radio"
            aria-checked={mode === m.id}
            disabled={loading}
            onClick={() => {
              setMode(m.id);
              reset();
            }}
            className={cn("rounded px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50", mode === m.id ? "bg-surface-3 text-foreground" : "text-muted hover:text-foreground")}
          >
            {m.label}
          </button>
        ))}
      </div>

      {mode === "payload" ? (
        <>
          <form
            className="flex flex-col gap-2 sm:flex-row"
            onSubmit={(e) => {
              e.preventDefault();
              runPayload(payloadText);
            }}
          >
            <input
              value={payloadText}
              onChange={(e) => setPayloadText(e.target.value)}
              disabled={loading}
              spellCheck={false}
              autoComplete="off"
              aria-label="Payload"
              placeholder="Parameter, query string or URL"
              className="h-11 min-w-0 flex-1 rounded-md border border-line-strong bg-background px-3 font-mono text-sm text-foreground placeholder:text-subtle disabled:opacity-60"
            />
            <Button type="submit" size="lg" disabled={loading || !payloadText.trim()} className="w-full sm:w-auto">
              {loading ? "Analyzing…" : "Analyze"}
            </Button>
          </form>
          <div className="flex flex-wrap gap-1.5">
            {PAYLOAD_EXAMPLES.map((ex) => (
              <button
                key={ex}
                type="button"
                disabled={loading}
                onClick={() => {
                  setPayloadText(ex);
                  runPayload(ex);
                }}
                className="max-w-full truncate rounded border border-line bg-surface-2 px-2 py-1 font-mono text-[11px] text-muted transition-colors hover:border-line-strong hover:text-foreground disabled:opacity-50"
              >
                {ex}
              </button>
            ))}
          </div>
        </>
      ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            runTraffic(trafficText);
          }}
        >
          <textarea
            value={trafficText}
            onChange={(e) => setTrafficText(e.target.value)}
            disabled={loading}
            spellCheck={false}
            rows={6}
            aria-label="Traffic"
            placeholder={"HAR export, or one request per line:\nGET https://site/item?id=1' OR '1'='1"}
            className="w-full rounded-md border border-line-strong bg-background p-3 font-mono text-xs text-foreground placeholder:text-subtle disabled:opacity-60"
          />
          <div className="flex items-center gap-3">
            <Button type="submit" size="lg" disabled={loading || !trafficText.trim()}>
              {loading ? "Analyzing…" : "Analyze"}
            </Button>
            <button
              type="button"
              disabled={loading}
              onClick={() => {
                setTrafficText(TRAFFIC_EXAMPLE);
                runTraffic(TRAFFIC_EXAMPLE);
              }}
              className="font-mono text-xs text-subtle underline-offset-4 hover:text-foreground hover:underline disabled:opacity-50"
            >
              Example
            </button>
          </div>
        </form>
      )}

      {error && (
        <p role="alert" className="text-sm text-danger">
          Analysis failed — {error}
        </p>
      )}
      {notLoaded && (
        <p role="alert" className="text-sm text-danger">
          Classifier not loaded — run <code className="font-mono">python -m ml.train_vuln</code>
        </p>
      )}

      {payloadResult?.model_loaded && (
        <div className="flex flex-col gap-3">
          <VerdictLine attack={payloadResult.findings.some((f) => f.is_attack)} summary={payloadResult.summary} />
          <div className="flex flex-col divide-y divide-line">
            {payloadResult.findings.map((f, i) => (
              <div key={i} className="flex flex-wrap items-center gap-x-4 gap-y-2 py-3 first:pt-0">
                <Badge variant="subtle">{f.location}</Badge>
                <ClassBadge label={f.label} attack={f.is_attack} />
                <ConfidenceBar value={f.confidence} />
                <div className="min-w-0 flex-1">
                  <HighlightedValue value={f.input} span={f.suspicious_span} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {trafficResult?.model_loaded && (
        <div className="flex flex-col gap-3">
          <VerdictLine attack={trafficResult.flagged > 0} summary={`${trafficResult.flagged} of ${trafficResult.analyzed} flagged — ${trafficResult.summary}`} />
          <div className="flex flex-col gap-2">
            {trafficResult.findings.map((r, i) => (
              <div key={i} className={cn("rounded-md border p-3", r.is_attack ? "border-danger/60 bg-surface-2/60" : "border-line")}>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                  <Badge variant="outline">{r.method}</Badge>
                  <ClassBadge label={r.worst_label} attack={r.is_attack} />
                  {r.is_attack && <ConfidenceBar value={r.worst_confidence} />}
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted" title={r.url}>
                    {r.url}
                  </span>
                </div>
                {r.is_attack && (
                  <div className="mt-2 border-t border-line pt-2 text-xs">
                    <span className="font-mono text-[10px] uppercase tracking-wide2 text-subtle">{r.worst_location}</span>{" "}
                    <HighlightedValue value={r.details.find((d) => d.location === r.worst_location)?.value ?? ""} span={r.suspicious_span} />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

function VerdictLine({ attack, summary }: { attack: boolean; summary: string }) {
  return (
    <p className="text-sm">
      <span className={cn("mr-2 font-semibold", attack ? "text-danger" : "text-ok")}>{attack ? "Injection detected" : "No injection detected"}</span>
      <span className="text-muted">{summary}</span>
    </p>
  );
}
