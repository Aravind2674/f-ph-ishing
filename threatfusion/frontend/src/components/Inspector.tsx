import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { SearchCode, ArrowRight, ShieldCheck, ShieldAlert, Radio } from "lucide-react";
import {
  analyzePayload,
  analyzeTraffic,
  type AnalyzeResponse,
  type TrafficAnalyzeResponse,
} from "@/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
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

/** Class label as a monochrome chip — filled = attack, hollow = benign. */
function ClassBadge({ label, attack }: { label: string; attack: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide2",
        attack
          ? "bg-foreground font-semibold text-background"
          : "border border-line text-subtle"
      )}
    >
      {label}
    </span>
  );
}

/** Render a value with its suspicious substring emphasised. */
function HighlightedValue({ value, span }: { value: string; span: string | null }) {
  if (!span || !value.toLowerCase().includes(span.toLowerCase())) {
    return <span className="break-all font-mono text-xs text-muted">{value}</span>;
  }
  const i = value.toLowerCase().indexOf(span.toLowerCase());
  return (
    <span className="break-all font-mono text-xs text-muted">
      {value.slice(0, i)}
      <mark className="rounded-sm bg-foreground/15 px-0.5 text-foreground ring-1 ring-foreground/30">
        {value.slice(i, i + span.length)}
      </mark>
      {value.slice(i + span.length)}
    </span>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1 w-14 overflow-hidden rounded-full bg-surface-2">
        <div className="h-full bg-foreground" style={{ width: `${Math.round(value * 100)}%` }} />
      </div>
      <span className="font-mono text-[11px] tabular-nums text-subtle">
        {Math.round(value * 100)}%
      </span>
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

  const runPayload = async (text: string) => {
    if (!text.trim() || loading) return;
    setLoading(true);
    reset();
    try {
      setPayloadResult(await analyzePayload(text.trim()));
    } catch (e: any) {
      setError(e.message || "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  const runTraffic = async (text: string) => {
    if (!text.trim() || loading) return;
    setLoading(true);
    reset();
    try {
      setTrafficResult(await analyzeTraffic(buildTrafficPayload(text)));
    } catch (e: any) {
      setError(e.message || "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      {/* ── Console ─────────────────────────────────────────────────────── */}
      <motion.section
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
        className="relative overflow-hidden rounded-xl border border-line bg-surface"
      >
        <div aria-hidden className="pointer-events-none absolute -right-10 -top-10 opacity-[0.06]">
          <SearchCode className="size-48" strokeWidth={0.5} />
        </div>

        <div className="relative p-6 md:p-8">
          <div className="mb-6 flex items-center gap-2">
            <SearchCode className="size-4 text-muted" />
            <span className="tf-eyebrow">Request Inspector</span>
          </div>

          <h1 className="mb-1 text-2xl font-semibold tracking-tightest text-foreground md:text-3xl">
            Read the request.
          </h1>
          <p className="mb-6 max-w-xl text-sm text-muted">
            A character-level neural network reads request contents and flags{" "}
            SQLi, XSS, path-traversal and command-injection — generalising past
            obfuscation a regex WAF would miss.
          </p>

          {/* Mode selector */}
          <div className="mb-4 inline-flex flex-wrap gap-1 rounded-lg border border-line bg-surface-2 p-1">
            {([
              { id: "payload", label: "Payload / URL" },
              { id: "traffic", label: "Captured Traffic" },
            ] as const).map((m) => (
              <button
                key={m.id}
                type="button"
                disabled={loading}
                onClick={() => {
                  setMode(m.id);
                  reset();
                }}
                className={cn(
                  "rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50",
                  mode === m.id
                    ? "bg-foreground text-background"
                    : "text-muted hover:bg-surface-3 hover:text-foreground"
                )}
              >
                {m.label}
              </button>
            ))}
          </div>

          {mode === "payload" ? (
            <>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  runPayload(payloadText);
                }}
              >
                <div className="flex flex-col gap-3 rounded-lg border border-line bg-background p-2 focus-within:border-line-strong focus-within:shadow-glow-sm sm:flex-row sm:items-center">
                  <input
                    value={payloadText}
                    onChange={(e) => setPayloadText(e.target.value)}
                    disabled={loading}
                    spellCheck={false}
                    autoComplete="off"
                    placeholder="Paste a parameter value, query string, or URL…"
                    className="w-full bg-transparent px-2 py-2 font-mono text-sm text-foreground placeholder:text-subtle outline-none disabled:opacity-60"
                  />
                  <Button type="submit" size="lg" disabled={loading || !payloadText.trim()} className="w-full sm:w-auto">
                    {loading ? "Analyzing" : <>Analyze <ArrowRight className="size-4" /></>}
                  </Button>
                </div>
              </form>
              <div className="mt-3 flex flex-wrap gap-1.5">
                <span className="mr-1 font-mono text-[10px] uppercase tracking-wide2 text-subtle">Try:</span>
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
            <>
              <form
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
                  placeholder={"Paste a HAR export (Burp / DevTools / ZAP), or one request per line:\nGET https://site/item?id=1' OR '1'='1\nPOST https://site/login"}
                  className="w-full rounded-lg border border-line bg-background p-3 font-mono text-xs text-foreground placeholder:text-subtle outline-none focus:border-line-strong focus:shadow-glow-sm disabled:opacity-60"
                />
                <div className="mt-3 flex items-center gap-3">
                  <Button type="submit" size="lg" disabled={loading || !trafficText.trim()}>
                    {loading ? "Analyzing" : <>Analyze Session <ArrowRight className="size-4" /></>}
                  </Button>
                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => {
                      setTrafficText(TRAFFIC_EXAMPLE);
                      runTraffic(TRAFFIC_EXAMPLE);
                    }}
                    className="font-mono text-[11px] text-subtle underline-offset-4 hover:text-foreground hover:underline disabled:opacity-50"
                  >
                    load example session
                  </button>
                </div>
              </form>
            </>
          )}
        </div>
      </motion.section>

      {/* ── Errors / model state ────────────────────────────────────────── */}
      {error && (
        <Card className="flex items-start gap-3 border-line-strong p-5">
          <ShieldAlert className="size-4 shrink-0 text-foreground" />
          <div>
            <h3 className="text-sm font-semibold text-foreground">Analysis failed</h3>
            <p className="mt-1 font-mono text-xs text-muted">{error}</p>
          </div>
        </Card>
      )}

      {payloadResult && !payloadResult.model_loaded && <ModelNotLoaded />}
      {trafficResult && !trafficResult.model_loaded && <ModelNotLoaded />}

      {/* ── Payload results ─────────────────────────────────────────────── */}
      <AnimatePresence>
        {payloadResult && payloadResult.model_loaded && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
            <Card className="p-5">
              <VerdictHeader
                attack={payloadResult.findings.some((f) => f.is_attack)}
                summary={payloadResult.summary}
              />
              <div className="mt-4 flex flex-col divide-y divide-line">
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
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Traffic results ─────────────────────────────────────────────── */}
      <AnimatePresence>
        {trafficResult && trafficResult.model_loaded && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
            <Card className="p-5">
              <div className="mb-4 flex items-center gap-2">
                <Radio className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">Captured Session</span>
                <Badge variant="subtle">
                  {trafficResult.flagged}/{trafficResult.analyzed} flagged
                </Badge>
              </div>
              <p className="mb-4 text-sm text-muted">{trafficResult.summary}</p>
              <div className="flex flex-col gap-2">
                {trafficResult.findings.map((r, i) => (
                  <div
                    key={i}
                    className={cn(
                      "rounded-lg border p-3",
                      r.is_attack ? "border-line-strong bg-surface-2/60" : "border-line"
                    )}
                  >
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
                        <span className="font-mono text-[10px] uppercase tracking-wide2 text-subtle">
                          {r.worst_location}
                        </span>{" "}
                        <HighlightedValue
                          value={
                            r.details.find((d) => d.location === r.worst_location)?.value ?? ""
                          }
                          span={r.suspicious_span}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {!payloadResult && !trafficResult && !error && <IdleInspector />}
    </div>
  );
};

function VerdictHeader({ attack, summary }: { attack: boolean; summary: string }) {
  return (
    <div className="flex items-start gap-3">
      <div
        className={cn(
          "flex size-9 shrink-0 items-center justify-center rounded-md border",
          attack ? "border-line-strong bg-foreground text-background" : "border-line bg-surface-2"
        )}
      >
        {attack ? <ShieldAlert className="size-4" /> : <ShieldCheck className="size-4 text-muted" />}
      </div>
      <div>
        <h3 className="text-sm font-semibold text-foreground">
          {attack ? "Injection detected" : "No injection detected"}
        </h3>
        <p className="mt-1 text-sm text-muted">{summary}</p>
      </div>
    </div>
  );
}

function ModelNotLoaded() {
  return (
    <Card className="flex items-start gap-3 border-line-strong p-5">
      <ShieldAlert className="size-4 shrink-0 text-foreground" />
      <div>
        <h3 className="text-sm font-semibold text-foreground">Classifier not loaded</h3>
        <p className="mt-1 font-mono text-xs text-muted">
          Train it with <code>python -m ml.train_vuln</code> so the backend can load
          <code> ml/models/vuln_classifier.pt</code>.
        </p>
      </div>
    </Card>
  );
}

function IdleInspector() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.1 }}
      className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-line py-16 text-center"
    >
      <SearchCode className="size-8 text-subtle/50" strokeWidth={1} />
      <p className="max-w-sm text-xs text-subtle">
        Submit a payload or a captured session — the neural classifier will read every
        value and flag injection attempts.
      </p>
    </motion.div>
  );
}
