import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldCheck, ShieldAlert, Ban, ArrowRight, Beaker } from "lucide-react";
import { verifyTarget, type VerifyResponse } from "@/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const EXAMPLE = "http://127.0.0.1:8099/user?id=1";

export const VerifyPanel: React.FC = () => {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VerifyResponse | null>(null);

  const run = async (url: string) => {
    if (!url.trim() || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await verifyTarget(url.trim()));
    } catch (e: any) {
      setError(e.message || "Verification failed");
    } finally {
      setLoading(false);
    }
  };

  const confirmed = result?.probes.filter((p) => p.confirmed) ?? [];

  return (
    <div className="flex flex-col gap-4">
      <motion.section
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
        className="relative overflow-hidden rounded-xl border border-line bg-surface"
      >
        <div aria-hidden className="pointer-events-none absolute -right-10 -top-10 opacity-[0.06]">
          <ShieldCheck className="size-48" strokeWidth={0.5} />
        </div>

        <div className="relative p-6 md:p-8">
          <div className="mb-6 flex items-center gap-2">
            <ShieldCheck className="size-4 text-muted" />
            <span className="tf-eyebrow">Active Verification</span>
          </div>

          <h1 className="mb-1 text-2xl font-semibold tracking-tightest text-foreground md:text-3xl">
            Confirm it's real.
          </h1>
          <p className="mb-4 max-w-xl text-sm text-muted">
            Sends safe, non-destructive probes to a target to <em>confirm</em> a
            flagged injection point is actually exploitable — the difference
            between a hunch and a finding.
          </p>

          {/* Scope notice — this is the safety contract, surfaced plainly. */}
          <div className="mb-5 flex items-start gap-2.5 rounded-lg border border-line bg-surface-2 p-3">
            <Ban className="mt-0.5 size-4 shrink-0 text-muted" />
            <p className="text-xs text-muted">
              <span className="font-medium text-foreground">Localhost only.</span>{" "}
              Probing runs against <code className="font-mono">127.0.0.1</code> /{" "}
              <code className="font-mono">localhost</code> targets you control. Any
              other host is refused before a request is sent. Start the bundled lab
              with <code className="font-mono">python -m tools.vuln_lab</code>.
            </p>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              run(target);
            }}
          >
            <div className="flex flex-col gap-3 rounded-lg border border-line bg-background p-2 focus-within:border-line-strong focus-within:shadow-glow-sm sm:flex-row sm:items-center">
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={loading}
                spellCheck={false}
                autoComplete="off"
                placeholder="http://127.0.0.1:8099/search?q=test"
                className="w-full bg-transparent px-2 py-2 font-mono text-sm text-foreground placeholder:text-subtle outline-none disabled:opacity-60"
              />
              <Button type="submit" size="lg" disabled={loading || !target.trim()} className="w-full sm:w-auto">
                {loading ? "Probing" : <>Verify <ArrowRight className="size-4" /></>}
              </Button>
            </div>
          </form>
          <button
            type="button"
            disabled={loading}
            onClick={() => {
              setTarget(EXAMPLE);
              run(EXAMPLE);
            }}
            className="mt-3 inline-flex items-center gap-1.5 font-mono text-[11px] text-subtle underline-offset-4 hover:text-foreground hover:underline disabled:opacity-50"
          >
            <Beaker className="size-3" />
            try the local lab ({EXAMPLE})
          </button>
        </div>
      </motion.section>

      {error && (
        <Card className="flex items-start gap-3 border-line-strong p-5">
          <ShieldAlert className="size-4 shrink-0 text-foreground" />
          <div>
            <h3 className="text-sm font-semibold text-foreground">Verification failed</h3>
            <p className="mt-1 font-mono text-xs text-muted">{error}</p>
          </div>
        </Card>
      )}

      <AnimatePresence>
        {result && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
            {!result.authorized ? (
              <Card className="flex items-start gap-3 border-line-strong p-5">
                <Ban className="size-4 shrink-0 text-foreground" />
                <div>
                  <h3 className="text-sm font-semibold text-foreground">Out of scope — refused</h3>
                  <p className="mt-1 text-sm text-muted">{result.error || result.summary}</p>
                </div>
              </Card>
            ) : (
              <Card className="p-5">
                <div className="flex items-start gap-3">
                  <div
                    className={cn(
                      "flex size-9 shrink-0 items-center justify-center rounded-md border",
                      confirmed.length
                        ? "border-line-strong bg-foreground text-background"
                        : "border-line bg-surface-2"
                    )}
                  >
                    {confirmed.length ? <ShieldAlert className="size-4" /> : <ShieldCheck className="size-4 text-muted" />}
                  </div>
                  <div className="min-w-0">
                    <h3 className="text-sm font-semibold text-foreground">
                      {confirmed.length ? "Vulnerabilities confirmed" : "Nothing confirmed"}
                    </h3>
                    <p className="mt-1 text-sm text-muted">{result.summary}</p>
                  </div>
                </div>

                {result.probes.length > 0 && (
                  <div className="mt-4 flex flex-col divide-y divide-line">
                    {result.probes.map((p, i) => (
                      <div key={i} className="flex flex-wrap items-center gap-x-4 gap-y-2 py-3 first:pt-0">
                        <span
                          className={cn(
                            "inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide2",
                            p.confirmed
                              ? "bg-foreground font-semibold text-background"
                              : "border border-line text-subtle"
                          )}
                        >
                          {p.technique}
                        </span>
                        <Badge variant="subtle">param: {p.param}</Badge>
                        <span className="font-mono text-[11px] tabular-nums text-subtle">
                          {Math.round(p.confidence * 100)}%
                        </span>
                        <p className="min-w-0 flex-1 text-xs text-muted">{p.evidence}</p>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
