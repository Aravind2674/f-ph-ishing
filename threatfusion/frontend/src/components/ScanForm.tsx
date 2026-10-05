import React, { useState } from "react";
import { motion } from "framer-motion";
import { Globe, Server, Link2, Hash, Crosshair, ArrowRight } from "lucide-react";
import type { ScanRequest } from "@/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

interface ScanFormProps {
  onSubmit: (req: ScanRequest) => void;
  loading: boolean;
}

type TargetType = ScanRequest["target_type"];

// Target-type registry drives the segmented selector, the input placeholder and
// the little inline "syntax" hint so target entry feels like a real console.
const TARGET_TYPES: {
  id: TargetType;
  label: string;
  icon: typeof Globe;
  placeholder: string;
  hint: string;
}[] = [
  { id: "domain", label: "Domain", icon: Globe, placeholder: "evil.example.com", hint: "FQDN" },
  { id: "ip", label: "IP", icon: Server, placeholder: "185.220.101.47", hint: "IPv4 / IPv6" },
  { id: "url", label: "URL", icon: Link2, placeholder: "https://example.com/login", hint: "Absolute URL" },
  { id: "file_hash", label: "Hash", icon: Hash, placeholder: "44d88612fea8a8f36de82e1278abb02f", hint: "MD5 / SHA-1 / SHA-256" },
];

export const ScanForm: React.FC<ScanFormProps> = ({ onSubmit, loading }) => {
  const [target, setTarget] = useState("");
  const [type, setType] = useState<TargetType>("domain");
  const [fullUrl, setFullUrl] = useState(false);

  const active = TARGET_TYPES.find((t) => t.id === type)!;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim() || loading) return;
    onSubmit({
      target: target.trim(),
      target_type: type,
      ...(type === "url" && fullUrl ? { send_full_url: true } : {}),
    });
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="relative overflow-hidden rounded-xl border border-line bg-surface"
    >
      {/* Faint crosshair motif in the corner — reinforces "targeting console". */}
      <div
        aria-hidden
        className="pointer-events-none absolute -right-10 -top-10 opacity-[0.06]"
      >
        <Crosshair className="size-48" strokeWidth={0.5} />
      </div>

      {/* Scan-line sweep while a scan is in flight (replaces a spinner). */}
      {loading && (
        <div className="pointer-events-none absolute inset-x-0 top-0 h-24 overflow-hidden">
          <div className="tf-scanline absolute inset-x-0 h-16 animate-scan" />
        </div>
      )}

      <div className="relative p-6 md:p-8">
        <div className="mb-6 flex items-center gap-2">
          <Crosshair className="size-4 text-muted" />
          <span className="tf-eyebrow">New Scan</span>
        </div>

        <h1 className="mb-1 text-2xl font-semibold tracking-tightest text-foreground md:text-3xl">
          Scan a target for vulnerabilities.
        </h1>
        <p className="mb-6 max-w-xl text-sm text-muted">
          Enter a domain, IP, URL, or hash to analyze its security risk.
        </p>

        {/* Target-type segmented selector. */}
        <div className="mb-3 inline-flex flex-wrap gap-1 rounded-lg border border-line bg-surface-2 p-1">
          {TARGET_TYPES.map((t) => {
            const Icon = t.icon;
            const isActive = t.id === type;
            return (
              <button
                key={t.id}
                type="button"
                disabled={loading}
                onClick={() => setType(t.id)}
                className={cn(
                  "flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50",
                  isActive
                    ? "bg-foreground text-background"
                    : "text-muted hover:bg-surface-3 hover:text-foreground"
                )}
              >
                <Icon className="size-3.5" />
                {t.label}
              </button>
            );
          })}
        </div>

        <form onSubmit={handleSubmit}>
          <div
            className={cn(
              "group flex flex-col gap-3 rounded-lg border bg-background p-2 transition-colors sm:flex-row sm:items-center",
              "border-line focus-within:border-line-strong focus-within:shadow-glow-sm"
            )}
          >
            <div className="flex flex-1 items-center gap-3 pl-2">
              <active.icon className="size-4 shrink-0 text-subtle" />
              <input
                id="tf-target-input"
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={loading}
                spellCheck={false}
                autoComplete="off"
                placeholder={active.placeholder}
                className="w-full bg-transparent py-2 font-mono text-sm text-foreground placeholder:text-subtle outline-none disabled:opacity-60"
              />
              <span className="hidden shrink-0 font-mono text-[10px] uppercase tracking-wide2 text-subtle sm:inline">
                {active.hint}
              </span>
            </div>
            <Button
              type="submit"
              size="lg"
              disabled={loading || !target.trim()}
              className="w-full sm:w-auto"
            >
              {loading ? (
                <>
                  {/* Pulse dots instead of a spinner — matches the designed loading language. */}
                  <span className="flex items-center gap-1" aria-hidden>
                    <span className="size-1 animate-pulse rounded-full bg-background" />
                    <span className="size-1 animate-pulse rounded-full bg-background [animation-delay:120ms]" />
                    <span className="size-1 animate-pulse rounded-full bg-background [animation-delay:240ms]" />
                  </span>
                  Scanning
                </>
              ) : (
                <>
                  Run Scan
                  <ArrowRight className="size-4" />
                </>
              )}
            </Button>
          </div>
          {type === "url" && (
            <label className="mt-3 flex cursor-pointer items-start gap-2 text-xs text-muted">
              <input
                type="checkbox"
                checked={fullUrl}
                onChange={(e) => setFullUrl(e.target.checked)}
                className="mt-0.5 size-3.5 accent-foreground"
              />
              <span>
                Send the <strong className="text-foreground">full URL</strong> (query string &amp; fragment) to
                analysers. Off by default: only <code className="font-mono">scheme://host/path</code> leaves this
                machine, because query strings often carry session tokens and personal data.
              </span>
            </label>
          )}
        </form>
      </div>
    </motion.section>
  );
};
