import React, { useEffect, useState } from "react";
import type { ScanRequest } from "@/api";
import { cn } from "@/lib/utils";
import { parsePrefill } from "@/lib/prefill";
import { Button } from "@/components/ui/button";

interface ScanFormProps {
  onSubmit: (req: ScanRequest) => void;
  loading: boolean;
}

type TargetType = ScanRequest["target_type"];

const TARGET_TYPES: { id: TargetType; label: string; placeholder: string }[] = [
  { id: "domain", label: "Domain", placeholder: "evil.example.com" },
  { id: "ip", label: "IP", placeholder: "185.220.101.47" },
  { id: "url", label: "URL", placeholder: "https://example.com/login" },
  { id: "file_hash", label: "Hash", placeholder: "44d88612fea8a8f36de82e1278abb02f" },
];

export const ScanForm: React.FC<ScanFormProps> = ({ onSubmit, loading }) => {
  // The extension's "Open in ThreatFusion" link pre-fills the form and is then removed from the address bar. It never submits.
  const [prefill] = useState(() => parsePrefill(window.location.search));
  useEffect(() => {
    if (prefill) window.history.replaceState(null, "", window.location.pathname);
  }, [prefill]);
  const [target, setTarget] = useState(prefill?.target ?? "");
  const [type, setType] = useState<TargetType>(prefill?.type ?? "domain");
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
    <form onSubmit={handleSubmit} className="flex flex-col gap-3">
      <div role="radiogroup" aria-label="Target type" className="inline-flex w-fit flex-wrap gap-1 rounded-md border border-line bg-surface p-1">
        {TARGET_TYPES.map((t) => (
          <button
            key={t.id}
            type="button"
            role="radio"
            aria-checked={t.id === type}
            disabled={loading}
            onClick={() => setType(t.id)}
            className={cn(
              "rounded px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50",
              t.id === type ? "bg-surface-3 text-foreground" : "text-muted hover:text-foreground",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="flex gap-2">
        <input
          id="tf-target-input"
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={loading}
          spellCheck={false}
          autoComplete="off"
          aria-label="Target"
          placeholder={active.placeholder}
          className="h-11 min-w-0 flex-1 rounded-md border border-line-strong bg-surface px-3 font-mono text-sm text-foreground placeholder:text-subtle disabled:opacity-60"
        />
        <Button type="submit" size="lg" disabled={loading || !target.trim()}>
          {loading ? "Scanning…" : "Scan"}
        </Button>
      </div>

      {type === "url" && (
        <label className="flex cursor-pointer items-center gap-2 text-xs text-muted">
          <input type="checkbox" checked={fullUrl} onChange={(e) => setFullUrl(e.target.checked)} className="size-3.5 accent-accent" />
          Send full URL (query and fragment leave this machine)
        </label>
      )}
    </form>
  );
};
