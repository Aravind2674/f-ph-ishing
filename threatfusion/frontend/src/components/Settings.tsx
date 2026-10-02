import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  Radar,
  Bug,
  Boxes,
  Eye,
  EyeOff,
  Info,
  type LucideIcon,
} from "lucide-react";
import { fetchHealth, type ProviderHealth } from "@/api";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";

/*
 * Settings — grouped by ingestion source. This is a presentation-layer surface:
 * the backend owns the real configuration via environment variables, so the
 * inputs here are local-only and never leave the browser. The mock/live toggle
 * *reflects* the backend's reported mode (GET /health) and clearly states that
 * switching to live requires a backend restart with USE_MOCK_DATA=false.
 */

interface Source {
  id: string;
  name: string;
  icon: LucideIcon;
  env: string;
  desc: string;
  keyless?: boolean;
  // Name of this source in GET /health -> providers
  provider: string;
}

const SOURCES: Source[] = [
  {
    id: "virustotal",
    name: "VirusTotal",
    icon: ShieldCheck,
    env: "VIRUSTOTAL_API_KEY",
    provider: "virustotal",
    desc: "File & URL reputation, AV engine detections. Needs a key; without one it is skipped.",
  },
  {
    id: "shodan",
    name: "Shodan",
    icon: Radar,
    env: "SHODAN_API_KEY",
    provider: "shodan_internetdb",
    desc: "Host exposure, open ports, service CPEs. InternetDB works without a key.",
  },
  {
    id: "cve",
    name: "CVE / NVD",
    icon: Bug,
    env: "NVD_API_KEY",
    provider: "nvd",
    desc: "Vulnerability severity enrichment. Needs a key; without one CVE enrichment is skipped (and reported as not configured).",
  },
  {
    id: "tech",
    name: "Tech Fingerprint",
    icon: Boxes,
    env: "—",
    provider: "tech_fingerprint",
    desc: "Local Wappalyzer-style detection. Runs entirely on the backend.",
    keyless: true,
  },
];

function stateLabel(p?: ProviderHealth): { text: string; variant: "solid" | "subtle" | "outline" } | null {
  if (!p) return null;
  if (p.mock) return { text: "Mock", variant: "subtle" };
  if (p.configured) return { text: p.state === "keyless" ? "Keyless" : "Configured", variant: "solid" };
  return { text: p.state === "placeholder" ? "Not configured · placeholder" : "Not configured", variant: "outline" };
}

function SourceRow({ source, provider }: { source: Source; provider?: ProviderHealth }) {
  const [value, setValue] = useState("");
  const [reveal, setReveal] = useState(false);
  const Icon = source.icon;

  return (
    <div className="flex flex-col gap-4 p-5 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex items-start gap-3">
        <div className="flex size-9 shrink-0 items-center justify-center rounded-md border border-line bg-surface-2">
          <Icon className="size-4 text-foreground" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-foreground">
              {source.name}
            </span>
            {source.keyless ? (
              <Badge variant="subtle">Local</Badge>
            ) : (
              <span className="font-mono text-[10px] text-subtle">
                {source.env}
              </span>
            )}
            {!source.keyless && stateLabel(provider) && (
              <Badge variant={stateLabel(provider)!.variant}>{stateLabel(provider)!.text}</Badge>
            )}
          </div>
          <p className="mt-0.5 max-w-sm text-xs text-subtle">{source.desc}</p>
        </div>
      </div>

      {!source.keyless && (
        <div className="flex w-full items-center gap-2 sm:w-auto sm:max-w-xs">
          <div className="relative flex-1">
            <Input
              type={reveal ? "text" : "password"}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="Not set"
              className="pr-9 font-mono text-xs"
            />
            <button
              type="button"
              onClick={() => setReveal((r) => !r)}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-subtle hover:text-foreground"
              aria-label={reveal ? "Hide key" : "Reveal key"}
            >
              {reveal ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
            </button>
          </div>
          <Button variant="subtle" size="sm" disabled={!value.trim()}>
            Save
          </Button>
        </div>
      )}
    </div>
  );
}

export const Settings: React.FC = () => {
  const [mock, setMock] = useState(true);
  const [dirty, setDirty] = useState(false);
  const [known, setKnown] = useState(false);
  const [providers, setProviders] = useState<Record<string, ProviderHealth>>({});

  // Seed the toggle (and per-provider readiness) from the backend's reported state.
  useEffect(() => {
    fetchHealth()
      .then((h) => {
        setMock(h.mock_mode);
        setProviders(h.providers ?? {});
        setKnown(true);
      })
      .catch(() => setKnown(false));
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="mx-auto flex w-full max-w-3xl flex-col gap-5"
    >
      <div>
        <h2 className="text-xl font-semibold tracking-tight text-foreground">
          Settings
        </h2>
        <p className="mt-1 text-sm text-muted">
          Data mode and ingestion sources.
        </p>
      </div>

      {/* Prominent mock/live mode toggle. */}
      <Card interactive className="p-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-foreground">
                Data Mode
              </span>
              <Badge variant={mock ? "subtle" : "solid"}>
                {mock ? "Mock" : "Live"}
              </Badge>
            </div>
            <p className="mt-1 max-w-md text-xs text-muted">
              {mock
                ? "Serving synthetic data so the demo runs without API keys."
                : "Serving live intelligence from configured sources."}
            </p>
          </div>
          <div className="flex flex-col items-end gap-1">
            <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wide2 text-subtle">
              <span className={cn(mock && "text-foreground")}>Mock</span>
              <Switch
                checked={!mock}
                onCheckedChange={(on) => {
                  setMock(!on);
                  setDirty(true);
                }}
                aria-label="Toggle live data mode"
              />
              <span className={cn(!mock && "text-foreground")}>Live</span>
            </div>
          </div>
        </div>

        {/* Honest note: the switch is UI-only; the backend owns the real mode. */}
        {(dirty || !known) && (
          <div className="mt-4 flex items-start gap-2 rounded-md border border-line bg-surface-2 p-3 text-xs text-muted">
            <Info className="mt-0.5 size-3.5 shrink-0 text-subtle" />
            <span>
              This toggle reflects the backend's <code className="font-mono text-foreground">USE_MOCK_DATA</code>{" "}
              setting. To change it, update <code className="font-mono text-foreground">backend/.env</code> and restart the API — it can't be flipped at runtime from the browser.
            </span>
          </div>
        )}
      </Card>

      {/* Ingestion sources, grouped. */}
      <Card>
        <div className="border-b border-line p-5">
          <span className="text-sm font-semibold text-foreground">
            Ingestion Sources
          </span>
          <p className="mt-0.5 text-xs text-subtle">
            Keys entered here stay in your browser; the backend reads its own from{" "}
            <code className="font-mono text-muted">.env</code>.
          </p>
        </div>
        <div className="divide-y divide-line">
          {SOURCES.map((s) => (
            <SourceRow key={s.id} source={s} provider={providers[s.provider]} />
          ))}
        </div>
      </Card>
    </motion.div>
  );
};
