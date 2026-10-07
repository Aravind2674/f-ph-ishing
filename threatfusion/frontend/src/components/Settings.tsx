import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  Radar,
  Bug,
  Boxes,
  Eye,
  EyeOff,
  type LucideIcon,
} from "lucide-react";
import { deleteNetworkData, fetchHealth, getApiToken, setApiToken, type ProviderHealth } from "@/api";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { InterfacePicker } from "@/components/InterfacePicker";

/*
 * Settings — grouped by ingestion source. This is a presentation-layer surface:
 * the backend owns the real configuration via environment variables, so the
 * inputs here are local-only and never leave the browser.
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

function ApiTokenCard() {
  const [value, setValue] = useState("");
  const [saved, setSaved] = useState(() => getApiToken() !== "");
  const [reveal, setReveal] = useState(false);

  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-foreground">API token</span>
            <Badge variant={saved ? "solid" : "outline"}>{saved ? "Set" : "Not set"}</Badge>
          </div>
          <p className="mt-1 max-w-md text-xs text-muted">
            The backend requires a Bearer token on every request except /health. It is generated on first
            start and stored outside the repository. Print it with{" "}
            <code className="font-mono text-foreground">python -m app.core.auth</code> and paste it here. It
            is kept in this browser only.
          </p>
        </div>
      </div>
      <div className="mt-4 flex w-full items-center gap-2 sm:max-w-md">
        <div className="relative flex-1">
          <Input
            type={reveal ? "text" : "password"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={saved ? "•••••••• (saved)" : "Paste token"}
            className="pr-9 font-mono text-xs"
            autoComplete="off"
          />
          <button
            type="button"
            onClick={() => setReveal((r) => !r)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-subtle hover:text-foreground"
            aria-label={reveal ? "Hide token" : "Reveal token"}
          >
            {reveal ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
          </button>
        </div>
        <Button
          variant="subtle"
          size="sm"
          disabled={!value.trim()}
          onClick={() => {
            setApiToken(value);
            setSaved(true);
            setValue("");
          }}
        >
          Save
        </Button>
        {saved && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setApiToken("");
              setSaved(false);
            }}
          >
            Clear
          </Button>
        )}
      </div>
    </Card>
  );
}

function PrivacyCard() {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const erase = async () => {
    if (!window.confirm("Erase ALL stored network data (devices, per-device domain history, alerts)? This cannot be undone.")) return;
    setBusy(true);
    setMsg(null);
    try {
      const c = await deleteNetworkData();
      setMsg(`Erased ${c.devices ?? 0} device(s), ${c.domains ?? 0} domain record(s), ${c.alerts ?? 0} alert(s).`);
    } catch (e: any) {
      setMsg(e.message || "Could not erase network data");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="p-5">
      <span className="text-sm font-semibold text-foreground">Data &amp; privacy</span>
      <ul className="mt-2 flex max-w-xl list-disc flex-col gap-1 pl-4 text-xs text-muted">
        <li>
          Private, local and reverse-DNS names (<code className="font-mono">printer.local</code>, …) and private IPs are
          never sent to third-party services.
        </li>
        <li>
          URL scans send only <code className="font-mono">scheme://host/path</code> unless you tick “send full URL”.
        </li>
        <li>
          Network monitoring keeps per-device domain history for{" "}
          <code className="font-mono">NETWORK_RETENTION_DAYS</code> (default 30), then deletes it automatically.
        </li>
      </ul>
      <div className="mt-4 flex items-center gap-3">
        <Button variant="outline" size="sm" disabled={busy} onClick={erase}>
          {busy ? "Erasing…" : "Erase all network data"}
        </Button>
        {msg && <span className="font-mono text-[11px] text-subtle">{msg}</span>}
      </div>
    </Card>
  );
}

function stateLabel(p?: ProviderHealth): { text: string; variant: "solid" | "subtle" | "outline" } | null {
  if (!p) return null;
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
  const [providers, setProviders] = useState<Record<string, ProviderHealth>>({});

  useEffect(() => {
    fetchHealth()
      .then((h) => setProviders(h.providers ?? {}))
      .catch(() => setProviders({}));
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

      <ApiTokenCard />

      <InterfacePicker />

      <PrivacyCard />

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
