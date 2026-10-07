import React, { useEffect, useState } from "react";
import { Eye, EyeOff } from "lucide-react";
import { fetchHealth, getApiToken, setApiToken, type ProviderHealth } from "@/api";
import { sourceLabel } from "@/lib/evidence";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { InterfacePicker } from "@/components/InterfacePicker";

// Provider keys live in backend/.env; this page only reports whether each one is set.
const KEY_ENV: Record<string, string> = {
  virustotal: "VIRUSTOTAL_API_KEY",
  nvd: "NVD_API_KEY",
  wigle: "WIGLE_API_NAME, WIGLE_API_TOKEN",
  urlhaus: "ABUSECH_AUTH_KEY",
  threatfox: "ABUSECH_AUTH_KEY",
  safebrowsing: "GOOGLE_SAFE_BROWSING_API_KEY",
  abuseipdb: "ABUSEIPDB_API_KEY",
  otx: "OTX_API_KEY",
};

const STATE_TEXT: Record<string, string> = { configured: "Set", placeholder: "Placeholder", missing: "Not set" };

function ApiTokenCard() {
  const [value, setValue] = useState("");
  const [saved, setSaved] = useState(() => getApiToken() !== "");
  const [reveal, setReveal] = useState(false);

  return (
    <Card className="flex flex-col gap-3 p-5">
      <div className="flex items-center gap-2">
        <span className="text-sm font-semibold text-foreground">API token</span>
        <Badge variant={saved ? "solid" : "outline"}>{saved ? "Set" : "Not set"}</Badge>
      </div>
      <div className="flex w-full max-w-md items-center gap-2">
        <div className="relative flex-1">
          <Input
            type={reveal ? "text" : "password"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={saved ? "•••••••• (saved)" : "Paste token"}
            aria-label="API token"
            className="pr-9 font-mono text-xs"
            autoComplete="off"
          />
          <button
            type="button"
            onClick={() => setReveal((r) => !r)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-subtle hover:text-foreground"
            aria-label={reveal ? "Hide token" : "Show token"}
          >
            {reveal ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
          </button>
        </div>
        <Button
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
      {!saved && <p className="font-mono text-xs text-subtle">python -m app.core.auth prints it</p>}
    </Card>
  );
}

function ProviderKeys({ providers }: { providers: Record<string, ProviderHealth> | null }) {
  const keyed = Object.entries(providers ?? {}).filter(([, p]) => p.state !== "keyless" && p.state !== "local");
  return (
    <Card className="p-5">
      <span className="text-sm font-semibold text-foreground">Provider keys</span>
      {providers === null ? (
        <p className="mt-3 text-sm text-subtle">Backend unreachable</p>
      ) : (
        <ul className="mt-3 flex flex-col divide-y divide-line">
          {keyed.map(([name, p]) => (
            <li key={name} className="grid grid-cols-[11rem_minmax(0,1fr)_auto] items-center gap-x-3 py-2 text-sm">
              <span className="text-foreground">{sourceLabel(name)}</span>
              <span className="truncate font-mono text-xs text-subtle">{KEY_ENV[name] ?? ""}</span>
              <Badge variant={p.configured ? "solid" : "outline"}>{STATE_TEXT[p.state] ?? p.state}</Badge>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export const Settings: React.FC = () => {
  const [providers, setProviders] = useState<Record<string, ProviderHealth> | null>({});

  useEffect(() => {
    fetchHealth()
      .then((h) => setProviders(h.providers ?? {}))
      .catch(() => setProviders(null));
  }, []);

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
      <ApiTokenCard />
      <InterfacePicker />
      <ProviderKeys providers={providers} />
    </div>
  );
};
