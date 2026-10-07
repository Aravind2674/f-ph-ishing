import { useEffect, useState } from "react";
import { Settings as SettingsIcon } from "lucide-react";
import { fetchHealth } from "@/api";
import { cn } from "@/lib/utils";

export type View = "scan" | "network" | "history" | "settings";

const TABS: { id: View; label: string }[] = [
  { id: "scan", label: "Scan" },
  { id: "network", label: "Network" },
  { id: "history", label: "History" },
];

export function TopBar({ view, onChange }: { view: View; onChange: (view: View) => void }) {
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    let alive = true;
    fetchHealth()
      .then(() => alive && setOffline(false))
      .catch(() => alive && setOffline(true));
    return () => {
      alive = false;
    };
  }, []);

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-background">
      <div className="mx-auto flex h-14 w-full max-w-6xl items-center gap-6 px-6">
        <button type="button" onClick={() => onChange("scan")} className="flex items-center gap-2 text-sm font-semibold text-foreground" aria-label="ThreatFusion">
          <span className="size-3 rounded-sm bg-accent" aria-hidden />
          <span>ThreatFusion</span>
        </button>

        <nav aria-label="Views" className="flex flex-1 items-stretch gap-1 self-stretch">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              aria-current={view === tab.id ? "page" : undefined}
              onClick={() => onChange(tab.id)}
              className={cn(
                "border-b-2 px-3 text-sm transition-colors",
                view === tab.id ? "border-accent font-medium text-foreground" : "border-transparent text-muted hover:text-foreground",
              )}
            >
              {tab.label}
            </button>
          ))}
        </nav>

        {offline && <span className="font-mono text-xs text-danger">API offline</span>}

        <button
          type="button"
          aria-label="Settings"
          aria-current={view === "settings" ? "page" : undefined}
          onClick={() => onChange("settings")}
          className={cn("rounded-md p-2 transition-colors hover:text-foreground", view === "settings" ? "text-accent" : "text-muted")}
        >
          <SettingsIcon className="size-4" aria-hidden />
        </button>
      </div>
    </header>
  );
}
