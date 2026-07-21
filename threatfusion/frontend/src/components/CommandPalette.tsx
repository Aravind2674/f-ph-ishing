import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Crosshair,
  History as HistoryIcon,
  Settings as SettingsIcon,
  CornerDownLeft,
  Search,
} from "lucide-react";
import { cn } from "@/lib/utils";

type View = "scan" | "history" | "settings";

interface Command {
  id: string;
  label: string;
  hint: string;
  keywords: string;
  icon: typeof Crosshair;
  run: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onNavigate: (view: View) => void;
  onNewScan: () => void;
}

/*
 * ⌘K command palette. Purely a convenience layer over the *existing* view state
 * (it only calls the navigation callbacks already owned by <App/>), so it adds
 * no new global state or routing — just a faster way to move around.
 */
export function CommandPalette({
  open,
  onOpenChange,
  onNavigate,
  onNewScan,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands: Command[] = useMemo(
    () => [
      {
        id: "new-scan",
        label: "New scan",
        hint: "Open the targeting console",
        keywords: "scan target new run analyze",
        icon: Crosshair,
        run: onNewScan,
      },
      {
        id: "history",
        label: "Scan history",
        hint: "Review previous engagements",
        keywords: "history log past records table",
        icon: HistoryIcon,
        run: () => onNavigate("history"),
      },
      {
        id: "settings",
        label: "Settings",
        hint: "Ingestion sources & mode",
        keywords: "settings config keys sources mock live",
        icon: SettingsIcon,
        run: () => onNavigate("settings"),
      },
    ],
    [onNavigate, onNewScan]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter(
      (c) =>
        c.label.toLowerCase().includes(q) ||
        c.keywords.includes(q)
    );
  }, [commands, query]);

  // Reset transient state each time the palette opens, and focus the input.
  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      // Defer focus until the element is mounted/animated in.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    if (active >= filtered.length) setActive(0);
  }, [filtered.length, active]);

  const runActive = () => {
    const cmd = filtered[active];
    if (cmd) {
      cmd.run();
      onOpenChange(false);
    }
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-[100] flex items-start justify-center px-4 pt-[16vh]"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          onMouseDown={() => onOpenChange(false)}
        >
          <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" />
          <motion.div
            role="dialog"
            aria-modal="true"
            className="relative w-full max-w-lg overflow-hidden rounded-xl border border-line-strong bg-surface shadow-glow"
            initial={{ opacity: 0, y: -8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            onMouseDown={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setActive((a) => Math.min(a + 1, filtered.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setActive((a) => Math.max(a - 1, 0));
              } else if (e.key === "Enter") {
                e.preventDefault();
                runActive();
              } else if (e.key === "Escape") {
                onOpenChange(false);
              }
            }}
          >
            <div className="flex items-center gap-3 border-b border-line px-4">
              <Search className="size-4 text-subtle" />
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Type a command or search…"
                className="h-12 w-full bg-transparent text-sm text-foreground placeholder:text-subtle outline-none"
              />
              <kbd className="rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-subtle">
                ESC
              </kbd>
            </div>

            <div className="max-h-72 overflow-y-auto p-2">
              {filtered.length === 0 ? (
                <div className="px-3 py-8 text-center font-mono text-xs uppercase tracking-wide2 text-subtle">
                  No matching commands
                </div>
              ) : (
                filtered.map((cmd, i) => {
                  const Icon = cmd.icon;
                  const isActive = i === active;
                  return (
                    <button
                      key={cmd.id}
                      onMouseEnter={() => setActive(i)}
                      onClick={runActive}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left transition-colors",
                        isActive ? "bg-surface-3" : "hover:bg-surface-2"
                      )}
                    >
                      <Icon
                        className={cn(
                          "size-4",
                          isActive ? "text-foreground" : "text-muted"
                        )}
                      />
                      <span className="flex-1">
                        <span className="block text-sm text-foreground">
                          {cmd.label}
                        </span>
                        <span className="block text-xs text-subtle">
                          {cmd.hint}
                        </span>
                      </span>
                      {isActive && (
                        <CornerDownLeft className="size-3.5 text-subtle" />
                      )}
                    </button>
                  );
                })
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
