/** Settings → capture interface. Automatic means the interface that carries the default route; virtual adapters are marked, not hidden. */
import { useEffect, useState } from "react";
import { fetchInterfaces, setCaptureInterface, type InterfaceChoice } from "@/api";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

export function InterfacePicker() {
  const [choice, setChoice] = useState<InterfaceChoice | null>(null);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    fetchInterfaces()
      .then((c) => {
        setChoice(c);
        setValue(c.configured ?? "");
      })
      .catch((e) => setMessage(e?.message || "Could not load the interfaces"));
  }, []);

  const save = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const c = await setCaptureInterface(value);
      setChoice(c);
      setMessage(value ? `Capture will use ${value}.` : "Capture will use the default route's interface.");
    } catch (e: any) {
      setMessage(e?.message || "Could not save the interface");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="flex flex-col gap-3 p-5">
      <span className="text-sm font-semibold text-foreground">Capture interface</span>
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={value}
          onChange={(e) => setValue(e.target.value)}
          aria-label="Capture interface"
          className="h-9 min-w-[16rem] rounded border border-line-strong bg-surface-2 px-2 text-sm text-foreground"
        >
          <option value="">Automatic (default route)</option>
          {(choice?.interfaces ?? []).map((i) => (
            <option key={i.name} value={i.name}>
              {i.name} - {i.address ?? i.ipv4[0] ?? i.ipv6[0] ?? "no address"}
              {i.virtual ? " (virtual)" : ""}
              {!i.usable ? " (may not capture)" : ""}
            </option>
          ))}
        </select>
        <Button size="sm" onClick={save} disabled={busy || !choice || value === (choice.configured ?? "")}>Save</Button>
      </div>
      {choice?.selected && <p className="text-xs text-muted">In use: {choice.selected}{choice.source ? ` (${choice.source})` : ""}</p>}
      {choice?.error && <p className="text-xs text-danger">{choice.error}</p>}
      {message && <p className="text-xs text-muted">{message}</p>}
    </Card>
  );
}
