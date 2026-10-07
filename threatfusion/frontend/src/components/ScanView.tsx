/** Scan view: input → verdict row → evidence table → collapsible details. The request inspector sits below. */
import { useState } from "react";
import { ChevronDown, Check, Copy } from "lucide-react";
import type { ScanResult } from "@/api";
import { cn } from "@/lib/utils";
import { verdictView } from "@/lib/verdict";
import { evidenceTable, liveRows } from "@/lib/scanview";
import type { ScanState } from "@/hooks/useScan";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SeverityTag } from "@/components/RiskIndicators";
import { RiskScorePanel } from "@/components/RiskScorePanel";
import { ScanForm } from "@/components/ScanForm";
import { FastVerdictCard } from "@/components/FastVerdictCard";
import { EvidenceTable } from "@/components/EvidenceTable";
import { ScanDetails } from "@/components/ScanDetails";
import { Inspector } from "@/components/Inspector";

function exportJson(result: ScanResult) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `threatfusion-${result.scan_id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function ScanReport({ result, onRescan }: { result: ScanResult; onRescan: () => void }) {
  const [copied, setCopied] = useState(false);
  const view = verdictView(result);
  const table = evidenceTable(result);

  const copyTarget = async () => {
    try {
      await navigator.clipboard.writeText(result.target);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* the clipboard can be unavailable (insecure context); nothing to recover */
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <SeverityTag score={null} label={result.headline_band ?? "Unknown"} className="text-base" />
        <span className="min-w-0 flex-1 break-all font-mono text-sm text-foreground">{result.target}</span>
        <Badge variant="subtle">{result.target_type}</Badge>
        <button type="button" onClick={copyTarget} aria-label="Copy target" className="text-subtle transition-colors hover:text-foreground">
          {copied ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
        </button>
        <Button variant="outline" size="sm" onClick={onRescan}>Rescan</Button>
        <Button variant="outline" size="sm" onClick={() => exportJson(result)}>Export</Button>
      </div>

      {result.verdict_status === "unknown" && result.verdict_reason && <p className="text-sm text-warn">Unknown — {result.verdict_reason}</p>}

      <RiskScorePanel view={view} />
      <EvidenceTable rows={table.rows} footer={table} />
      <ScanDetails result={result} />
    </div>
  );
}

export function ScanView({ scan }: { scan: ScanState }) {
  const { loading, error, result, live, fast, submit, rescan } = scan;
  return (
    <div className="flex flex-col gap-6">
      <ScanForm onSubmit={submit} loading={loading} />

      {error && (
        <p role="alert" className="text-sm text-danger">
          Scan failed — {error}
        </p>
      )}

      {loading && (
        <div className="flex flex-col gap-4">
          <FastVerdictCard verdict={fast} running />
          <EvidenceTable rows={liveRows(live)} running />
        </div>
      )}
      {!loading && !error && result && <ScanReport result={result} onRescan={rescan} />}
      {!loading && !error && !result && <p className="text-sm text-subtle">No scan yet</p>}

      <details className="group rounded-lg border border-line bg-surface">
        <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3 text-sm font-medium text-foreground">
          Inspect request
          <ChevronDown className={cn("size-4 text-subtle transition-transform group-open:rotate-180")} aria-hidden />
        </summary>
        <div className="border-t border-line p-4">
          <Inspector />
        </div>
      </details>
    </div>
  );
}
