/** One scan at a time: the result, the live per-source progress and the fast verdict. Lives in App so switching views keeps the result. */
import { useCallback, useRef, useState } from "react";
import { newScanId, submitScan, subscribeScanEvents, waitForScan, type FastVerdict, type ScanRequest, type ScanResult } from "../api";
import { applyLiveEvent, emptyLiveState, type LiveState } from "../lib/evidence";

export interface ScanState {
  loading: boolean;
  error: string | null;
  result: ScanResult | null;
  live: LiveState;
  fast: FastVerdict | null;
  submit: (request: ScanRequest) => Promise<void>;
  rescan: () => void;
}

export function useScan(): ScanState {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState<LiveState>(emptyLiveState());
  const [fast, setFast] = useState<FastVerdict | null>(null);
  const liveSub = useRef<{ close: () => void } | null>(null);

  const submit = useCallback(async (request: ScanRequest) => {
    setLoading(true);
    setError(null);
    setResult(null);
    setFast(null);
    // Choose the scan id first and open the progress stream before posting, so every source shows from its first event.
    const scanId = newScanId();
    setLive(emptyLiveState());
    liveSub.current?.close();
    liveSub.current = subscribeScanEvents(scanId, (event) => setLive((s) => applyLiveEvent(s, event)));
    try {
      // The POST answers at once with the fast verdict; the full scan finishes in the background.
      const started = await submitScan({ ...request, scan_id: scanId, mode: "async" });
      if (started.fast) setFast(started.fast);
      const response = started.status === "running" ? await waitForScan(scanId) : started;
      if (response.success && response.result) setResult(response.result);
      else setError(response.error || "Unknown error");
    } catch (err: any) {
      setError(err.message || "Could not submit the scan");
    } finally {
      liveSub.current?.close();
      liveSub.current = null;
      setLoading(false);
    }
  }, []);

  const rescan = useCallback(() => {
    if (result) void submit({ target: result.target, target_type: result.target_type as ScanRequest["target_type"] });
  }, [result, submit]);

  return { loading, error, result, live, fast, submit, rescan };
}
