import { useState } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Crosshair } from 'lucide-react';
import { DashboardLayout } from './components/DashboardLayout';
import { ScanForm } from './components/ScanForm';
import { ScanResult } from './components/ScanResult';
import { Inspector } from './components/Inspector';
import { VerifyPanel } from './components/VerifyPanel';
import { History } from './components/History';
import { Settings } from './components/Settings';
import { NetworkSection } from './components/NetworkSection';
import { Card } from './components/ui/card';
import { Skeleton } from './components/ui/skeleton';
import { SiteMeteorsBackground } from './components/ui/site-meteors-background';
import { submitScan } from './api';
import type { ScanResult as IScanResult, ScanRequest } from './api';

function App() {
  // NOTE: view/scan state management is intentionally unchanged from the
  // original — this rebuild is presentation-only.
  const [currentView, setCurrentView] = useState<'scan' | 'network' | 'history' | 'settings'>('scan');
  const [scanResult, setScanResult] = useState<IScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScanSubmit = async (request: ScanRequest) => {
    setLoading(true);
    setError(null);
    setScanResult(null);
    setCurrentView('scan'); // Auto-switch to scan view
    try {
      const response = await submitScan(request);
      if (response.success && response.result) {
        setScanResult(response.result);
      } else {
        setError(response.error || 'Unknown error occurred');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to submit scan');
    } finally {
      setLoading(false);
    }
  };

  const handleRescan = () => {
    if (scanResult) {
      handleScanSubmit({ target: scanResult.target, target_type: scanResult.target_type as any });
    }
  };

  return (
    <>
      {/*
        Ambient meteors — mounted once at the app root (sibling of the shell),
        not inside DashboardLayout or per-view, so it never remounts on nav and
        stays behind floating nav / opaque cards via -z-10.
      */}
      <SiteMeteorsBackground />

      <DashboardLayout activeTab={currentView} onTabChange={setCurrentView as any}>
        {currentView === 'network' && <NetworkSection />}
        {currentView === 'history' && <History />}
        {currentView === 'settings' && <Settings />}
        {currentView === 'scan' && (
          <div className="flex flex-col gap-8">
            {/* Intro — orients a first-time viewer to the three tools below. */}
            <div className="rounded-xl border border-line bg-surface-2/40 p-4">
              <p className="text-sm text-muted">
                <span className="font-medium text-foreground">Three tools, one workflow.</span>{' '}
                Assess a domain's risk, inspect requests for injection attacks, then
                actively confirm a finding — each section below works on its own.
              </p>
            </div>

            {/* ── 01 · Scan a domain ─────────────────────────────────────── */}
            <section className="flex flex-col gap-5">
              <SectionDivider step="01" label="Scan a domain" hint="reputation + neural URL risk" />
              <ScanForm onSubmit={handleScanSubmit} loading={loading} />

              {error && (
                <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
                  <Card className="flex items-start gap-3 border-line-strong p-5">
                    <div className="flex size-9 shrink-0 items-center justify-center rounded-md border border-line-strong bg-surface-2">
                      <AlertTriangle className="size-4 text-foreground" />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-foreground">Scan failed</h3>
                      <p className="mt-1 font-mono text-xs text-muted">{error}</p>
                    </div>
                  </Card>
                </motion.div>
              )}

              {loading && <ScanningState />}
              {!loading && !error && scanResult && (
                <ScanResult result={scanResult} onRescan={handleRescan} />
              )}
              {!loading && !error && !scanResult && <IdleState />}
            </section>

            {/* ── 02 · Inspect a request ─────────────────────────────────── */}
            <section className="flex flex-col gap-5">
              <SectionDivider step="02" label="Inspect a request or traffic" hint="neural attack classifier" />
              <Inspector />
            </section>

            {/* ── 03 · Verify a target ───────────────────────────────────── */}
            <section className="flex flex-col gap-5">
              <SectionDivider step="03" label="Verify a target" hint="safe active probes · localhost only" />
              <VerifyPanel />
            </section>
          </div>
        )}
      </DashboardLayout>
    </>
  );
}

/** Labelled divider that gives the merged page clear top-to-bottom wayfinding. */
function SectionDivider({ step, label, hint }: { step: string; label: string; hint: string }) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-2">
      <span className="font-mono text-xs font-semibold tabular-nums text-foreground">{step}</span>
      <span className="text-sm font-medium text-foreground">{label}</span>
      <span className="font-mono text-[10px] uppercase tracking-wide2 text-subtle">{hint}</span>
      <span className="ml-1 h-px flex-1 bg-line" />
    </div>
  );
}

/** Designed loading state — skeletons + a scan-line, never a spinner. */
function ScanningState() {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-wide2 text-subtle">
        <span className="size-1.5 animate-pulse rounded-full bg-foreground" />
        Fusing signals…
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {[0, 1].map((i) => (
          <Card key={i} className="flex items-center gap-5 p-6">
            <Skeleton className="size-28 rounded-full" />
            <div className="flex flex-1 flex-col gap-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-3 w-40" />
              <Skeleton className="mt-2 h-3 w-24" />
            </div>
          </Card>
        ))}
      </div>
      <Card className="relative overflow-hidden p-5">
        <div className="pointer-events-none absolute inset-x-0 top-0 h-full overflow-hidden">
          <div className="tf-scanline absolute inset-x-0 h-20 animate-scan" />
        </div>
        <div className="flex flex-col gap-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-4" style={{ width: `${90 - i * 12}%` }} />
          ))}
        </div>
      </Card>
    </div>
  );
}

/** Designed empty state shown before the first scan. */
function IdleState() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.1 }}
      className="flex flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-line py-20 text-center"
    >
      <div className="relative flex size-16 items-center justify-center">
        <Crosshair className="absolute size-16 animate-spin-slow text-subtle/30" strokeWidth={0.75} />
        <Crosshair className="size-6 text-muted" />
      </div>
      <div>
        <p className="text-sm font-medium text-foreground">Awaiting target</p>
        <p className="mx-auto mt-1 max-w-sm text-xs text-subtle">
          Enter a domain, IP, URL or file hash above to begin attack-surface analysis.
        </p>
      </div>
    </motion.div>
  );
}

export default App;
