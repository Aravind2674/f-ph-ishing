const fs = require('fs');
let content = fs.readFileSync('src/components/ScanResult.tsx', 'utf8');

const returnStartStr = '  return (\n    <motion.div';
const returnStart = content.indexOf(returnStartStr);
const endMarker = content.indexOf('\nfunction EmptyPanel({');
const returnEnd = content.lastIndexOf('  );\n};\n', endMarker);

const newReturn = `  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col gap-4"
    >
      {/* Target header */}
      <div className="flex flex-col gap-4 border-b border-line pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-3">
            <SeverityTag score={ml / 100} label={result.ml_label} />
            <span className="font-mono text-xs text-subtle">
              {result.scan_id.slice(0, 8).toUpperCase()}
            </span>
            <Badge variant="subtle">{result.target_type}</Badge>
          </div>
          <div className="flex items-center gap-2">
            <h2 className="truncate font-mono text-xl font-semibold tracking-tight text-foreground md:text-2xl">
              {result.target}
            </h2>
            <button
              onClick={copyTarget}
              className="text-subtle transition-colors hover:text-foreground"
              aria-label="Copy target"
            >
              {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
            </button>
          </div>
          <p className="mt-1 font-mono text-xs text-subtle">
            {new Date(result.timestamp).toLocaleString()}
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button variant="outline" size="sm" onClick={onRescan}>
            <RefreshCw className="size-3.5" />
            Re-scan
          </Button>
          <Button variant="subtle" size="sm" onClick={handleExport}>
            <Download className="size-3.5" />
            Export JSON
          </Button>
        </div>
      </div>

      {result.summary && (
        <p className="text-sm leading-relaxed text-muted">{result.summary}</p>
      )}

      {/* Masonry-style 2-column layout to prevent unused gaps */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
        
        {/* LEFT COLUMN */}
        <div className="flex flex-col gap-4">
          <RiskScorePanel
            baselineScore={baseline}
            mlScore={ml}
            severityLabel={result.ml_label}
            revealKey={result.scan_id}
          />

          <Card className="p-0">
            <div className="flex items-center gap-2 p-5 pb-4 border-b border-line">
              <Radar className="size-4 text-muted" />
              <span className="text-sm font-semibold text-foreground">
                Why this score? (Top Factors)
              </span>
            </div>
            <div className="px-5 py-5">
              {topShap.length ? (
                <ShapWaterfall items={topShap} />
              ) : (
                <p className="py-6 text-center text-sm text-subtle">
                  No specific factors found to explain this score.
                </p>
              )}
            </div>
          </Card>

          {explanations.length > 0 && <FeatureVectorTable items={explanations} />}

          {result.attack_paths && result.attack_paths.length > 0 && (
            <Card className="p-5">
              <div className="mb-4 flex items-center gap-2">
                <GitBranch className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Attack Paths
                </span>
                <Badge variant="subtle">{result.attack_paths.length}</Badge>
              </div>
              <div className="flex flex-col gap-4">
                {result.attack_paths.map((path) => (
                  <div
                    key={path.path_id}
                    className="rounded-lg border border-line bg-surface-2/40"
                  >
                    <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
                      <span className="font-mono text-xs text-muted">
                        Path {path.path_id} - {path.summary}
                      </span>
                      <span className="flex items-center gap-2">
                        <RiskMeter score={path.total_risk_score} />
                        <span className="font-mono text-xs tabular-nums text-foreground">
                          {pct(path.total_risk_score)}%
                        </span>
                      </span>
                    </div>
                    <div className="p-4">
                      <AttackChain path={path} />
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>

        {/* RIGHT COLUMN */}
        <div className="flex flex-col gap-4">
          <NeuralPanel result={result} />

          <Card className="p-5">
            <div className="mb-4 flex items-center gap-2">
              <CircleAlert className="size-4 text-muted" />
              <span className="text-sm font-semibold text-foreground">
                Data Sources
              </span>
            </div>
            <div className="flex flex-col gap-4">
              <DataRow label={"Successful - " + (result.data_sources_succeeded?.length ?? 0)}>
                {result.data_sources_succeeded?.length ? (
                  result.data_sources_succeeded.map((s) => (
                    <Badge key={s} variant="outline">
                      {s}
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs text-subtle">None</span>
                )}
              </DataRow>
              <DataRow label={"Failed - " + (result.data_sources_failed?.length ?? 0)}>
                {result.data_sources_failed?.length ? (
                  result.data_sources_failed.map((s) => (
                    <Badge key={s} variant="ghost" className="line-through">
                      {s}
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs text-subtle">None</span>
                )}
              </DataRow>
              {vt && (
                <div className="border-t border-line pt-3">
                  <span className="tf-eyebrow">Antivirus Detections</span>
                  <p className="mt-1 font-mono text-lg tabular-nums text-foreground">
                    {vt.malicious_count ?? 0}
                    <span className="text-subtle">
                      {" "}/ {vt.total_engines ?? "?"}
                    </span>
                  </p>
                </div>
              )}
            </div>
          </Card>

          <Card className="p-5">
            <div className="mb-4 flex items-center gap-2">
              <Boxes className="size-4 text-muted" />
              <span className="text-sm font-semibold text-foreground">
                Technologies Detected
              </span>
            </div>
            {techs.length ? (
              <div className="flex flex-col divide-y divide-line">
                {techs.map((t, i) => (
                  <div key={i} className="flex items-center justify-between py-2 first:pt-0">
                    <span className="text-sm text-foreground">{t.name}</span>
                    <span
                      className={cn(
                        "rounded border px-2 py-0.5 font-mono text-[10px]",
                        t.is_eol
                          ? "border-line-strong font-semibold text-foreground"
                          : "border-line text-subtle"
                      )}
                    >
                      v{t.version || "?"}
                      {t.is_eol ? " (EOL)" : ""}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyPanel icon={Boxes} text="No tech stack detected." />
            )}
          </Card>

          <Card className="p-5">
            <div className="mb-4 flex items-center gap-2">
              <Network className="size-4 text-muted" />
              <span className="text-sm font-semibold text-foreground">
                Open Ports
              </span>
            </div>
            {shodan ? (
              <div className="flex flex-col gap-4">
                <DataRow label="Ports">
                  {shodan.open_ports?.length ? (
                    shodan.open_ports.map((p) => (
                      <span
                        key={p}
                        className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-xs tabular-nums text-foreground"
                      >
                        {p}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-subtle">None</span>
                  )}
                </DataRow>
              </div>
            ) : (
              <EmptyPanel icon={Network} text="No ports detected." />
            )}
          </Card>

          {cves.length > 0 && (
            <Card className="p-5">
              <div className="mb-4 flex items-center gap-2">
                <Bug className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Vulnerabilities (CVEs)
                </span>
                <Badge variant="subtle">{cves.length}</Badge>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {cves.map((c, i) => {
                  const id = c.cve_id || c.id;
                  const cvss = c.cvss_v3_score ?? c.cvss_score;
                  return (
                    <div
                      key={id || i}
                      className="flex items-center justify-between rounded-md border border-line bg-surface-2 px-3 py-2"
                    >
                      <span className="font-mono text-xs text-foreground">{id}</span>
                      {cvss != null && (
                        <span className="flex items-center gap-2">
                          <RiskMeter score={Number(cvss) / 10} />
                          <span className="font-mono text-xs tabular-nums text-muted">
                            {Number(cvss).toFixed(1)}
                          </span>
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </Card>
          )}
        </div>
      </div>
    </motion.div>`;

const newContent = content.slice(0, returnStart) + newReturn + content.slice(returnEnd);
fs.writeFileSync('src/components/ScanResult.tsx', newContent, 'utf8');
console.log("Success");
