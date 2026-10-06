const fs = require('fs');
let content = fs.readFileSync('src/components/ScanResult.tsx', 'utf8');

const targetStr = `          <Card className="p-5">
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
          </Card>`;

const replacement = `          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Card className="p-4 sm:p-5 flex flex-col max-h-[340px]">
              <div className="mb-4 flex items-center gap-2 shrink-0">
                <Boxes className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Technologies
                </span>
              </div>
              <div className="flex-1 overflow-y-auto pr-1.5 min-h-0">
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
              </div>
            </Card>

            <Card className="p-4 sm:p-5 flex flex-col max-h-[340px]">
              <div className="mb-4 flex items-center gap-2 shrink-0">
                <Network className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Open Ports
                </span>
              </div>
              <div className="flex-1 overflow-y-auto pr-1.5 min-h-0">
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
              </div>
            </Card>
          </div>`;

if (content.includes(targetStr)) {
  const newContent = content.replace(targetStr, replacement);
  fs.writeFileSync('src/components/ScanResult.tsx', newContent, 'utf8');
  console.log("Success");
} else {
  console.log("Target string not found. Please check.");
}
