const fs = require('fs');

let tsx = fs.readFileSync('src/components/ScanResult.tsx', 'utf8');

// 1. Attack Paths
let attackPathSearch = `            <Card className="p-5">
              <div className="mb-4 flex items-center gap-2">
                <GitBranch className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Attack Paths
                </span>
                <Badge variant="subtle">{result.attack_paths.length}</Badge>
              </div>
              <div className="flex flex-col gap-4">
                {result.attack_paths.map((path) => (`;
let attackPathReplace = `            <Card className="flex flex-col p-4 sm:p-5 max-h-[400px]">
              <div className="mb-4 flex items-center gap-2 shrink-0">
                <GitBranch className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Attack Paths
                </span>
                <Badge variant="subtle">{result.attack_paths.length}</Badge>
              </div>
              <div className="flex-1 overflow-y-auto pr-1.5 min-h-0 tf-scrollbar">
                <div className="flex flex-col gap-4">
                  {result.attack_paths.map((path) => (`

let attackPathSearchEnd = `                  </div>
                ))}
              </div>
            </Card>`;
let attackPathReplaceEnd = `                  </div>
                ))}
                </div>
              </div>
            </Card>`;
if (tsx.includes(attackPathSearch)) {
  tsx = tsx.replace(attackPathSearch, attackPathReplace);
  tsx = tsx.replace(attackPathSearchEnd, attackPathReplaceEnd);
}

// 2. Vulnerabilities
let vulnsSearch = `            <Card className="p-5">
              <div className="mb-4 flex items-center gap-2">
                <Bug className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Vulnerabilities (CVEs)
                </span>
                <Badge variant="subtle">{cves.length}</Badge>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {cves.map((c, i) => {`;

let vulnsReplace = `            <Card className="flex flex-col p-4 sm:p-5 max-h-[400px]">
              <div className="mb-4 flex items-center gap-2 shrink-0">
                <Bug className="size-4 text-muted" />
                <span className="text-sm font-semibold text-foreground">
                  Vulnerabilities (CVEs)
                </span>
                <Badge variant="subtle">{cves.length}</Badge>
              </div>
              <div className="flex-1 overflow-y-auto pr-1.5 min-h-0 tf-scrollbar">
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {cves.map((c, i) => {`;

let vulnsSearchEnd = `                  );
                })}
              </div>
            </Card>`;
let vulnsReplaceEnd = `                  );
                })}
                </div>
              </div>
            </Card>`;

if (tsx.includes(vulnsSearch)) {
  tsx = tsx.replace(vulnsSearch, vulnsReplace);
  tsx = tsx.replace(vulnsSearchEnd, vulnsReplaceEnd);
}

// 3. Data Sources
let dsSearch = `          <Card className="p-5">
            <div className="mb-4 flex items-center gap-2">
              <CircleAlert className="size-4 text-muted" />
              <span className="text-sm font-semibold text-foreground">
                Data Sources
              </span>
            </div>
            <div className="flex flex-col gap-4">`;

let dsReplace = `          <Card className="flex flex-col p-4 sm:p-5 max-h-[340px]">
            <div className="mb-4 flex items-center gap-2 shrink-0">
              <CircleAlert className="size-4 text-muted" />
              <span className="text-sm font-semibold text-foreground">
                Data Sources
              </span>
            </div>
            <div className="flex-1 overflow-y-auto pr-1.5 min-h-0 tf-scrollbar">
              <div className="flex flex-col gap-4">`;
let dsSearchEnd = `              )}
            </div>
          </Card>`;
let dsReplaceEnd = `              )}
              </div>
            </div>
          </Card>`;

if (tsx.includes(dsSearch)) {
  tsx = tsx.replace(dsSearch, dsReplace);
  tsx = tsx.replace(dsSearchEnd, dsReplaceEnd);
}

// 4. Neural Panel
let neuralSearch = `  return (
    <Card className="p-4 sm:p-5">
      <div className="mb-4 flex items-center gap-2">
        <BrainCircuit className="size-4 text-muted" />
        <span className="text-sm font-semibold text-foreground">
          AI Phishing Analysis
        </span>
        <span className="tf-eyebrow ml-1">Detects suspicious patterns in URLs</span>
        <span className="ml-auto">
          <SeverityTag score={neural} label={result.neural_label ?? undefined} />
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">`;
      
let neuralReplace = `  return (
    <Card className="flex flex-col p-4 sm:p-5 max-h-[400px]">
      <div className="mb-4 flex items-center gap-2 shrink-0">
        <BrainCircuit className="size-4 text-muted" />
        <span className="text-sm font-semibold text-foreground">
          AI Phishing Analysis
        </span>
        <span className="tf-eyebrow ml-1">Detects suspicious patterns in URLs</span>
        <span className="ml-auto">
          <SeverityTag score={neural} label={result.neural_label ?? undefined} />
        </span>
      </div>

      <div className="flex-1 overflow-y-auto pr-1.5 min-h-0 tf-scrollbar">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">`;
        
let neuralSearchEnd = `        )}
    </Card>
  );`;
let neuralReplaceEnd = `        )}
      </div>
    </Card>
  );`;

if (tsx.includes(neuralSearch)) {
  tsx = tsx.replace(neuralSearch, neuralReplace);
  tsx = tsx.replace(neuralSearchEnd, neuralReplaceEnd);
}

// Add tf-scrollbar to ports and tech if they don't have it
tsx = tsx.replace('overflow-y-auto pr-1.5 min-h-0"', 'overflow-y-auto pr-1.5 min-h-0 tf-scrollbar"');
tsx = tsx.replace('overflow-y-auto pr-1.5 min-h-0"', 'overflow-y-auto pr-1.5 min-h-0 tf-scrollbar"'); // replace both

// Also add tf-scrollbar to FeatureVectorTable
let fvtSearch = `          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden"
          >
            <div className="border-t border-line">`;
let fvtReplace = `          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden"
          >
            <div className="border-t border-line max-h-[400px] overflow-y-auto pr-1 tf-scrollbar">`;
            
if (tsx.includes(fvtSearch)) {
  tsx = tsx.replace(fvtSearch, fvtReplace);
}

fs.writeFileSync('src/components/ScanResult.tsx', tsx, 'utf8');
console.log("Patched all cards to be scrollable!");
