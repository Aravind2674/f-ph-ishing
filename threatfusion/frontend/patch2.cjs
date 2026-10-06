const fs = require('fs');
let tsx = fs.readFileSync('src/components/RiskScorePanel.tsx', 'utf8');

tsx = tsx.replace('className={cn(\n        "flex flex-col gap-5 p-5 sm:p-6",', 'className={cn(\n        "flex flex-col gap-3 p-4 sm:p-5 h-full justify-between",');
tsx = tsx.replace('className="mt-4"', 'className="mt-3"');

fs.writeFileSync('src/components/RiskScorePanel.tsx', tsx, 'utf8');
console.log("Patched RiskScorePanel");
