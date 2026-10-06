const fs = require('fs');

let rs = fs.readFileSync('src/components/RiskScorePanel.tsx', 'utf8');
rs = rs.replace('className={cn(\n        "flex flex-col gap-3 p-4 sm:p-5 h-full justify-between",', 'className={cn(\n        "flex flex-col gap-3 p-4 sm:p-5",');
fs.writeFileSync('src/components/RiskScorePanel.tsx', rs, 'utf8');

let sr = fs.readFileSync('src/components/ScanResult.tsx', 'utf8');
sr = sr.replace('<Card className="flex flex-col h-full justify-between p-4 sm:p-5">', '<Card className="p-4 sm:p-5">');
fs.writeFileSync('src/components/ScanResult.tsx', sr, 'utf8');
console.log("Cleaned up h-full");
