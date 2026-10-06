const fs = require('fs');
let tsx = fs.readFileSync('src/components/ScanResult.tsx', 'utf8');

tsx = tsx.replace('      <Card className="p-5">\n        <div className="mb-4 flex items-center gap-2">\n          <BrainCircuit className="size-4 text-muted" />', '      <Card className="flex flex-col h-full justify-between p-4 sm:p-5">\n        <div className="mb-4 flex items-center gap-2">\n          <BrainCircuit className="size-4 text-muted" />');

fs.writeFileSync('src/components/ScanResult.tsx', tsx, 'utf8');
console.log("Patched NeuralPanel");
