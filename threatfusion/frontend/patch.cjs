const fs = require('fs');

let css = fs.readFileSync('src/index.css', 'utf8');
css = css.replace('--background: 0 0% 4%;', '--background: 0 0% 3%;');
css = css.replace('--surface: 0 0% 7%;', '--surface: 0 0% 10%;');
css = css.replace('--surface-2: 0 0% 10%;', '--surface-2: 0 0% 14%;');
css = css.replace('--surface-3: 0 0% 14%;', '--surface-3: 0 0% 18%;');
css = css.replace('--foreground: 0 0% 91%;', '--foreground: 0 0% 96%;');
css = css.replace('--muted: 0 0% 64%;', '--muted: 0 0% 75%;');
css = css.replace('--subtle: 0 0% 42%;', '--subtle: 0 0% 55%;');
css = css.replace('--line: 0 0% 100% / 0.08;', '--line: 0 0% 100% / 0.12;');
fs.writeFileSync('src/index.css', css, 'utf8');

let tsx = fs.readFileSync('src/components/ScanResult.tsx', 'utf8');
// tighten the overall gap
tsx = tsx.replace('className="flex flex-col gap-6"', 'className="flex flex-col gap-4"');
// make sure the grid columns are dense
tsx = tsx.replace('className="grid grid-cols-1 gap-4 xl:grid-cols-3"', 'className="grid grid-cols-1 gap-4 lg:grid-cols-3"');
tsx = tsx.replace('className="flex flex-col gap-4 xl:col-span-2"', 'className="flex flex-col gap-4 lg:col-span-2"');
// remove h-full if it's causing empty space in the Why this score card
tsx = tsx.replace('<Card className="h-full">', '<Card className="flex flex-col h-full justify-between">');
fs.writeFileSync('src/components/ScanResult.tsx', tsx, 'utf8');
console.log("Patched");
