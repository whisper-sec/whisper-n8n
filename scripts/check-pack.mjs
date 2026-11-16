// Refuse a tarball that would not load in n8n: every credential and node file that
// package.json's "n8n" block declares must be inside what `npm pack` would publish.
//
//   npm pack --dry-run --json | node scripts/check-pack.mjs
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const report = JSON.parse(readFileSync(0, 'utf8'));
const packed = new Set((report[0]?.files ?? []).map((f) => f.path));
const declared = [...(pkg.n8n?.credentials ?? []), ...(pkg.n8n?.nodes ?? [])];

if (declared.length === 0) {
	console.error('package.json declares no n8n credentials or nodes');
	process.exit(1);
}
const missing = declared.filter((p) => !packed.has(p));
if (missing.length > 0) {
	console.error(`the tarball would not carry: ${missing.join(', ')}`);
	process.exit(1);
}
console.log(`${report[0].name}@${report[0].version}: ${packed.size} files, all ${declared.length} n8n entry points present`);
