// Copy non-TypeScript node assets (icons + codex JSON) into dist/ after tsc.
// Dependency-free and cross-platform (Windows/macOS/Linux) - no gulp, no shx.
import { cpSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const srcDir = join(root, 'nodes');
const outDir = join(root, 'dist', 'nodes');

const ASSET_RE = /\.(svg|png|node\.json)$/;

function walk(dir) {
	for (const entry of readdirSync(dir)) {
		const abs = join(dir, entry);
		if (statSync(abs).isDirectory()) {
			walk(abs);
		} else if (ASSET_RE.test(entry)) {
			const dest = join(outDir, relative(srcDir, abs));
			cpSync(abs, dest);
			console.log('copied', relative(root, dest));
		}
	}
}

walk(srcDir);
