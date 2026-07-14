// Generate nodes/Whisper/GraphCatalog.ts from the Whisper graph catalog (catalog.json).
// Usage: node scripts/generate-graph-catalog.mjs <path-to-catalog.json>
//
// The catalog is the single source of truth for the graph recipes this node exposes:
//   - "direct" entries run their exec.cypher as-is against the graph query API,
//     with the recipe's inputs bound as Cypher $parameters.
//   - "flow" entries run by slug via the console gallery/run endpoint (SSE stream).
// Every generated recipe carries its documentation URL (docsBase + docPath) so each
// n8n operation links straight to its docs page.
//
// Dependency-free and deterministic: the same catalog always produces the same file.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const catalogPath = process.argv[2];
if (!catalogPath) {
	console.error('usage: node scripts/generate-graph-catalog.mjs <path-to-catalog.json>');
	process.exit(1);
}

const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));
const docsBase = catalog.graph?.docsBase ?? 'https://www.whisper.security';

// Keep every emitted string ASCII-dashed (repo convention: no em/en dashes).
function clean(s) {
	return String(s ?? '')
		.replace(/\u2014/g, '-')
		.replace(/\u2013/g, '-')
		.replace(/\s+/g, ' ')
		.trim();
}

const WORD_CASE = { asn: 'ASN', ipv4: 'IPv4', ipv6: 'IPv6', rdap: 'RDAP', dns: 'DNS' };

// 'identifierKind' -> 'Identifier Kind', 'asn' -> 'ASN'
function humanize(id) {
	return id
		.replace(/[-_]/g, ' ')
		.replace(/([a-z0-9])([A-Z])/g, '$1 $2')
		.split(' ')
		.filter(Boolean)
		.map((w) => WORD_CASE[w.toLowerCase()] ?? w.charAt(0).toUpperCase() + w.slice(1))
		.join(' ');
}

// 'history-whois' -> 'historyWhois' (for stable, unique n8n parameter names)
function camel(id) {
	return id.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase());
}

function fieldType(kind) {
	if (kind === 'number') return 'number';
	if (kind === 'select') return 'options';
	return 'string';
}

function fieldDescription(input) {
	const parts = [];
	parts.push(`The ${input.kind && input.kind !== 'any' ? input.kind : 'value'} the recipe runs against`);
	if (Array.isArray(input.examples) && input.examples.length) {
		parts.push(`(e.g. ${input.examples.join(', ')})`);
	}
	return clean(parts.join(' '));
}

const recipes = [];
for (const entry of catalog.entries ?? []) {
	const mode = entry.exec?.mode;
	if (mode !== 'direct' && mode !== 'flow') continue;

	const fields = [];
	const cypher = mode === 'direct' ? String(entry.exec.cypher ?? '') : undefined;

	for (const input of entry.inputs ?? []) {
		// A direct recipe binds ONLY the $parameters its fixed exec.cypher references;
		// an input the cypher never reads would be a dead field (whisper.submit's
		// optional per-kind extras are documented on its docs page instead).
		if (mode === 'direct' && !new RegExp(`\\$${input.paramName}\\b`).test(cypher)) continue;
		fields.push({
			name: `g_${camel(entry.id)}_${input.paramName}`,
			paramName: input.paramName,
			displayName: humanize(input.id),
			description: fieldDescription(input),
			default: input.default ?? (fieldType(input.kind) === 'number' ? 0 : ''),
			type: fieldType(input.kind),
			...(input.options ? { options: input.options } : {}),
			target: 'inputs',
			...(mode === 'flow' && fields.length === 0 ? { primary: true } : {}),
		});
	}

	for (const param of entry.params ?? []) {
		fields.push({
			name: `g_${camel(entry.id)}_p_${param.name}`,
			paramName: param.name,
			displayName: humanize(param.name),
			description: clean(`Tuning parameter for the flow (default: ${param.default})`),
			default: param.default ?? (fieldType(param.kind) === 'number' ? 0 : ''),
			type: fieldType(param.kind),
			...(param.options ? { options: param.options } : {}),
			target: 'params',
		});
	}

	recipes.push({
		id: entry.id,
		name: clean(entry.title),
		action: clean(entry.title),
		description: clean(
			`${entry.purpose ?? ''} ${entry.why ?? ''} (${mode === 'flow' ? 'Multi-step flow: streams each step as an item.' : 'Direct graph procedure.'}) Docs: ${docsBase}${entry.docPath ?? ''}`,
		),
		mode,
		...(cypher ? { cypher } : {}),
		docsUrl: `${docsBase}${entry.docPath ?? ''}`,
		fields,
	});
}

// Stable order: directs first (the procedures), then flows, alphabetical by id within each.
recipes.sort((a, b) =>
	a.mode === b.mode ? a.id.localeCompare(b.id) : a.mode === 'direct' ? -1 : 1,
);

const header = `// SPDX-License-Identifier: MIT
// GENERATED FILE - do not edit by hand.
// Source: the Whisper graph catalog (catalog.json, schemaVersion ${catalog.schemaVersion ?? '?'}).
// Regenerate with: node scripts/generate-graph-catalog.mjs <path-to-catalog.json>
//
// ${recipes.filter((r) => r.mode === 'direct').length} direct graph procedures (run their Cypher via the graph query API) and
// ${recipes.filter((r) => r.mode === 'flow').length} multi-step flows (run by slug via the console gallery/run endpoint, SSE).
// Every recipe links its documentation page (docsUrl).

export type GraphRecipeMode = 'direct' | 'flow';

export interface GraphRecipeField {
	/** The n8n parameter name (unique across the node). */
	name: string;
	/** The wire name: the Cypher $parameter (direct) or the flow input/param name. */
	paramName: string;
	displayName: string;
	description: string;
	default: string | number;
	type: 'string' | 'number' | 'options';
	options?: string[];
	/** Which half of the flow-run body this field rides: entity 'inputs' or tuning 'params'. */
	target: 'inputs' | 'params';
	/** The flow's first entity input; also sent as the top-level 'value' key. */
	primary?: boolean;
}

export interface GraphRecipe {
	/** The catalog id; doubles as the n8n operation value and the flow slug. */
	id: string;
	name: string;
	action: string;
	description: string;
	mode: GraphRecipeMode;
	/** direct only: the exact catalog Cypher, run as-is with bound $parameters. */
	cypher?: string;
	/** The recipe's documentation page. */
	docsUrl: string;
	fields: GraphRecipeField[];
}

export const GRAPH_RECIPES: GraphRecipe[] = `;

// Plain JSON is valid TypeScript for a literal: no transformation, no escaping risk.
const out = header + JSON.stringify(recipes, null, '\t') + ';\n';
const root = fileURLToPath(new URL('..', import.meta.url));
const dest = join(root, 'nodes', 'Whisper', 'GraphCatalog.ts');
writeFileSync(dest, out);
console.log(`wrote ${dest}: ${recipes.length} recipes (${recipes.filter((r) => r.mode === 'direct').length} direct, ${recipes.filter((r) => r.mode === 'flow').length} flow)`);
