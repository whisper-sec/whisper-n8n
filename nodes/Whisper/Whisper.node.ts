// SPDX-License-Identifier: MIT
import {
	NodeConnectionTypes,
	NodeApiError,
	NodeOperationError,
	type IDataObject,
	type IExecuteFunctions,
	type IHttpRequestMethods,
	type INodeExecutionData,
	type INodeType,
	type INodeTypeDescription,
	type JsonObject,
} from 'n8n-workflow';

/**
 * Whisper - provision, govern and inspect Whisper agent identities from n8n.
 *
 * This node speaks the real Whisper control plane: the single Cypher verb
 * `whisper.agents({op:…})`, POSTed to https://graph.whisper.security/api/query with the
 * account holder's key in the `X-API-Key` header. The exact request/response contract is
 * documented in docs/packaging/CONTROL_API.md and mirrors the `whisper` CLI byte for byte.
 *
 * Keyed control operations (need a Whisper API credential): Register Agent, Create
 * Identity, List Agents, Get Agent, Set Policy, Get Logs, Revoke Agent, Get Egress Config.
 * Keyless convenience operations (no credential): Verify Identity, RDAP Lookup - these read
 * only the public identity data anyone can see.
 *
 * Robustness Principle (RFC 761): conservative in what we emit - every value is escaped
 * into the Cypher literal so nothing can break out of the map; liberal in what we accept -
 * the envelope decoder handles every wire shape the control plane returns, and by default
 * we NEVER surface the egress bearer / WireGuard key (bearer hygiene).
 */

const DEFAULT_CONTROL_URL = 'https://graph.whisper.security/api/query';
const RDAP_BASE = 'https://rdap.whisper.online';

// Operations that talk to the keyed control plane (require the Whisper API credential).
const KEYED_OPS = [
	'register',
	'identity',
	'list',
	'agent',
	'policy',
	'logs',
	'revoke',
	'connect',
];

// --- Cypher literal builder (ports the CLI's client/cypher.go exactly) ----------------
// Conservative-emit: a single quote is doubled (openCypher escaping) and a backslash is
// doubled, so a hostile value can never escape the surrounding '…' literal or the map.

function quoteCypher(s: string): string {
	return "'" + s.replace(/\\/g, '\\\\').replace(/'/g, "''") + "'";
}

function litCypher(v: unknown): string {
	if (v === null || v === undefined) return 'null';
	if (typeof v === 'string') return quoteCypher(v);
	if (typeof v === 'boolean') return v ? 'true' : 'false';
	if (typeof v === 'number') return String(v);
	if (Array.isArray(v)) return '[' + v.map(litCypher).join(',') + ']';
	if (typeof v === 'object') return cypherMap(v as IDataObject);
	return quoteCypher(String(v));
}

// Keys are sorted so the produced query is deterministic (stable for tests/caches/logs),
// exactly like the CLI's CypherMap.
function cypherMap(m: IDataObject): string {
	const keys = Object.keys(m).sort();
	if (keys.length === 0) return '{}';
	return '{' + keys.map((k) => k + ':' + litCypher(m[k])).join(',') + '}';
}

function buildAgentsQuery(op: string, args: IDataObject): string {
	const inner = Object.keys(args).length ? cypherMap(args) : '{}';
	return 'CALL whisper.agents({op:' + quoteCypher(op) + ', args:' + inner + '})';
}

// --- Envelope decoding (ports the CLI's client/envelope.go - liberal in what we accept) --

interface Problem {
	detail?: string;
	title?: string;
	type?: string;
	status?: number;
}

function problemMessage(err: Problem | undefined, status?: number): string {
	if (err) {
		if (err.detail) return err.detail;
		if (err.title) return err.title;
		if (err.type) return err.type;
	}
	return `control plane returned status ${status ?? '(unknown)'}`;
}

function zipRow(columns: string[], row: unknown[]): IDataObject {
	const out: IDataObject = {};
	for (let i = 0; i < columns.length; i++) out[columns[i]] = row[i] as IDataObject[string];
	return out;
}

// recordsFromResult turns a {columns, rows} result (or an already-shaped array) into a
// list of column-keyed objects - the ergonomic form we emit as n8n items.
function recordsFromResult(result: unknown): IDataObject[] {
	if (result === null || result === undefined) return [];
	if (Array.isArray(result)) return result as IDataObject[];
	const r = result as { columns?: string[]; rows?: unknown[] };
	if (Array.isArray(r.columns) && Array.isArray(r.rows)) {
		return r.rows.map((row) =>
			Array.isArray(row) ? zipRow(r.columns as string[], row) : (row as IDataObject),
		);
	}
	return [result as IDataObject];
}

/**
 * decodeEnvelope normalises any control-plane reply into a list of records, or throws a
 * clear error. It accepts (Postel):
 *  1. the live procedure-row wrapper: {columns, rows:[{op,ok,status,result,error,retry_after}]},
 *  2. the dev-guide shape: {ok, status, result, error},
 *  3. a bare {columns, rows:[[…]]} table, and
 *  4. a bare problem/object.
 */
function decodeEnvelope(body: unknown, httpStatus: number): IDataObject[] {
	const obj = body as IDataObject;

	// Shape 2: an explicit top-level ok flag.
	if (obj && typeof obj === 'object' && 'ok' in obj) {
		if (obj.ok === false) {
			throw { __whisperProblem: obj.error as Problem, status: (obj.status as number) ?? httpStatus };
		}
		return recordsFromResult(obj.result);
	}

	// Shapes 1 & 3: a {columns, rows} table.
	if (obj && Array.isArray((obj as { rows?: unknown[] }).rows)) {
		const rows = (obj as { rows: unknown[] }).rows;
		if (rows.length === 0) return [];
		const first = rows[0];
		// Shape 1: rows are per-op envelope objects {op,ok,status,result,error,…}.
		if (
			first &&
			typeof first === 'object' &&
			!Array.isArray(first) &&
			'ok' in (first as IDataObject)
		) {
			const env = first as IDataObject;
			if (env.ok === false) {
				throw {
					__whisperProblem: env.error as Problem,
					status: (env.status as number) ?? httpStatus,
				};
			}
			if (env.result !== undefined && env.result !== null) return recordsFromResult(env.result);
			return [env];
		}
		// Shape 3: positional rows against the outer columns.
		const columns = (obj as { columns?: string[] }).columns;
		if (Array.isArray(columns)) {
			return rows.map((row) =>
				Array.isArray(row) ? zipRow(columns, row) : (row as IDataObject),
			);
		}
		return rows as IDataObject[];
	}

	// Shape 4: a bare object → a single record.
	return obj ? [obj] : [];
}

// --- egress (op:connect) secret hygiene ----------------------------------------------
// The op:connect result carries the egress bearer (http_proxy / connection_string) and the
// WireGuard private key (client_private_key / wireguard_config). An n8n workflow variable or
// execution log must NEVER hold a live credential, so by default we emit only an ALLOWLIST of
// safe, identity fields - conservative in what we emit (Postel): a field we don't explicitly
// recognise is dropped, so a future server field can never leak. Advanced self-hosters who
// understand the exposure can opt into the raw envelope via "Include Raw Credentials".
const SAFE_CONNECT_KEYS = [
	'tier',
	'address',
	'addr128',
	'fqdn',
	'ptr',
	'state',
	'agent',
	'label',
	'verified',
];

function sanitizeConnect(rec: IDataObject, includeSecrets: boolean, selector: string): IDataObject {
	if (includeSecrets) return rec;
	const out: IDataObject = {};
	for (const k of SAFE_CONNECT_KEYS) {
		if (k in rec) out[k] = rec[k];
	}
	const agentArg = selector ? ` --agent ${selector}` : '';
	out.proxy_hint =
		`On the n8n host run:  whisper connect${agentArg}  ` +
		'- it prints a bearer-free local endpoint (socks5h://127.0.0.1:<port>). ' +
		'Point n8n HTTP_PROXY / an HTTP Request node at it and this agent’s traffic ' +
		'sources from its Whisper /128.';
	return out;
}

export class Whisper implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Whisper',
		name: 'whisper',
		icon: 'file:whisper.png',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description:
			'Provision, govern and inspect Whisper agent identities: register agents with routable IPv6 /128s, set DNS policy, read logs, get egress config, plus keyless identity verification and RDAP.',
		defaults: { name: 'Whisper' },
		// Usable as an AI Agent tool: an agent can register/verify/govern its own fleet.
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'whisperApi',
				required: true,
				// The keyless operations (verify, rdap) intentionally need no credential.
				displayOptions: { show: { operation: KEYED_OPS } },
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				default: 'list',
				options: [
					{
						name: 'Register Agent',
						value: 'register',
						action: 'Register a new agent with its own key',
						description:
							'Mint a brand-new agent with its own routable IPv6 /128 identity AND its own API key (op:register). The api_key is returned once - capture it.',
					},
					{
						name: 'Create Identity',
						value: 'identity',
						action: 'Create a routable identity for yourself',
						description:
							'Allocate a routable IPv6 /128 identity under your own tenant (op:identity). Returns the address, FQDN and PTR.',
					},
					{
						name: 'List Agents',
						value: 'list',
						action: 'List agents in your tenant',
						description: 'List the agents, identities or DNS records in your tenant (op:list).',
					},
					{
						name: 'Get Agent',
						value: 'agent',
						action: 'Get one agent and its counters',
						description:
							"Fetch one agent's detail and live counters by agent id or /128 address (op:agent).",
					},
					{
						name: 'Set Policy',
						value: 'policy',
						action: 'Set or read your resolver policy',
						description:
							'Set your per-tenant DNS resolver policy - a default action plus allow/deny lists (op:policy). With no entries and no default, it reads the current policy back.',
					},
					{
						name: 'Get Logs',
						value: 'logs',
						action: 'Query recent activity',
						description:
							'Query recent DNS / connection / allocation activity for your tenant (op:logs).',
					},
					{
						name: 'Revoke Agent',
						value: 'revoke',
						action: 'Revoke an agent entirely',
						description:
							"Fully revoke an agent - withdraw its /128, PTR, tokens and API key (op:revoke). Irreversible.",
					},
					{
						name: 'Get Egress Config',
						value: 'connect',
						action: 'Get an agent egress config',
						description:
							"Get an agent's egress connect details bound to its /128 (op:connect). Secret proxy credentials are stripped by default - run `whisper connect` on the n8n host for actual egress.",
					},
					{
						name: 'Verify Identity',
						value: 'verify',
						action: 'Verify an agent identity keyless',
						description:
							'Return the trust verdict for an IPv6 address: whether it is a genuine Whisper agent, plus fqdn, operator, tenant, dane_ok, jws_ok and the evidence. Keyless.',
					},
					{
						name: 'RDAP Lookup',
						value: 'rdap',
						action: 'Look up the public RDAP record keyless',
						description:
							'Fetch the RFC 9083 RDAP registry record for an agent IPv6 identity (optionally its transparency log or inbound lookups). Keyless.',
					},
				],
			},

			// --- Register / Create Identity -------------------------------------------------
			{
				displayName: 'Name',
				name: 'label',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'scout',
				description:
					'The human name for the agent/identity (maps to the server label surfaced by List and RDAP)',
				displayOptions: { show: { operation: ['register', 'identity'] } },
			},
			{
				displayName: 'Contact Email',
				name: 'contactEmail',
				type: 'string',
				default: '',
				placeholder: 'you@example.com',
				description: 'Optional public contact email, opt-in - surfaced in the RDAP record',
				displayOptions: { show: { operation: ['register', 'identity'] } },
			},

			// --- List -----------------------------------------------------------------------
			{
				displayName: 'Kind',
				name: 'kind',
				type: 'options',
				default: 'agents',
				options: [
					{ name: 'Agents', value: 'agents' },
					{ name: 'Identities', value: 'identities' },
					{ name: 'Records', value: 'records' },
				],
				description: 'What to list, confined to your tenant',
				displayOptions: { show: { operation: ['list'] } },
			},

			// --- Get Agent / Revoke (selector) ---------------------------------------------
			{
				displayName: 'Agent',
				name: 'selector',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'agent-ae3b051ff3bf7f478  or  2a04:2a01:…',
				description: 'Select the agent by its id or its /128 address',
				displayOptions: { show: { operation: ['agent', 'revoke'] } },
			},

			// --- Set Policy -----------------------------------------------------------------
			{
				displayName: 'Default Action',
				name: 'policyDefault',
				type: 'options',
				default: '',
				options: [
					{ name: 'Leave Unchanged (read current policy)', value: '' },
					{ name: 'Allow', value: 'allow' },
					{ name: 'Deny', value: 'deny' },
				],
				description:
					'The default action for names not on a list. Leave unchanged (with empty lists) to just read the current policy.',
				displayOptions: { show: { operation: ['policy'] } },
			},
			{
				displayName: 'Block List',
				name: 'block',
				type: 'string',
				default: '',
				placeholder: 'ads.example.com, tracker.example.net',
				description:
					'Names to block, comma- or newline-separated (max 1000 combined with the allow list)',
				displayOptions: { show: { operation: ['policy'] } },
			},
			{
				displayName: 'Allow List',
				name: 'allow',
				type: 'string',
				default: '',
				placeholder: 'api.openai.com, github.com',
				description: 'Names to allow, comma- or newline-separated',
				displayOptions: { show: { operation: ['policy'] } },
			},

			// --- Get Logs -------------------------------------------------------------------
			{
				displayName: 'Agent',
				name: 'logsAgent',
				type: 'string',
				default: '',
				placeholder: 'agent id or /128 (blank = all agents)',
				description: 'Narrow to one agent (id or /128 address); leave blank for the whole tenant',
				displayOptions: { show: { operation: ['logs'] } },
			},
			{
				displayName: 'Kind',
				name: 'logsKind',
				type: 'options',
				default: 'all',
				options: [
					{ name: 'All', value: 'all' },
					{ name: 'DNS', value: 'dns' },
					{ name: 'Connections', value: 'conn' },
					{ name: 'Allocations', value: 'alloc' },
				],
				description: 'Which event kind to return (All interleaves every kind)',
				displayOptions: { show: { operation: ['logs'] } },
			},
			{
				displayName: 'From',
				name: 'from',
				type: 'string',
				default: '',
				placeholder: '-1h  |  epoch-ms  |  RFC-3339',
				description: 'Window start - a relative offset (e.g. -1h), epoch-ms, or RFC-3339 timestamp',
				displayOptions: { show: { operation: ['logs'] } },
			},
			{
				displayName: 'To',
				name: 'to',
				type: 'string',
				default: '',
				placeholder: 'now  |  epoch-ms  |  RFC-3339',
				description: 'Window end',
				displayOptions: { show: { operation: ['logs'] } },
			},
			{
				displayName: 'Limit',
				name: 'limit',
				type: 'number',
				typeOptions: { minValue: 1, maxValue: 10000 },
				default: 1000,
				description: 'Max rows to return (cap 10000)',
				displayOptions: { show: { operation: ['logs'] } },
			},

			// --- Get Egress Config ----------------------------------------------------------
			{
				displayName: 'Agent',
				name: 'connectAgent',
				type: 'string',
				default: '',
				placeholder: 'agent id or /128 (blank = most recent)',
				description:
					'Bind the egress to this agent (id or /128). Blank uses the server reuse-most-recent default.',
				displayOptions: { show: { operation: ['connect'] } },
			},
			{
				displayName: 'Tier',
				name: 'tier',
				type: 'options',
				default: 'socks5',
				options: [
					{ name: 'SOCKS5 (Tier 1.5, default)', value: 'socks5' },
					{ name: 'WireGuard (Tier 1, routed /128)', value: 'wireguard' },
					{ name: 'AnyIP (Tier 1.5)', value: 'anyip' },
				],
				description: 'The egress tier to request',
				displayOptions: { show: { operation: ['connect'] } },
			},
			{
				displayName: 'Include Raw Credentials',
				name: 'includeSecrets',
				type: 'boolean',
				default: false,
				description:
					'Whether to include the raw egress bearer / WireGuard key in the output. Advanced and unsafe: these are live credentials that would appear in the workflow data and execution logs. Leave off; run `whisper connect` on the host for actual egress.',
				displayOptions: { show: { operation: ['connect'] } },
			},

			// --- Verify / RDAP (keyless) ---------------------------------------------------
			{
				displayName: 'Agent IPv6 Address',
				name: 'address',
				type: 'string',
				required: true,
				default: '',
				placeholder: '2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478',
				description:
					"The Whisper agent's routable IPv6 /128 to inspect. Whisper agent addresses live in 2a04:2a01::/32 (AS219419). Compressed or expanded notation is accepted.",
				displayOptions: { show: { operation: ['verify', 'rdap'] } },
			},
			{
				displayName: 'Resource',
				name: 'rdapResource',
				type: 'options',
				default: 'record',
				options: [
					{ name: 'RDAP Record', value: 'record' },
					{ name: 'Transparency Log', value: 'transparency' },
					{ name: 'Inbound Lookups', value: 'lookups' },
				],
				description: 'Which public object to fetch for the address',
				displayOptions: { show: { operation: ['rdap'] } },
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const iterations = Math.max(items.length, 1);

		for (let i = 0; i < iterations; i++) {
			try {
				const operation = this.getNodeParameter('operation', i) as string;
				let records: IDataObject[];

				if (operation === 'verify' || operation === 'rdap') {
					records = await runKeyless.call(this, operation, i);
				} else {
					records = await runKeyed.call(this, operation, i);
				}

				for (const rec of records) {
					returnData.push({ json: rec, pairedItem: { item: i } });
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: (error as Error).message ?? String(error) },
						pairedItem: { item: i },
					});
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}

// runKeyed builds the args for a keyed control op, POSTs the Cypher verb with the user's
// key (via httpRequestWithAuthentication → X-API-Key), and decodes the envelope.
async function runKeyed(
	this: IExecuteFunctions,
	operation: string,
	i: number,
): Promise<IDataObject[]> {
	const args: IDataObject = {};
	let selector = '';

	switch (operation) {
		case 'register':
		case 'identity': {
			const label = (this.getNodeParameter('label', i) as string).trim();
			if (!label) {
				throw new NodeOperationError(this.getNode(), 'A name is required to create an agent.', {
					itemIndex: i,
				});
			}
			args.label = label;
			const email = (this.getNodeParameter('contactEmail', i, '') as string).trim();
			if (email) args.contact_email = email;
			break;
		}
		case 'list': {
			args.kind = this.getNodeParameter('kind', i) as string;
			break;
		}
		case 'agent': {
			selector = (this.getNodeParameter('selector', i) as string).trim();
			if (!selector) {
				throw new NodeOperationError(this.getNode(), 'An agent id or /128 address is required.', {
					itemIndex: i,
				});
			}
			// Liberal-accept, mirroring the CLI: a colon means a /128 address, else an id.
			if (selector.includes(':')) args.address = selector;
			else args.agent = selector;
			break;
		}
		case 'revoke': {
			selector = (this.getNodeParameter('selector', i) as string).trim();
			if (!selector) {
				throw new NodeOperationError(this.getNode(), 'An agent id or /128 address is required.', {
					itemIndex: i,
				});
			}
			args.agent = selector;
			break;
		}
		case 'policy': {
			const def = (this.getNodeParameter('policyDefault', i, '') as string).trim();
			if (def) args.default = def;
			const block = splitList(this.getNodeParameter('block', i, '') as string);
			if (block.length) args.block = block;
			const allow = splitList(this.getNodeParameter('allow', i, '') as string);
			if (allow.length) args.allow = allow;
			break;
		}
		case 'logs': {
			const agent = (this.getNodeParameter('logsAgent', i, '') as string).trim();
			if (agent) args.agent = agent;
			const kind = this.getNodeParameter('logsKind', i, 'all') as string;
			if (kind && kind !== 'all') args.kind = kind;
			const from = (this.getNodeParameter('from', i, '') as string).trim();
			if (from) args.from = from;
			const to = (this.getNodeParameter('to', i, '') as string).trim();
			if (to) args.to = to;
			const limit = this.getNodeParameter('limit', i, 1000) as number;
			if (limit > 0) args.limit = limit;
			break;
		}
		case 'connect': {
			selector = (this.getNodeParameter('connectAgent', i, '') as string).trim();
			if (selector) args.agent = selector;
			const tier = this.getNodeParameter('tier', i, 'socks5') as string;
			if (tier) args.tier = tier;
			break;
		}
		default:
			throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`, {
				itemIndex: i,
			});
	}

	const creds = await this.getCredentials('whisperApi');
	const controlUrl = ((creds.controlUrl as string) || DEFAULT_CONTROL_URL).trim();
	const query = buildAgentsQuery(operation, args);

	let response: unknown;
	try {
		response = await this.helpers.httpRequestWithAuthentication.call(this, 'whisperApi', {
			method: 'POST' as IHttpRequestMethods,
			url: controlUrl,
			headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
			body: { query },
			json: true,
		});
	} catch (error) {
		throw new NodeApiError(this.getNode(), error as JsonObject, { itemIndex: i });
	}

	let records: IDataObject[];
	try {
		records = decodeEnvelope(asObject(response), 200);
	} catch (problem) {
		const p = problem as { __whisperProblem?: Problem; status?: number };
		if (p && p.__whisperProblem !== undefined) {
			throw new NodeOperationError(this.getNode(), problemMessage(p.__whisperProblem, p.status), {
				itemIndex: i,
			});
		}
		throw problem;
	}

	if (operation === 'connect') {
		const includeSecrets = this.getNodeParameter('includeSecrets', i, false) as boolean;
		return records.map((r) => sanitizeConnect(r, includeSecrets, selector));
	}
	return records;
}

// runKeyless handles the public, no-credential surfaces (rdap.whisper.online).
async function runKeyless(
	this: IExecuteFunctions,
	operation: string,
	i: number,
): Promise<IDataObject[]> {
	const address = (this.getNodeParameter('address', i) as string).trim();
	if (!address) {
		throw new NodeOperationError(this.getNode(), 'An agent IPv6 address is required.', {
			itemIndex: i,
		});
	}

	let url: string;
	let accept: string;
	if (operation === 'verify') {
		url = `${RDAP_BASE}/verify-identity?ip=${encodeURIComponent(address)}`;
		accept = 'application/json';
	} else {
		const resource = this.getNodeParameter('rdapResource', i, 'record') as string;
		const suffix = resource === 'record' ? '' : `/${resource}`;
		url = `${RDAP_BASE}/ip/${encodeURIComponent(address)}${suffix}`;
		accept = 'application/rdap+json, application/json;q=0.9, */*;q=0.1';
	}

	let response: unknown;
	try {
		response = await this.helpers.httpRequest({
			method: 'GET' as IHttpRequestMethods,
			url,
			headers: { Accept: accept },
			json: true,
		});
	} catch (error) {
		throw new NodeApiError(this.getNode(), error as JsonObject, { itemIndex: i });
	}
	return [asObject(response)];
}

// asObject is liberal in what it accepts: a parsed object passes through; a JSON string is
// parsed; anything else is wrapped so we always emit a usable object (never crash on a
// content-type the HTTP layer didn't auto-parse).
function asObject(response: unknown): IDataObject {
	if (response && typeof response === 'object') return response as IDataObject;
	if (typeof response === 'string') {
		try {
			return JSON.parse(response) as IDataObject;
		} catch {
			return { body: response };
		}
	}
	return { value: response as IDataObject[string] };
}

// splitList parses a comma/newline-separated field into a trimmed, non-empty list.
function splitList(raw: string): string[] {
	return (raw || '')
		.split(/[\n,]+/)
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
}
