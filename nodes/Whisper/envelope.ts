// SPDX-License-Identifier: MIT
import type { IDataObject } from 'n8n-workflow';

// --- Envelope decoding (ports the CLI's client/envelope.go - liberal in what we accept) --
// Kept free of any n8n runtime import so it can be unit-tested on its own.

export interface Problem {
	code?: string;
	message?: string;
	detail?: string;
	title?: string;
	type?: string;
	status?: number;
	retryable?: boolean;
}

/** A control-plane refusal, reduced to what a workflow needs to act on it. */
export interface ControlProblem {
	message: string;
	code?: string;
	status?: number;
	retryable?: boolean;
	/** The plane understood the call and found nothing of yours to act on. */
	notFound: boolean;
}

function text(v: unknown): string | undefined {
	return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

export function problemMessage(err: Problem | undefined, status?: number): string {
	if (err && typeof err === 'object') {
		const m = text(err.message) ?? text(err.detail) ?? text(err.title) ?? text(err.type);
		if (m) return m;
	}
	return `control plane returned status ${status ?? '(unknown)'}`;
}

/**
 * controlProblem reads a refusal's code, status and retryability. "Not found" is decided by
 * the server's NOT_FOUND code, never by a bare 404: a 404 can also be a wrong URL or a proxy.
 * The code must not be contradicted by the status (NOT_FOUND on a 403 is not trusted).
 */
export function controlProblem(err: Problem | undefined, status?: number): ControlProblem {
	const code = err && typeof err === 'object' ? text(err.code) : undefined;
	const retryable = err && typeof err.retryable === 'boolean' ? err.retryable : undefined;
	// The code decides; a status that contradicts it (NOT_FOUND on a 403) is not trusted.
	const statusAgrees = status === undefined || status === null || status === 0 || status === 404;
	const notFound = code !== undefined && code.toUpperCase() === 'NOT_FOUND' && statusAgrees;
	return {
		message: problemMessage(err, status),
		code,
		status,
		retryable: notFound ? false : retryable,
		notFound,
	};
}

/**
 * revokeMatchedNothing reports whether a successful revoke row still says nothing was
 * revoked: older control planes answered ok with `status: "not_found"`, either on the
 * record itself or under `item`. Returns the row that carries it, or undefined.
 */
export function revokeMatchedNothing(records: IDataObject[]): IDataObject | undefined {
	for (const rec of records) {
		if (!rec || typeof rec !== 'object') continue;
		const item = rec.item;
		const row = item && typeof item === 'object' && !Array.isArray(item) ? (item as IDataObject) : rec;
		const status = text(row.status) ?? text(rec.status);
		if (status && status.toLowerCase() === 'not_found') return row;
	}
	return undefined;
}

function zipRow(columns: string[], row: unknown[]): IDataObject {
	const out: IDataObject = {};
	for (let i = 0; i < columns.length; i++) out[columns[i]] = row[i] as IDataObject[string];
	return out;
}

// recordsFromResult turns a {columns, rows} result (or an already-shaped array) into a
// list of column-keyed objects - the ergonomic form we emit as n8n items.
export function recordsFromResult(result: unknown): IDataObject[] {
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

/** Thrown by decodeEnvelope when the plane answered ok:false. */
export interface EnvelopeProblem {
	__whisperProblem: Problem;
	status?: number;
}

/**
 * decodeEnvelope normalises any control-plane reply into a list of records, or throws an
 * EnvelopeProblem. It accepts (Postel):
 *  1. the live procedure-row wrapper: {columns, rows:[{op,ok,status,result,error,retry_after}]},
 *     where a refusal arrives as HTTP 200 with ok:false and the status inside the row,
 *  2. the dev-guide shape: {ok, status, result, error}, also as a non-2xx body,
 *  3. a bare {columns, rows:[[…]]} table, and
 *  4. a bare problem/object.
 */
export function decodeEnvelope(body: unknown, httpStatus: number): IDataObject[] {
	const obj = body as IDataObject;

	// Shape 2: an explicit top-level ok flag.
	if (obj && typeof obj === 'object' && 'ok' in obj) {
		if (obj.ok === false) {
			throw {
				__whisperProblem: (obj.error as Problem) ?? {},
				status: (obj.status as number) ?? httpStatus,
			} as EnvelopeProblem;
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
					__whisperProblem: (env.error as Problem) ?? {},
					status: (env.status as number) ?? httpStatus,
				} as EnvelopeProblem;
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

/** The text a workflow sees when a revoke matched nothing, in both wire shapes. */
export function nothingRevokedMessage(serverMessage: string | undefined, selector: string): string {
	let base =
		serverMessage ??
		`no agent of yours matches '${selector}'. If you revoked it before, there is nothing left to revoke`;
	base = base.replace(/[.\s]+$/, '');
	if (!/nothing was revoked/i.test(base)) base = `nothing was revoked: ${base}`;
	return `${base}. Not retryable: Retry On Fail gets the same answer. List Agents shows what is left.`;
}
