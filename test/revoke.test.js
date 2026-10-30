// SPDX-License-Identifier: MIT
// Revoke Agent: every way the control plane says "nothing was revoked" must fail the item
// with that message, keyed on the NOT_FOUND code (never on a bare 404), and never pass as
// a successful revoke. Runs against the built node in dist/ (npm test builds first).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { NodeApiError, NodeOperationError } = require('n8n-workflow');
const { Whisper } = require('../dist/nodes/Whisper/Whisper.node.js');
const env = require('../dist/nodes/Whisper/envelope.js');

const ADDR = '2a04:2a01::1';
const SERVER_MSG =
	"nothing was revoked: no agent of yours matches '" +
	ADDR +
	"'. If you revoked it before, there is nothing left to revoke";

function wrap(row) {
	return {
		columns: ['op', 'ok', 'status', 'result', 'error', 'retry_after', 'elapsed_ms'],
		rows: [row],
	};
}

// The front door today: HTTP 200, the refusal inside the row.
const IN_ROW_NOT_FOUND = wrap({
	op: 'revoke',
	ok: false,
	status: 404,
	result: null,
	error: { code: 'NOT_FOUND', message: SERVER_MSG, retryable: false },
	retry_after: null,
	elapsed_ms: 64,
});

// An older plane: an ok row whose status says not_found.
const OLD_ROW_NOT_FOUND = wrap({
	op: 'revoke',
	ok: true,
	status: 200,
	result: { columns: ['agent', 'status'], rows: [[ADDR, 'not_found']] },
	error: null,
});

const OLD_ITEM_NOT_FOUND = wrap({
	op: 'revoke',
	ok: true,
	status: 200,
	result: [{ item: { agent: ADDR, status: 'not_found' } }],
	error: null,
});

const REVOKED = wrap({
	op: 'revoke',
	ok: true,
	status: 200,
	result: { columns: ['agent', 'status'], rows: [['a0000000000000001', 'revoked']] },
	error: null,
});

function ctx({ reply, throws, continueOnFail = false, operation = 'revoke' }) {
	const params = { resource: 'control', operation, selector: ADDR };
	return {
		getInputData: () => [{ json: {} }],
		getNodeParameter: (name, _i, fallback) => (name in params ? params[name] : fallback),
		getNode: () => ({ name: 'Whisper', type: 'n8n-nodes-whisper.whisper', typeVersion: 1, parameters: {} }),
		getCredentials: async () => ({ apiKey: 'redacted' }),
		continueOnFail: () => continueOnFail,
		helpers: {
			httpRequestWithAuthentication: async () => {
				if (throws) throw throws;
				return reply;
			},
		},
	};
}

async function run(opts) {
	return new Whisper().execute.call(ctx(opts));
}

async function assertNothingRevoked(opts, expectServerMessage) {
	await assert.rejects(run(opts), (err) => {
		assert.ok(err instanceof NodeOperationError, `expected NodeOperationError, got ${err && err.constructor.name}`);
		assert.match(err.message, /nothing was revoked/i);
		assert.match(err.message, /Not retryable/);
		assert.match(err.message, /Retry On Fail/);
		if (expectServerMessage) assert.ok(err.message.startsWith(SERVER_MSG), err.message);
		assert.match(String(err.description), /NOT_FOUND/);
		return true;
	});
}

test('front door in-row NOT_FOUND fails the item as nothing revoked, with the server message', async () => {
	await assertNothingRevoked({ reply: IN_ROW_NOT_FOUND }, true);
});

test('older ok row with status not_found fails the item as nothing revoked', async () => {
	await assertNothingRevoked({ reply: OLD_ROW_NOT_FOUND }, false);
});

test('older ok row with status not_found under item fails the item as nothing revoked', async () => {
	await assertNothingRevoked({ reply: OLD_ITEM_NOT_FOUND }, false);
});

test('flat NOT_FOUND envelope sent as a real HTTP 404 is read from the error body', async () => {
	const httpErr = Object.assign(new Error('Request failed with status code 404'), {
		response: {
			status: 404,
			body: { ok: false, status: 404, error: { code: 'NOT_FOUND', message: SERVER_MSG, retryable: false } },
		},
	});
	await assertNothingRevoked({ throws: httpErr }, true);
});

test('a bare HTTP 404 with no NOT_FOUND code is not read as nothing revoked', async () => {
	const httpErr = Object.assign(new Error('Request failed with status code 404'), {
		response: { status: 404, body: '<html>Not Found</html>' },
	});
	await assert.rejects(run({ throws: httpErr }), (err) => {
		assert.ok(err instanceof NodeApiError);
		assert.doesNotMatch(err.message, /nothing was revoked/i);
		return true;
	});
});

test('an in-row 404 without the NOT_FOUND code stays a plain refusal', async () => {
	const reply = wrap({ op: 'revoke', ok: false, status: 404, result: null, error: { message: 'no route' } });
	await assert.rejects(run({ reply }), (err) => {
		assert.ok(err instanceof NodeOperationError);
		assert.equal(err.message, 'no route');
		return true;
	});
});

test('NOT_FOUND carried on a 403 is not trusted as nothing revoked', async () => {
	const reply = wrap({
		op: 'revoke',
		ok: false,
		status: 403,
		result: null,
		error: { code: 'NOT_FOUND', message: 'scope dns:identity required' },
	});
	await assert.rejects(run({ reply }), (err) => {
		assert.equal(err.message, 'scope dns:identity required');
		return true;
	});
});

test('other refusals now surface the server message field', async () => {
	const reply = wrap({
		op: 'revoke',
		ok: false,
		status: 403,
		result: null,
		error: { code: 'FORBIDDEN', message: 'key lacks scope dns:identity', retryable: false },
	});
	await assert.rejects(run({ reply }), (err) => {
		assert.equal(err.message, 'key lacks scope dns:identity');
		assert.match(String(err.description), /FORBIDDEN/);
		return true;
	});
});

test('a real revoke still returns the revoked record', async () => {
	const out = await run({ reply: REVOKED });
	assert.deepEqual(out[0].map((x) => x.json), [{ agent: 'a0000000000000001', status: 'revoked' }]);
});

test('Continue On Fail emits the nothing-revoked message as an error item, not a success', async () => {
	const out = await run({ reply: OLD_ROW_NOT_FOUND, continueOnFail: true });
	assert.equal(out[0].length, 1);
	assert.match(out[0][0].json.error, /nothing was revoked/i);
	assert.equal(out[0][0].json.status, undefined);
});

test('controlProblem keys on the code and marks NOT_FOUND not retryable', () => {
	assert.equal(env.controlProblem({ code: 'NOT_FOUND', retryable: true }, 404).notFound, true);
	assert.equal(env.controlProblem({ code: 'NOT_FOUND', retryable: true }, 404).retryable, false);
	assert.equal(env.controlProblem({ code: 'not_found' }, undefined).notFound, true);
	assert.equal(env.controlProblem({ message: 'x' }, 404).notFound, false);
	assert.equal(env.controlProblem({ code: 'NOT_FOUND' }, 403).notFound, false);
});

test('revokeMatchedNothing reads the record and the item shapes only', () => {
	assert.ok(env.revokeMatchedNothing([{ agent: 'a', status: 'not_found' }]));
	assert.ok(env.revokeMatchedNothing([{ item: { agent: 'a', status: 'NOT_FOUND' } }]));
	assert.equal(env.revokeMatchedNothing([{ agent: 'a', status: 'revoked' }]), undefined);
	assert.equal(env.revokeMatchedNothing([]), undefined);
});
