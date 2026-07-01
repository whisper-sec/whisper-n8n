// SPDX-License-Identifier: MIT
import type {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

/**
 * Whisper API credential - the user's own Whisper key.
 *
 * There is NO baked-in secret here: the key belongs to the account holder. It is sent
 * to the Whisper control plane as the `X-API-Key` header (the same header the `whisper`
 * CLI uses). Create a key at https://whisper.online/platform.
 *
 * Only the keyed control operations (Register, Create Identity, List, Get Agent, Set
 * Policy, Get Logs, Revoke, Get Egress Config) require this credential. The keyless
 * convenience operations (Verify Identity, RDAP Lookup) read only public data and need
 * no credential at all.
 */
export class WhisperApi implements ICredentialType {
	name = 'whisperApi';

	displayName = 'Whisper API';

	documentationUrl = 'https://whisper.online/platform';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'Your Whisper API key (typically starts with whisper_live_). It is sent as the X-API-Key header to the control plane - never stored in the node. Create one at https://whisper.online/platform.',
		},
		{
			displayName: 'Control Plane URL',
			name: 'controlUrl',
			type: 'string',
			default: 'https://graph.whisper.security/api/query',
			description:
				'The Whisper control-plane endpoint (the one Cypher verb whisper.agents runs behind). Leave as the default unless you are pointing at a pre-production endpoint.',
		},
	];

	// Sent on every keyed request: the account holder's key as X-API-Key (Postel: one
	// header, exactly what the control plane expects - never a surprise).
	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				'X-API-Key': '={{$credentials.apiKey}}',
			},
		},
	};

	// A read-only, side-effect-free probe: list the caller's own agents. A 200 with an
	// ok envelope proves the key resolves and is scoped; a bad key returns a clear error.
	test: ICredentialTestRequest = {
		request: {
			url: '={{$credentials.controlUrl}}',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Accept: 'application/json',
			},
			body: {
				query: "CALL whisper.agents({op:'list', args:{kind:'agents'}})",
			},
		},
	};
}
