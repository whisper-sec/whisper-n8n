import { NodeConnectionTypes, type INodeType, type INodeTypeDescription } from 'n8n-workflow';

/**
 * Whisper - verify agent IPv6 identities and read their public registry data.
 *
 * Declarative-style node: every operation is a plain GET against Whisper's public,
 * keyless identity API at https://rdap.whisper.online. There are no credentials -
 * the API is anonymous and read-only. The key-gated DoH resolver (/dns-query) is
 * intentionally not exposed here; it would be a broken keyless operation.
 */
export class Whisper implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Whisper',
		name: 'whisper',
		icon: { light: 'file:whisper.svg', dark: 'file:whisper.dark.svg' },
		group: ['input'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description:
			'Verify Whisper agent IPv6 identities and read their public RDAP record, transparency log, and inbound lookups. Keyless - no credentials required.',
		defaults: {
			name: 'Whisper',
		},
		// Usable as an AI Agent tool: an agent can check "is this address who it claims to be?"
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		// Keyless public API - this node declares no credentials.
		requestDefaults: {
			baseURL: 'https://rdap.whisper.online',
			headers: {
				// Liberal in what we accept (Postel): the RDAP record is served as
				// application/rdap+json, the other three as application/json. Asking for
				// only application/json makes the RDAP endpoint answer 406 Not Acceptable.
				Accept: 'application/rdap+json, application/json;q=0.9, */*;q=0.1',
			},
		},
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Verify Identity',
						value: 'verify',
						action: 'Verify an agent identity',
						description:
							'Return the verdict for an IPv6 address: whether it is a genuine Whisper agent, plus fqdn, operator, tenant, dane_ok, jws_ok and the DNS/DANE evidence',
						routing: {
							request: {
								method: 'GET',
								url: '/verify-identity',
								qs: {
									ip: '={{$parameter.address}}',
								},
							},
						},
					},
					{
						name: 'Get RDAP Record',
						value: 'rdap',
						action: 'Get the RDAP record',
						description:
							'Fetch the RFC 9083 RDAP registry record for an agent IPv6 identity (returns an RDAP 404 error object if the address anchors no Whisper identity)',
						routing: {
							request: {
								method: 'GET',
								url: '=/ip/{{$parameter.address}}',
							},
						},
					},
					{
						name: 'Get Transparency Log',
						value: 'transparency',
						action: 'Get the transparency log',
						description:
							'Fetch the hash-chained, signed issuance history for an identity, including the append-only ledger inclusion proof',
						routing: {
							request: {
								method: 'GET',
								url: '=/ip/{{$parameter.address}}/transparency',
							},
						},
					},
					{
						name: 'Get Inbound Lookups',
						value: 'lookups',
						action: 'Get inbound lookups',
						description:
							'Fetch the recent inbound lookup feed for an identity - who has been resolving or verifying this address',
						routing: {
							request: {
								method: 'GET',
								url: '=/ip/{{$parameter.address}}/lookups',
							},
						},
					},
				],
				default: 'verify',
			},
			{
				displayName: 'Agent IPv6 Address',
				name: 'address',
				type: 'string',
				required: true,
				default: '',
				placeholder: '2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478',
				description:
					"The Whisper agent's routable IPv6 /128 address to inspect. Whisper agent addresses live in the 2a04:2a01::/32 range (AS219419). Compressed or expanded IPv6 notation is accepted.",
			},
		],
	};
}
