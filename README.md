# n8n-nodes-whisper

Verify [Whisper](https://whisper.online/platform) agent IPv6 identities from an n8n
workflow - **keyless, no credentials.**

## Install

In n8n: **Settings → Community Nodes → Install**, then enter:

```
n8n-nodes-whisper
```

That's it. The node needs no API key and no account - it wraps Whisper's public,
anonymous identity API.

> Published on npm as **`n8n-nodes-whisper`** (the `n8n-nodes-` prefix is what makes it
> discoverable as a community node). If that exact name is ever unavailable, the scoped
> fallback is **`@whisper-sec/n8n-nodes-whisper`** - install whichever this repo publishes.

## What it does

Every Whisper agent has a routable IPv6 `/128` in `2a04:2a01::/32` (AS219419) whose
reverse-DNS, DANE, and signed transparency log prove *who it is*. This node reads that
public identity data.

| Operation | Endpoint | Returns |
|---|---|---|
| **Verify Identity** | `GET /verify-identity?ip=…` | Verdict: `is_whisper_agent`, `fqdn`, `operator`, `tenant`, `dane_ok`, `jws_ok`, evidence |
| **Get RDAP Record** | `GET /ip/{address}` | RFC 9083 RDAP registry record |
| **Get Transparency Log** | `GET /ip/{address}/transparency` | Hash-chained, signed issuance history + ledger inclusion proof |
| **Get Inbound Lookups** | `GET /ip/{address}/lookups` | Recent inbound lookup feed (who has been checking this identity) |

All four are read-only `GET`s against `https://rdap.whisper.online`. The key-gated DoH
resolver (`/dns-query`) is intentionally **not** exposed - it would be a broken keyless
operation.

## Parameters

- **Operation** - one of the four above.
- **Agent IPv6 Address** - the `/128` to inspect, e.g.
  `2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478`. Compressed or expanded notation both work.

## Example - Verify Identity

Input address `2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478` returns:

```json
{
  "is_whisper_agent": true,
  "fqdn": "…agents.whisper.online",
  "operator": "…",
  "tenant": "…",
  "dane_ok": true,
  "jws_ok": true,
  "evidence": { "address": "2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478", "ptr": "…ip6.arpa", "posture": "tier1.5" }
}
```

A non-agent address returns `{"is_whisper_agent": false, …}` with a plain-language
`detail`. (For **Get RDAP Record**, an address that anchors no identity returns the
standard RDAP `404` error object, per RFC 9083.)

## Use as an AI tool

This node is enabled as an **AI Agent tool** (`usableAsTool`). Drop it onto an AI Agent
node and your agent can answer *"is this address who it claims to be?"* on its own - the
frictionless-agent-identity story, inside n8n.

## Links

- Platform: https://whisper.online/platform
- RDAP + registry rules: https://rdap.whisper.online · https://nic.whisper.online
- CLI (MIT): https://github.com/whisper-sec/whisper-cli · install: https://get.whisper.online

## License

[MIT](LICENSE.md) © viaGraph B.V. (Whisper Security)
