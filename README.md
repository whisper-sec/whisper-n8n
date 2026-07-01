# n8n-nodes-whisper

Provision, govern and inspect [Whisper](https://whisper.online/platform) agent identities
from an n8n workflow - give an agent a real, routable IPv6 identity, set its DNS policy,
read its activity, and verify any agent, all with your own Whisper key.

## Install

In n8n: **Settings → Community Nodes → Install**, then enter:

```
n8n-nodes-whisper
```

## Credential - bring your own key

The control operations use a **Whisper API** credential: your own key (typically
`whisper_live_…`). Create one at <https://whisper.online/platform>, then in n8n add a
**Whisper API** credential and paste the key. It is sent as the `X-API-Key` header to the
control plane - the same header the [`whisper` CLI](https://github.com/whisper-sec/whisper-cli)
uses - and nothing is baked into the node.

The two **keyless** operations (Verify Identity, RDAP Lookup) read only public data and
need no credential at all.

## Operations

| Operation | Key | What it does |
|---|:--:|---|
| **Register Agent** | ✔ | Mint a brand-new agent with its own routable IPv6 `/128` **and** its own API key (returned once). |
| **Create Identity** | ✔ | Allocate a routable `/128` identity under your own tenant. |
| **List Agents** | ✔ | List the agents / identities / records in your tenant. |
| **Get Agent** | ✔ | One agent's detail + live counters, by id or `/128`. |
| **Set Policy** | ✔ | Set your per-tenant DNS resolver policy (default action + allow/deny lists). With no changes, reads the current policy. |
| **Get Logs** | ✔ | Recent DNS / connection / allocation activity. |
| **Revoke Agent** | ✔ | Fully revoke an agent - withdraw its `/128`, PTR, tokens and key. Irreversible. |
| **Get Egress Config** | ✔ | An agent's egress connect details bound to its `/128` (see **Egress** below). |
| **Verify Identity** | - | Trust verdict for an address: `is_whisper_agent`, `fqdn`, `operator`, `tenant`, `dane_ok`, `jws_ok`, evidence. |
| **RDAP Lookup** | - | RFC 9083 RDAP record (or its transparency log / inbound lookups). |

Every control operation is the one Cypher verb `whisper.agents({op:…})`, POSTed to the
control plane. The exact request/response contract is documented in
[`CONTROL_API.md`](https://github.com/whisper-sec/whisper-n8n/blob/main/CONTROL_API.md).

## Egress - run your n8n agents *on* the Whisper network

Every Whisper agent has a routable IPv6 `/128` in `2a04:2a01::/32` (AS219419). To make an
n8n HTTP Request actually **leave from that `/128`** (so the destination sees the agent's
identity, and reverse-DNS/DANE prove who it is), run the egress locally on the n8n host -
the credential stays on the host and never enters the workflow:

1. **Install the CLI on the n8n host** (once):

   ```bash
   curl -fsSL https://get.whisper.online | sh
   ```

2. **Bring up the egress** bound to your agent's `/128`. It prints one bearer-free local
   proxy string and holds it open:

   ```bash
   whisper connect --agent <agent-id-or-/128>
   # → socks5h://127.0.0.1:1080
   ```

3. **Point n8n at it.** Either set the proxy for the whole n8n process:

   ```bash
   export HTTP_PROXY=http://127.0.0.1:1080
   export HTTPS_PROXY=http://127.0.0.1:1080
   # then start n8n
   ```

   …or set **Proxy** on an individual **HTTP Request** node to
   `socks5h://127.0.0.1:1080`. Every request through it now sources from the agent's
   Whisper `/128`.

Use **Get Egress Config** in a workflow to fetch which agent/`/128` you'd egress as (the
raw proxy bearer / WireGuard key is stripped by default - enable *Include Raw Credentials*
only if you understand it will appear in the workflow data). Actual egress always runs via
`whisper connect` on the host, per the steps above.

## Use as an AI tool

This node is enabled as an **AI Agent tool** (`usableAsTool`). Drop it onto an AI Agent
node and your agent can register a fresh identity for itself, set its own DNS policy, or
verify a peer - the frictionless-agent-identity story, inside n8n.

## Example - Verify Identity

Input `2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478` returns:

```json
{
  "is_whisper_agent": true,
  "fqdn": "…agents.whisper.online",
  "operator": "…",
  "tenant": "…",
  "dane_ok": true,
  "jws_ok": true,
  "evidence": { "address": "2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478", "ptr": "…ip6.arpa" }
}
```

A non-agent address returns `{"is_whisper_agent": false, …}` with a plain-language
`detail`. (For an RDAP lookup, an address that anchors no identity returns the standard
RDAP `404` object, per RFC 9083.)

## Links

- Platform: <https://whisper.online/platform>
- RDAP + registry: <https://rdap.whisper.online> · <https://nic.whisper.online>
- CLI (MIT): <https://github.com/whisper-sec/whisper-cli> · install: <https://get.whisper.online>

## License

[MIT](LICENSE.md) © viaGraph B.V. (Whisper Security)
