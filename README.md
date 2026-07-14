# n8n-nodes-whisper

Provision, govern and inspect [Whisper](https://whisper.online/platform) agent identities
from an n8n workflow - give an agent a real, routable IPv6 identity, set its DNS policy,
read its activity, and verify any agent, all with your own Whisper key. Plus the full
[whisper.security](https://www.whisper.security) graph: raw Cypher and 29 named recipes
(threat posture, typosquats, attack surface, BGP hygiene and more) as native operations.

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

## The Graph resource - query the whisper.security graph

Switch **Resource** to **Graph** and the node speaks to the
[whisper.security](https://www.whisper.security) security graph itself (3.6B+ nodes of
DNS/BGP/WHOIS/threat intelligence). Every Graph operation is keyed (same **Whisper API**
credential).

**Run Cypher** sends arbitrary Cypher with `$parameters` to the graph query API - see the
[Cypher API docs](https://www.whisper.security/docs/cypher-api):

- **Cypher**: `CALL whisper.identify([$v]) YIELD host, canonical_name, category`
- **Parameters (JSON)**: `{ "v": "api.openai.com" }`

Each result row comes back as one n8n item.

The **named recipes** below come straight from the Whisper graph catalog. *Procedures*
run a single graph call and emit one item per row; *flows* are multi-step investigations
run by the Whisper engine - the node streams every step back as an item
(`start` / `step-start` / `step` / `graph` / `complete`), each `step` carrying its bound
Cypher, columns and rows. Every field is pre-filled with a documented example, so each
recipe runs out of the box.

| Operation | Kind | What it does | Docs |
|---|---|---|---|
| **Threat Posture (whisper.assess)** | procedure | Get a labelled threat posture for a host or IP - malicious, benign, or unknown. | [docs](https://www.whisper.security/docs/whisper-graph/procedures) |
| **AS-SET Membership (whisper.asSet)** | procedure | List the member ASNs of an AS-SET macro. | [docs](https://www.whisper.security/docs/whisper-graph/procedures) |
| **Graph Schema Catalog (db.schema)** | procedure | List every node and relationship type in the graph with counts and examples. | [docs](https://www.whisper.security/docs/whisper-graph/schema) |
| **Threat-Feed Explainer (whisper.explain / explain)** | procedure | Score an indicator against the threat feeds and explain exactly why. | [docs](https://www.whisper.security/docs/whisper-graph/procedures/explain) |
| **WHOIS History Timeline (whisper.history)** | procedure | Get the full historical WHOIS timeline for a domain. | [docs](https://www.whisper.security/docs/whisper-graph/procedures/history) |
| **WHOIS History (projection) (whisper.history.whois)** | procedure | Get the WHOIS-only historical timeline for a domain. | [docs](https://www.whisper.security/docs/whisper-graph/procedures/history) |
| **Vendor / Operator Identity (whisper.identify)** | procedure | Name the vendor and operator role behind a host or IP in one call. | [docs](https://www.whisper.security/docs/whisper-graph/procedures/identify) |
| **Tor Exit-Relay Lookup (whisper.lookupTorRelay)** | procedure | Check whether an IP is a known Tor exit relay. | [docs](https://www.whisper.security/docs/whisper-graph/procedures/helpers) |
| **CDN-Origin De-cloaker (whisper.origins)** | procedure | Find the real origin IPs behind a CDN-fronted domain, ranked by confidence. | [docs](https://www.whisper.security/docs/whisper-graph/procedures/origins) |
| **PSL Private-Suffix Affiliation (whisper.psl.affiliation)** | procedure | Check whether a domain is a PSL private-section suffix and who submitted it. | [docs](https://www.whisper.security/docs/whisper-graph/procedures/helpers) |
| **Registrable Apex (whisper.psl.tldPlusOne)** | procedure | Reduce any hostname to its registrable apex (eTLD+1) via the Public Suffix List. | [docs](https://www.whisper.security/docs/whisper-graph/procedures/helpers) |
| **Submit Observation / Feedback (whisper.submit)** | procedure | Contribute an indicator observation or feedback back into the graph (requires an API key). | [docs](https://www.whisper.security/docs/cypher-api) |
| **Typosquat Variant Generator (whisper.variants)** | procedure | Generate look-alike domain variants of a brand and see which are registered. | [docs](https://www.whisper.security/docs/whisper-graph/procedures/variants) |
| **Vendor Attribution Walk (whisper.walk)** | procedure | Walk the graph to the nearest known vendors behind a host, with the channel and confidence. | [docs](https://www.whisper.security/docs/whisper-graph/procedures) |
| **Anycast DNS-Root Sovereignty** | flow | Assess how resilient a country's core DNS is if it were cut off from the world. | [docs](https://www.whisper.security/docs/recipes/compliance) |
| **Attack Path & Connection Finder** | flow | Find the choke points an attacker would target - and how any two things connect. | [docs](https://www.whisper.security/docs/recipes/attack-path) |
| **Attack-Surface Mapper** | flow | Map everything about a domain that's exposed to the outside world, scored for risk. | [docs](https://www.whisper.security/docs/recipes/pentest-recon) |
| **BGP Hijack & Routing-Hygiene Audit** | flow | Grade a network's routing security and trace conflicts to the domains they'd expose. | [docs](https://www.whisper.security/docs/recipes/bgp-routing) |
| **Dependency Blast Radius** | flow | Pick one asset and see what would break if it failed - and what it depends on in turn. | [docs](https://www.whisper.security/docs/recipes/soc) |
| **Takedown Evidence Package** | flow | Assemble a ready-to-submit dossier for taking down a scam or phishing domain. | [docs](https://www.whisper.security/docs/recipes/threat-intel) |
| **AI / Agent Infrastructure Discovery** | flow | Map an organisation's externally visible AI and agent endpoints from the outside. | [docs](https://www.whisper.security/docs/recipes/pentest-recon) |
| **Threat Investigation** | flow | Investigate one suspicious domain, IP, or network in depth and get a clear picture of the threat and everything connected to it. | [docs](https://www.whisper.security/docs/recipes/soc) |
| **Indicator Enrichment** | flow | Turn one domain or IP into a full context card - owner, hosting, mail, location, reputation at a glance. | [docs](https://www.whisper.security/docs/recipes/dns-email) |
| **Digital Infrastructure Mapping** | flow | Trace one indicator to its true owner and full estate, even behind privacy screens and CDNs. | [docs](https://www.whisper.security/docs/recipes/compliance) |
| **Infrastructure Concentration & Resilience** | flow | Grade an organisation for over-reliance on single providers, regions, or facilities. | [docs](https://www.whisper.security/docs/recipes/compliance) |
| **Nameserver & DNS Delegation Audit** | flow | Check a domain's name servers for the misconfigurations that enable DNS hijacking. | [docs](https://www.whisper.security/docs/recipes/dns-email) |
| **Network & Routing Report** | flow | Profile a network or address block into a full routing and reachability health card. | [docs](https://www.whisper.security/docs/recipes/bgp-routing) |
| **Subdomain Takeover Detection** | flow | Find subdomains that point at abandoned services an attacker could claim. | [docs](https://www.whisper.security/docs/recipes/pentest-recon) |
| **Typosquat & Brand-Impersonation Scanner** | flow | Find registered look-alikes of your brand and check which ones are dangerous. | [docs](https://www.whisper.security/docs/recipes/brand-protection) |

To regenerate the recipe surface after a catalog update:
`node scripts/generate-graph-catalog.mjs <path-to-catalog.json>`.

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
