# Whisper Control API - the client-facing contract

The reference for every non-CLI integration (n8n, Zapier, Pipedream, SDKs, MCP). It is
reverse-engineered from the `whisper` CLI (the reference implementation:
`whisper-cli/internal/client/*.go`) and verified live. It describes only the **client
protocol** - what a caller sends over the public network and what it gets back - so it is
safe to ship in a public repo.

> Robustness Principle (RFC 761): the wire we emit is strict and deterministic (sorted
> keys, doubled-quote escaping); what we accept is liberal (two envelope shapes, POST body
> as documented). Errors are structured problem objects, never opaque 500s.

---

## 1. Endpoint & auth

| | |
|---|---|
| **Control endpoint** | `POST https://graph.whisper.security/api/query` |
| **Auth (owner key)** | header `X-API-Key: <whisper_live_…>` |
| **Auth (monitor token)** | header `Authorization: Bearer et_…` - only for the SSE monitor stream |
| **Content-Type** | `application/json` |
| **Accept** | `application/json` |
| **Body** | `{"query": "CALL whisper.agents({op:'<op>', args:{…}})"}` |

The one control verb is `whisper.agents({op, args})`. `op` selects the action; `args` is a
map of parameters. Both are sent as a Cypher call in the JSON `query` field. There is no key
in the body - the key travels only in the `X-API-Key` header.

### Building the Cypher literal (conservative-emit)

The `args` map is rendered to a Cypher map literal deterministically:

- **string** → single-quoted; a `'` is **doubled** (`''`) and a `\` is doubled, so a value
  can never break out of the literal (`Tim O'Reilly` → `'Tim O''Reilly'`).
- **number** → decimal; **bool** → `true`/`false`; **null** → `null`.
- **array** → `[a,b,c]`; **map** → `{k:v}`.
- **map keys are emitted in sorted order** so the produced query is byte-stable.

Example - `op:policy` with `default=deny`, `block=[x.com,y.com]`, `allow=[z.com]`:

```json
{"query":"CALL whisper.agents({op:'policy', args:{allow:['z.com'],block:['x.com','y.com'],default:'deny'}})"}
```

---

## 2. Response envelope (liberal-accept - handle both shapes)

**A. Live shape** (what `/api/query` returns today) - a procedure-row table whose single row
carries the per-op envelope:

```json
{
  "columns": ["op","ok","status","result","error","retry_after"],
  "rows": [
    { "op":"list", "ok":true, "status":200,
      "result": { "columns":["kind","item"], "rows":[ ["agents", {…}] ] },
      "error": null, "retry_after": null }
  ]
}
```

**B. Dev-guide shape** - a flat envelope:

```json
{ "ok": true, "status": 200, "result": {"columns":[…],"rows":[…]}, "error": null }
```

A robust client accepts both: read `ok`; on success unwrap `result` (`result.rows` are
positional arrays aligned to `result.columns` → turn each into a `{column: value}` record);
on `ok:false` surface `error`.

### Error object (`ok:false`, or an HTTP 4xx bare body)

```json
{ "type":"…", "title":"…", "status":403, "detail":"scope admin:dns required", "suggestions":[…] }
```

Surface `detail` (then `title`, then `type`) verbatim - it is written to be helpful and
secret-free. `retry_after` (seconds) may accompany a 429/503.

---

## 3. Operations (`op` → args → result columns)

Scopes: `register`, `revoke`, `policy` require `admin:dns`; the rest require the matching
read/write scope. All actions are confined to the caller's own tenant.

### `register` - mint a new agent + its own key
- **args**: `label` (required, the agent's human name), `contact_email` (optional).
- **result**: `agent`, `address` (the `/128`), `fqdn`, `ptr`, `state`, **`api_key`**
  (the new agent's key - returned **once**; capture it).

### `identity` - allocate the caller's own `/128`
- **args**: `label` (required), `contact_email` (optional). Release form:
  `release=true` + `address=<128>`.
- **result**: `agent`, `address`, `fqdn`, `ptr`, `state`.

### `list` - list the tenant's fleet
- **args**: `kind` = `agents` | `identities` | `records` (default `agents`).
- **result columns**: `kind`, `item`. Each `item` = `{label, fqdn, address, agent, created, state}`.

### `agent` - one agent's detail + counters
- **args**: `agent=<id>` **or** `address=<128>` (a value containing `:` is an address).
- **result columns**: `agent, address, fqdn, ptr, label, state, allocated_at, contact,
  last_seen, dns_queries, dns_blocked, dns_nxdomain, packets, bytes_up, bytes_down,
  connections_active, connections_total`.

### `policy` - set or read the per-tenant DNS resolver policy
- **args (set)**: `default` = `allow` | `deny`; `block` = `[names]`; `allow` = `[names]`
  (max 1000 combined). **No args ⇒ reads** the current policy back.
- **result columns**: `key`, `value` (e.g. `["default","allow"]`).

### `logs` - recent activity from warm storage
- **args**: `agent` (id or `/128`, optional), `kind` = `dns` | `conn` | `alloc` (omit for
  all), `from`, `to` (epoch-ms, RFC-3339, or relative like `-1h`), `limit` (default 1000,
  cap 10000).
- **result columns**: `ts, kind, qname, qtype, rcode, decision, source, answer, latency_ms,
  agent, peer, bytes_up, bytes_down, duration_ms, reason, client_src, packets_up,
  packets_down` (empty rows when the window has no events).

### `revoke` - fully revoke an agent (irreversible)
- **args**: `agent` = `<id>` or `<128>`.
- **result**: a status field (`status`/`state`).

### `connect` - egress config bound to the agent's `/128`
- **args**: `agent` (id or `/128`, optional - omit for the reuse-most-recent default),
  `tier` = `socks5` (default) | `wireguard` | `anyip`. For `wireguard`, also send
  `public_key` (base64) so the server registers your locally-generated public key.
- **result**: `tier`, `address`, `fqdn`, plus **secret-carrying** transport fields:
  - `socks5`/`anyip`: `http_proxy`, `connection_string` (both embed an `et_` bearer),
    `socks5_endpoint`.
  - `wireguard`: `server_public_key`, `endpoint`, `dns`, `wireguard_config`,
    `client_private_key` (present only on the zero-key path).
- **⚠️ Bearer hygiene**: the bearer / WireGuard private key must never be persisted to
  logs, workflow data, argv, or child-env. The CLI hands them straight to a local proxy and
  surfaces only a bearer-free `socks5h://127.0.0.1:<port>`. Integrations that cannot bring
  up a local proxy should **strip** these fields by default.

---

## 4. Keyless public surfaces (no credential)

These read only public identity data and take **no** auth header.

| Call | Request | Returns |
|---|---|---|
| **Verify identity** | `GET https://rdap.whisper.online/verify-identity?ip=<addr>` | `{is_whisper_agent, fqdn, operator, tenant, dane_ok, jws_ok, verified_at, detail, evidence{…}}`. `200` = is an agent, `404` = not an agent, `400` = malformed. |
| **RDAP record** | `GET https://rdap.whisper.online/ip/<addr>` | RFC 9083 RDAP object (`404` object if the address anchors no identity). |
| **Transparency log** | `GET https://rdap.whisper.online/ip/<addr>/transparency` | Hash-chained signed issuance history + ledger inclusion proof. |
| **Inbound lookups** | `GET https://rdap.whisper.online/ip/<addr>/lookups` | Recent inbound-lookup feed. |

RDAP is served as `application/rdap+json`; verify as `application/json`. Ask for
`Accept: application/rdap+json, application/json;q=0.9, */*;q=0.1` to be safe.

---

## 5. Reference implementation

The `whisper` CLI (MIT, <https://github.com/whisper-sec/whisper-cli>) is the canonical
client: `internal/client/client.go` (transport + auth), `cypher.go` (the query builder),
`envelope.go` (the two-shape decoder), `verify.go` + `rdap.go` (keyless). Match its
behaviour and an integration is correct by construction.
