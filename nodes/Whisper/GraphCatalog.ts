// SPDX-License-Identifier: MIT
// GENERATED FILE - do not edit by hand.
// Source: the Whisper graph catalog (catalog.json, schemaVersion 1).
// Regenerate with: node scripts/generate-graph-catalog.mjs <path-to-catalog.json>
//
// 14 direct graph procedures (run their Cypher via the graph query API) and
// 15 multi-step flows (run by slug via the console gallery/run endpoint, SSE).
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

export const GRAPH_RECIPES: GraphRecipe[] = [
	{
		"id": "assess",
		"name": "Threat Posture (whisper.assess)",
		"action": "Threat Posture (whisper.assess)",
		"description": "Get a labelled threat posture for a host or IP - malicious, benign, or unknown. Returns a posture label + severity band + sub-labels + coverage + evidence for an indicator; benign-allowlisted vs malicious-evidenced, never a bare score. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures",
		"mode": "direct",
		"cypher": "CALL whisper.assess([$v]) YIELD host, label, band, sub_labels, coverage, evidence",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures",
		"fields": [
			{
				"name": "g_assess_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The value the recipe runs against (e.g. 8.8.8.8, theblackservicenetwork.com, 185.220.101.33)",
				"default": "8.8.8.8",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "asset",
		"name": "AS-SET Membership (whisper.asSet)",
		"action": "AS-SET Membership (whisper.asSet)",
		"description": "List the member ASNs of an AS-SET macro. Expands an AS-SET name (e.g. AS-CLOUDFLARE) to its member ASNs and source RIR. Arg is a STRING as-set name, not an integer ASN. (Membership is sparsely populated in the current graph.) (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures",
		"mode": "direct",
		"cypher": "CALL whisper.asSet($v) YIELD asSetName, memberAsn, sourceRir",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures",
		"fields": [
			{
				"name": "g_asset_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The value the recipe runs against",
				"default": "AS-CLOUDFLARE",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "db-schema",
		"name": "Graph Schema Catalog (db.schema)",
		"action": "Graph Schema Catalog (db.schema)",
		"description": "List every node and relationship type in the graph with counts and examples. The self-describing schema: node/relationship types with counts, descriptions, examples, source/target labels and query best-practices - the map of what the graph holds. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/schema",
		"mode": "direct",
		"cypher": "CALL db.schema()",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/schema",
		"fields": []
	},
	{
		"id": "explain",
		"name": "Threat-Feed Explainer (whisper.explain / explain)",
		"action": "Threat-Feed Explainer (whisper.explain / explain)",
		"description": "Score an indicator against the threat feeds and explain exactly why. Threat-intel scorer: score + level + human explanation + the feeds it is listed in (feedId, weight, firstSeen/lastSeen). Two live forms: bare CALL explain($v) (full columns) and CALL whisper.explain($v) (restricted YIELD). (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures/explain",
		"mode": "direct",
		"cypher": "CALL whisper.explain($v) YIELD indicator, score, level, explanation, sources",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures/explain",
		"fields": [
			{
				"name": "g_explain_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The value the recipe runs against (e.g. paypal.com, ickaoex.com, github.com)",
				"default": "paypal.com",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "history",
		"name": "WHOIS History Timeline (whisper.history)",
		"action": "WHOIS History Timeline (whisper.history)",
		"description": "Get the full historical WHOIS timeline for a domain. Every observed WHOIS snapshot over time: create/update/expiry, registrar, registrant, country, nameservers - the ownership/registration story. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures/history",
		"mode": "direct",
		"cypher": "CALL whisper.history($v)",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures/history",
		"fields": [
			{
				"name": "g_history_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The domain the recipe runs against",
				"default": "paypal.com",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "history-whois",
		"name": "WHOIS History (projection) (whisper.history.whois)",
		"action": "WHOIS History (projection) (whisper.history.whois)",
		"description": "Get the WHOIS-only historical timeline for a domain. The registration-record projection of the history timeline: create/update/expiry, registrar, registrant, country, nameservers per snapshot. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures/history",
		"mode": "direct",
		"cypher": "CALL whisper.history.whois($v) YIELD queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures/history",
		"fields": [
			{
				"name": "g_historyWhois_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The domain the recipe runs against",
				"default": "paypal.com",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "identify",
		"name": "Vendor / Operator Identity (whisper.identify)",
		"action": "Vendor / Operator Identity (whisper.identify)",
		"description": "Name the vendor and operator role behind a host or IP in one call. Resolves a host/IP to its canonical vendor, category and operator roles (DNS_OPERATOR / CDN / ORIGIN_AS / MAIL_RECEIVER) with a confidence band. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures/identify",
		"mode": "direct",
		"cypher": "CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures/identify",
		"fields": [
			{
				"name": "g_identify_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The value the recipe runs against (e.g. cloudflare.com, api.openai.com, 8.8.8.8)",
				"default": "api.openai.com",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "lookup-tor-relay",
		"name": "Tor Exit-Relay Lookup (whisper.lookupTorRelay)",
		"action": "Tor Exit-Relay Lookup (whisper.lookupTorRelay)",
		"description": "Check whether an IP is a known Tor exit relay. Live Tor exit-node check: found + fingerprint + exit-address count + source + ingest time for an IPv4. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures/helpers",
		"mode": "direct",
		"cypher": "CALL whisper.lookupTorRelay($v) YIELD indicator, found, fingerprint, exitAddressCount, source, ingestedAt",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures/helpers",
		"fields": [
			{
				"name": "g_lookupTorRelay_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The ipv4 the recipe runs against",
				"default": "185.220.101.33",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "origins",
		"name": "CDN-Origin De-cloaker (whisper.origins)",
		"action": "CDN-Origin De-cloaker (whisper.origins)",
		"description": "Find the real origin IPs behind a CDN-fronted domain, ranked by confidence. Candidate origin IPs behind a CDN with confidence, the methods that found them (e.g. links_to), and the hosting ASN/name - de-cloaks to the real server. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures/origins",
		"mode": "direct",
		"cypher": "CALL whisper.origins($v) YIELD ip, confidence, methods, asn, asnName, kind",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures/origins",
		"fields": [
			{
				"name": "g_origins_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The domain the recipe runs against",
				"default": "cloudflare.com",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "psl-affiliation",
		"name": "PSL Private-Suffix Affiliation (whisper.psl.affiliation)",
		"action": "PSL Private-Suffix Affiliation (whisper.psl.affiliation)",
		"description": "Check whether a domain is a PSL private-section suffix and who submitted it. For a PSL private-section suffix, returns the submitting org/login and evidence kind + confidence; found=false for ordinary registrable domains. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures/helpers",
		"mode": "direct",
		"cypher": "CALL whisper.psl.affiliation($v) YIELD found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures/helpers",
		"fields": [
			{
				"name": "g_pslAffiliation_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The domain the recipe runs against",
				"default": "paypal.com",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "psl-tldplusone",
		"name": "Registrable Apex (whisper.psl.tldPlusOne)",
		"action": "Registrable Apex (whisper.psl.tldPlusOne)",
		"description": "Reduce any hostname to its registrable apex (eTLD+1) via the Public Suffix List. PSL-correct eTLD+1: www.foo.co.uk -> foo.co.uk. The right way to group hosts by the thing someone actually registered. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures/helpers",
		"mode": "direct",
		"cypher": "CALL whisper.psl.tldPlusOne($v) YIELD apex",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures/helpers",
		"fields": [
			{
				"name": "g_pslTldplusone_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The hostname the recipe runs against",
				"default": "www.foo.co.uk",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "submit",
		"name": "Submit Observation / Feedback (whisper.submit)",
		"action": "Submit Observation / Feedback (whisper.submit)",
		"description": "Contribute an indicator observation or feedback back into the graph (requires an API key). The write channel: submit an indicator/feedback with an attributable API key (anonymous submits are refused to preserve K-anonymity). Keyed-only by design. (Direct graph procedure.) Docs: https://www.whisper.security/docs/cypher-api",
		"mode": "direct",
		"cypher": "CALL whisper.submit({kind:$kind, identifier_kind:$identifier_kind, value:$value})",
		"docsUrl": "https://www.whisper.security/docs/cypher-api",
		"fields": [
			{
				"name": "g_submit_kind",
				"paramName": "kind",
				"displayName": "Kind",
				"description": "The select the recipe runs against",
				"default": "indicator",
				"type": "options",
				"options": [
					"indicator",
					"feedback"
				],
				"target": "inputs"
			},
			{
				"name": "g_submit_identifier_kind",
				"paramName": "identifier_kind",
				"displayName": "Identifier Kind",
				"description": "The select the recipe runs against",
				"default": "ip",
				"type": "options",
				"options": [
					"ip",
					"asn",
					"cert_sha256",
					"cert_ja3_hash",
					"cert_ja4_hash",
					"cert_jarm",
					"cidr",
					"whois_pattern",
					"host_hash_rotating",
					"url_path_hash"
				],
				"target": "inputs"
			},
			{
				"name": "g_submit_value",
				"paramName": "value",
				"displayName": "Value",
				"description": "The value the recipe runs against (e.g. 203.0.113.5, AS64496, 198.51.100.0/24)",
				"default": "203.0.113.5",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "variants",
		"name": "Typosquat Variant Generator (whisper.variants)",
		"action": "Typosquat Variant Generator (whisper.variants)",
		"description": "Generate look-alike domain variants of a brand and see which are registered. Enumerates permutations (omission, bitsquatting, ...) of a domain, flags which exist, with a per-variant confidence. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures/variants",
		"mode": "direct",
		"cypher": "CALL whisper.variants($v) YIELD variant, method, exists, confidence",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures/variants",
		"fields": [
			{
				"name": "g_variants_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The domain the recipe runs against",
				"default": "paypal.com",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "walk",
		"name": "Vendor Attribution Walk (whisper.walk)",
		"action": "Vendor Attribution Walk (whisper.walk)",
		"description": "Walk the graph to the nearest known vendors behind a host, with the channel and confidence. Structural attribution: returns nearest_known_vendors with the channel (DELEGATED_TO / ORIGIN_AS) and confidence, plus siblings and coverage - explains WHY a host maps to a vendor. (Direct graph procedure.) Docs: https://www.whisper.security/docs/whisper-graph/procedures",
		"mode": "direct",
		"cypher": "CALL whisper.walk($v) YIELD coverage, host, nearest_known_vendors, no_atlas_match, siblings",
		"docsUrl": "https://www.whisper.security/docs/whisper-graph/procedures",
		"fields": [
			{
				"name": "g_walk_v",
				"paramName": "v",
				"displayName": "Value",
				"description": "The value the recipe runs against",
				"default": "cloudflare.com",
				"type": "string",
				"target": "inputs"
			}
		]
	},
	{
		"id": "anycast-dns-root-sovereignty",
		"name": "Anycast DNS-Root Sovereignty",
		"action": "Anycast DNS-Root Sovereignty",
		"description": "Assess how resilient a country's core DNS is if it were cut off from the world. Could a country still resolve names if it were isolated? Counts how many of the 13 root letters have in-country DNS_ROOT_INSTANCE anycast nodes, the Global-vs-Local split, the BGP origin ASNs hosting them, and a resilience grade. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/compliance",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/compliance",
		"fields": [
			{
				"name": "g_anycastDnsRootSovereignty_country",
				"paramName": "country",
				"displayName": "Country",
				"description": "The value the recipe runs against (e.g. BR, US, DE, ZA, CY)",
				"default": "BR",
				"type": "string",
				"target": "inputs",
				"primary": true
			},
			{
				"name": "g_anycastDnsRootSovereignty_p_instanceType",
				"paramName": "instanceType",
				"displayName": "Instance Type",
				"description": "Tuning parameter for the flow (default: ALL)",
				"default": "ALL",
				"type": "options",
				"options": [
					"ALL",
					"Global",
					"Local"
				],
				"target": "params"
			}
		]
	},
	{
		"id": "attack-path",
		"name": "Attack Path & Connection Finder",
		"action": "Attack Path & Connection Finder",
		"description": "Find the choke points an attacker would target - and how any two things connect. From a starting foothold, finds shared dependencies whose compromise reaches furthest; for any two indicators, traces how they are actually connected. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/attack-path",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/attack-path",
		"fields": [
			{
				"name": "g_attackPath_value",
				"paramName": "value",
				"displayName": "Asset",
				"description": "The hostname the recipe runs against (e.g. github.com, cloudflare.com, coinbase.com)",
				"default": "paypal.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			},
			{
				"name": "g_attackPath_other",
				"paramName": "other",
				"displayName": "Other",
				"description": "The hostname the recipe runs against",
				"default": "paypa1.com",
				"type": "string",
				"target": "inputs"
			},
			{
				"name": "g_attackPath_p_level",
				"paramName": "level",
				"displayName": "Level",
				"description": "Tuning parameter for the flow (default: standard)",
				"default": "standard",
				"type": "options",
				"options": [
					"quick",
					"standard",
					"deep",
					"comprehensive",
					"exhaustive"
				],
				"target": "params"
			}
		]
	},
	{
		"id": "attack-surface",
		"name": "Attack-Surface Mapper",
		"action": "Attack-Surface Mapper",
		"description": "Map everything about a domain that's exposed to the outside world, scored for risk. Maps the full external footprint - subdomains, name/mail servers, registrant, third-party services, connected web - and scores the exposure. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/pentest-recon",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/pentest-recon",
		"fields": [
			{
				"name": "g_attackSurface_domain",
				"paramName": "domain",
				"displayName": "Domain",
				"description": "The domain the recipe runs against",
				"default": "github.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			},
			{
				"name": "g_attackSurface_p_level",
				"paramName": "level",
				"displayName": "Level",
				"description": "Tuning parameter for the flow (default: standard)",
				"default": "standard",
				"type": "options",
				"options": [
					"quick",
					"standard",
					"deep",
					"comprehensive",
					"exhaustive"
				],
				"target": "params"
			}
		]
	},
	{
		"id": "bgp-hijack-exposure",
		"name": "BGP Hijack & Routing-Hygiene Audit",
		"action": "BGP Hijack & Routing-Hygiene Audit",
		"description": "Grade a network's routing security and trace conflicts to the domains they'd expose. Grades a network on the conflicts/gaps that make route hijacking possible, then traces any conflict to the specific domains and organisations exposed on the affected blocks. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/bgp-routing",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/bgp-routing",
		"fields": [
			{
				"name": "g_bgpHijackExposure_value",
				"paramName": "value",
				"displayName": "ASN",
				"description": "The asn the recipe runs against",
				"default": "AS13335",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	},
	{
		"id": "blast-radius",
		"name": "Dependency Blast Radius",
		"action": "Dependency Blast Radius",
		"description": "Pick one asset and see what would break if it failed - and what it depends on in turn. Maps dependencies in both directions: everything that breaks if the asset fails (SPOFs) and everything it relies on (its own DNS/mail/hosting/network supply chain). (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/soc",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/soc",
		"fields": [
			{
				"name": "g_blastRadius_indicator",
				"paramName": "indicator",
				"displayName": "Asset",
				"description": "The value the recipe runs against (e.g. ns1.dreamhost.com, dns1.p01.nsone.net, cloudflare.com, 104.16.132.229, AS13335, 104.16.128.0/20)",
				"default": "ns1.dreamhost.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			},
			{
				"name": "g_blastRadius_p_depth",
				"paramName": "depth",
				"displayName": "Depth",
				"description": "Tuning parameter for the flow (default: 2)",
				"default": 2,
				"type": "number",
				"target": "params"
			}
		]
	},
	{
		"id": "build-takedown-evidence-package",
		"name": "Takedown Evidence Package",
		"action": "Takedown Evidence Package",
		"description": "Assemble a ready-to-submit dossier for taking down a scam or phishing domain. One-pass takedown package: reputation verdict, owner (WHOIS), abuse-list listings, and surrounding infrastructure, laid out ready to hand to a registrar/host. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/threat-intel",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/threat-intel",
		"fields": [
			{
				"name": "g_buildTakedownEvidencePackage_domain",
				"paramName": "domain",
				"displayName": "Domain",
				"description": "The domain the recipe runs against (e.g. ickaoex.com, bodis.com, paypal.com)",
				"default": "ickaoex.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	},
	{
		"id": "discover-ai-agent-infrastructure",
		"name": "AI / Agent Infrastructure Discovery",
		"action": "AI / Agent Infrastructure Discovery",
		"description": "Map an organisation's externally visible AI and agent endpoints from the outside. Maps externally visible AI/agent hosts (API, model, agent) from the outside via heuristic hostname patterns (api./mcp./ai./vector./llm./agent./chat./copilot.). Best-effort leads. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/pentest-recon",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/pentest-recon",
		"fields": [
			{
				"name": "g_discoverAiAgentInfrastructure_value",
				"paramName": "value",
				"displayName": "Domain",
				"description": "The domain the recipe runs against",
				"default": "github.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	},
	{
		"id": "indicator",
		"name": "Threat Investigation",
		"action": "Threat Investigation",
		"description": "Investigate one suspicious domain, IP, or network in depth and get a clear picture of the threat and everything connected to it. Deep-dive: works outward across the whole footprint (related domains, real origins behind CDN, neighbouring infra), threat-checks each node, never inherits maliciousness from shared infra; labelled posture, no score. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/soc",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/soc",
		"fields": [
			{
				"name": "g_indicator_indicator",
				"paramName": "indicator",
				"displayName": "Indicator",
				"description": "The value the recipe runs against (e.g. theblackservicenetwork.com, 185.220.101.33, customclothing.in, bitcoin-embassy.org, AS60729, 185.220.101.0/24)",
				"default": "theblackservicenetwork.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	},
	{
		"id": "indicator-enrichment",
		"name": "Indicator Enrichment",
		"action": "Indicator Enrichment",
		"description": "Turn one domain or IP into a full context card - owner, hosting, mail, location, reputation at a glance. Fills the picture for one indicator: registrant (WHOIS), hosting + country, mail/name servers, network behind it, reputation read. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/dns-email",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/dns-email",
		"fields": [
			{
				"name": "g_indicatorEnrichment_value",
				"paramName": "value",
				"displayName": "Domain",
				"description": "The value the recipe runs against (e.g. google.com, cloudflare.com, 185.220.101.33, AS13335, 104.247.80.0/22)",
				"default": "google.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	},
	{
		"id": "infrastructure-mapping",
		"name": "Digital Infrastructure Mapping",
		"action": "Digital Infrastructure Mapping",
		"description": "Trace one indicator to its true owner and full estate, even behind privacy screens and CDNs. Works out the true operator (even behind privacy WHOIS), de-cloaks CDN-fronted sites to real servers, pivots to the rest of that owner’s estate across every layer. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/compliance",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/compliance",
		"fields": [
			{
				"name": "g_infrastructureMapping_value",
				"paramName": "value",
				"displayName": "Target",
				"description": "The value the recipe runs against (e.g. github.com, 8.8.8.8, AS15169, 104.16.0.0/13)",
				"default": "cloudflare.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			},
			{
				"name": "g_infrastructureMapping_p_level",
				"paramName": "level",
				"displayName": "Level",
				"description": "Tuning parameter for the flow (default: standard)",
				"default": "standard",
				"type": "options",
				"options": [
					"quick",
					"standard",
					"deep",
					"comprehensive",
					"exhaustive"
				],
				"target": "params"
			}
		]
	},
	{
		"id": "map-supply-chain-concentration",
		"name": "Infrastructure Concentration & Resilience",
		"action": "Infrastructure Concentration & Resilience",
		"description": "Grade an organisation for over-reliance on single providers, regions, or facilities. Grades how concentrated infra is - too much riding on one provider/region/data-centre/cable landing - surfacing SPOFs for resilience and DORA/NIS2 fourth-party risk. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/compliance",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/compliance",
		"fields": [
			{
				"name": "g_mapSupplyChainConcentration_domain",
				"paramName": "domain",
				"displayName": "Domain",
				"description": "The domain the recipe runs against (e.g. atlassian.com, shopify.com, cloudflare.com)",
				"default": "atlassian.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	},
	{
		"id": "nameserver-hijack-dns-consistency",
		"name": "Nameserver & DNS Delegation Audit",
		"action": "Nameserver & DNS Delegation Audit",
		"description": "Check a domain's name servers for the misconfigurations that enable DNS hijacking. Audits delegation, flags stale/mismatched/lame nameservers, sizes each provider’s share, surfaces registry facts - catches delegation weakness before exploit. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/dns-email",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/dns-email",
		"fields": [
			{
				"name": "g_nameserverHijackDnsConsistency_value",
				"paramName": "value",
				"displayName": "Domain",
				"description": "The domain the recipe runs against",
				"default": "google.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	},
	{
		"id": "route-health",
		"name": "Network & Routing Report",
		"action": "Network & Routing Report",
		"description": "Profile a network or address block into a full routing and reachability health card. Health card for a network/block: what it announces, peers/transit, single-upstream lean, RPKI protection - the one-look reach & resilience report. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/bgp-routing",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/bgp-routing",
		"fields": [
			{
				"name": "g_routeHealth_target",
				"paramName": "target",
				"displayName": "Target",
				"description": "The value the recipe runs against",
				"default": "1.1.1.0/24",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	},
	{
		"id": "subdomain-takeover",
		"name": "Subdomain Takeover Detection",
		"action": "Subdomain Takeover Detection",
		"description": "Find subdomains that point at abandoned services an attacker could claim. Walks subdomains and flags ones aiming at deprovisioned targets (dangling CNAME whose target no longer resolves) so you can reclaim/remove before someone else does. CNAME layer is prod-ahead. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/pentest-recon",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/pentest-recon",
		"fields": [
			{
				"name": "g_subdomainTakeover_value",
				"paramName": "value",
				"displayName": "Domain",
				"description": "The domain the recipe runs against",
				"default": "github.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	},
	{
		"id": "typosquat",
		"name": "Typosquat & Brand-Impersonation Scanner",
		"action": "Typosquat & Brand-Impersonation Scanner",
		"description": "Find registered look-alikes of your brand and check which ones are dangerous. Finds registered impersonations across misspellings/risky TLDs, separates your own defensive domains from strangers’, flags fresh/privacy/abuse-listed ones into a prioritised list. (Multi-step flow: streams each step as an item.) Docs: https://www.whisper.security/docs/recipes/brand-protection",
		"mode": "flow",
		"docsUrl": "https://www.whisper.security/docs/recipes/brand-protection",
		"fields": [
			{
				"name": "g_typosquat_domain",
				"paramName": "domain",
				"displayName": "Domain",
				"description": "The domain the recipe runs against",
				"default": "paypal.com",
				"type": "string",
				"target": "inputs",
				"primary": true
			}
		]
	}
];
