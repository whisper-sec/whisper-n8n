# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@whisper.online**.
We aim to acknowledge within two business days and will coordinate a fix
and a disclosure timeline with you.

Please do not open a public issue for security reports.

## Scope

This policy covers the `n8n-nodes-whisper` community node in this
repository. The node calls Whisper's public API only (the control plane
at `graph.whisper.online` and the keyless RDAP surface at
`rdap.whisper.online`); your Whisper API key is stored by n8n as an
encrypted credential and is never written to the node.
