# mcp-warden

A security gateway and scanner for **Model Context Protocol (MCP)** servers.
Runs fully offline — no LLM, no telemetry, no data leaves the process.

> ⚠️ Early development. APIs and detection rules will change.

## Why this exists

MCP adoption outran its security tooling. Through 2026 researchers disclosed
[40+ CVEs](https://dev.to/piiiico/mcp-security-vulnerabilities-in-2026-40-cves-and-counting-4pco)
against MCP implementations, and scans keep finding that a large fraction of
exposed MCP servers ship with **no authentication at all**. The common attacks
are well known: **tool poisoning** (hidden instructions in a tool's metadata),
**rug pulls** (a trusted tool silently changing its definition after approval),
**prompt injection** delivered through tool *results*, and **credential
exfiltration**.

The existing open-source tools (mcp-scan, Cisco's scanner, mcp-audit, …) are
**static** — they inspect configs and metadata before/at install time. They do
not see what actually flows at call time. The gateways (MCPX, ContextForge, …)
focus on routing, auth, and governance, not threat enforcement.

`mcp-warden` fills the **runtime** gap: it sits inline between an MCP client and
server and inspects live JSON-RPC traffic, blocking the message when a critical
rule fires.

## What it checks

| Class | When | Rule |
| ----- | ---- | ---- |
| Tool poisoning | `tools/list` | Instruction-like phrases or invisible-unicode in tool metadata |
| Rug pull | `tools/list` | A tool's hash changed since you pinned it (`warden pin`) |
| Prompt injection | `tools/call` result | Injection phrases / invisible unicode in returned content |
| Data exfiltration | `tools/call` args **and** results | AWS / GitHub / Slack / OpenAI / Google keys, private keys, JWTs |

Detection is deterministic and dependency-free (Go standard library only) —
appropriate for a component in the trust path.

## Install / build

```bash
go build -o warden ./cmd/warden   # Go 1.25+
```

## Use

**Audit a server (CI-friendly — exits non-zero on a critical finding):**

```bash
warden scan https://my-mcp-server.example.com/mcp
```

**Pin the approved tool set, then detect later rug pulls:**

```bash
warden pin  https://my-mcp-server.example.com/mcp --out warden.lock.json
warden scan https://my-mcp-server.example.com/mcp --lock warden.lock.json
```

**Run the inline gateway** (`warden.json`):

```json
{
  "listen": "127.0.0.1:7000",
  "upstream": "https://my-mcp-server.example.com/mcp",
  "lockfile": "warden.lock.json",
  "auditLog": "warden-audit.jsonl",
  "blockOnCritical": true
}
```

```bash
warden proxy --config warden.json
# point your MCP client at http://127.0.0.1:7000 instead of the upstream
```

When a critical rule fires, Warden returns a JSON-RPC error to the client
instead of forwarding the malicious message, and records the decision to the
audit log.

## Limitations (honest)

- Streamable HTTP transport only (stdio proxying not yet implemented).
- Pattern-based detection catches known shapes, not novel obfuscation; treat it
  as defense-in-depth, not a guarantee. An optional LLM-judge mode is on the
  roadmap but will remain off by default to preserve the offline guarantee.
- SSE response bodies are scanned as text (coarse) rather than fully parsed.

Contributions and rule submissions welcome — see `CONTRIBUTING.md`.

## License

MIT — see [LICENSE](LICENSE).
