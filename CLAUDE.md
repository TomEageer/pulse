# mcp-warden — guidance for Claude Code

Runtime security gateway & scanner for MCP servers. Read this before making changes.

## Non-negotiable constraints
- **Zero external dependencies.** Go standard library only. Do not add modules to
  `go.mod`. Detection runs in the trust path — keep the supply chain empty.
- **Offline, no LLM, no telemetry.** Nothing about inspected traffic may leave the
  process. (An optional LLM-judge mode may exist later but must be opt-in and off
  by default.)
- **Deterministic detection.** Inspectors are pure functions; same input → same findings.

## Layout
- `internal/detect/` — the security inspectors (poisoning, pinning, injection, secrets).
  **Most work lands here.** Each rule needs a table-driven test; clean input must stay quiet.
- `internal/mcp/` — minimal JSON-RPC / MCP message types.
- `internal/client/` — minimal Streamable HTTP MCP client (used by scan/pin).
- `internal/proxy/` — the inline gateway (request + response inspection, block-on-critical).
- `cmd/warden/` — CLI: `scan`, `pin`, `proxy`, `version`.

## Conventions
- Match the existing style: small files, doc comments on exported symbols, `slog` for logs.
- A new detector = a `Finding` with `Category`/`Severity`/`Rule`/`Detail`/`Location`,
  plus a test asserting both a positive case and a clean (no-finding) case.
- Severity: `critical` triggers blocking in the proxy. Reserve it for high-confidence rules
  to avoid false positives breaking real traffic.

## Workflow
- Always run `make test vet` before committing. `make build` produces `./warden`.
- Manual end-to-end check: build a tiny mock MCP server, run `warden scan <url>` and a
  `warden proxy` round-trip (see the README demo shape).
- Keep `README.md` "What it checks" table and "Limitations" section in sync with reality.
  Do not claim coverage the code doesn't have.

## Roadmap (good next tasks)
- stdio transport proxying (currently Streamable HTTP only)
- confused-deputy / token-passthrough detection (client token forwarded upstream)
- SSE-aware response parsing (currently coarse text scan)
- a `warden test` red-team subcommand that probes a server with known attack payloads
