# Contributing

mcp-warden is dependency-free by design (Go standard library only). Please keep
it that way — detection must run offline and in the trust path.

## Layout
- `internal/detect` — the security inspectors (pure functions; this is where
  most contributions land). Add a rule + a table-driven test.
- `internal/mcp` — minimal JSON-RPC / MCP message types.
- `internal/client` — minimal Streamable HTTP MCP client (scan/pin).
- `internal/proxy` — the inline gateway.
- `cmd/warden` — the CLI.

## Adding a detection rule
1. Add the pattern/logic in the relevant `internal/detect` file.
2. Add a test case (clean input must stay quiet — avoid false positives).
3. `make test vet`.

Rule ideas welcome: new credential shapes, injection phrasings, confused-deputy
token-passthrough heuristics, SSE-aware parsing.
