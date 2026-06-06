package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/TomEageer/mcp-warden/internal/mcp"
)

// ToolHash is a stable fingerprint of a tool's security-relevant surface: its
// name, description, and input schema. A change in any of these after the tool
// was approved is a "rug pull" — the classic MCP supply-chain attack where a
// trusted tool silently mutates its behavior.
func ToolHash(t mcp.Tool) string {
	// Normalize the schema so insignificant key ordering doesn't churn hashes.
	var schema any
	_ = json.Unmarshal(t.InputSchema, &schema)
	norm, _ := json.Marshal(map[string]any{
		"name":        t.Name,
		"description": t.Description,
		"inputSchema": schema,
	})
	sum := sha256.Sum256(norm)
	return hex.EncodeToString(sum[:])
}

// Baseline maps tool name to its pinned hash (a warden.lock.json).
type Baseline map[string]string

// Pin builds a baseline from the current tool set.
func Pin(tools []mcp.Tool) Baseline {
	b := make(Baseline, len(tools))
	for _, t := range tools {
		b[t.Name] = ToolHash(t)
	}
	return b
}

// Check compares the live tool set against the pinned baseline. A changed hash
// is a critical rug-pull; a tool absent from the baseline is informational
// (newly added, never approved).
func (b Baseline) Check(tools []mcp.Tool) []Finding {
	if len(b) == 0 {
		return nil // no baseline pinned yet; nothing to compare
	}
	var findings []Finding
	for _, t := range tools {
		pinned, known := b[t.Name]
		switch {
		case !known:
			findings = append(findings, Finding{
				Category: CatRugPull,
				Severity: SevWarning,
				Rule:     "unpinned-tool",
				Detail:   "tool is not in the pinned baseline (added since last pin)",
				Location: t.Name,
			})
		case pinned != ToolHash(t):
			findings = append(findings, Finding{
				Category: CatRugPull,
				Severity: SevCritical,
				Rule:     "rug-pull",
				Detail:   fmt.Sprintf("tool definition changed since it was pinned (%s… → %s…)", pinned[:8], ToolHash(t)[:8]),
				Location: t.Name,
			})
		}
	}
	return findings
}
