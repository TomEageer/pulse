package detect

import (
	"fmt"

	"github.com/TomEageer/mcp-warden/internal/mcp"
)

// ScanResult inspects a tools/call result for prompt injection: a tool whose
// output tries to steer the agent (e.g. "ignore previous instructions") or
// hides directives in invisible unicode. This is the runtime counterpart to
// tool poisoning — the attack arrives in data, not metadata.
func ScanResult(toolName string, res mcp.ToolCallResult) []Finding {
	var findings []Finding
	for _, block := range res.Content {
		if block.Type != "text" || block.Text == "" {
			continue
		}
		matches, invisible := scanInjection(block.Text)
		for _, m := range matches {
			findings = append(findings, Finding{
				Category: CatInjection,
				Severity: SevCritical,
				Rule:     "result-injection",
				Detail:   fmt.Sprintf("tool result contains an instruction-like phrase: %q", m),
				Location: toolName,
			})
		}
		if invisible {
			findings = append(findings, Finding{
				Category: CatInjection,
				Severity: SevWarning,
				Rule:     "result-invisible-unicode",
				Detail:   "tool result contains zero-width or unicode-tag characters",
				Location: toolName,
			})
		}
	}
	return findings
}
