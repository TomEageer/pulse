package detect

import (
	"fmt"

	"github.com/TomEageer/mcp-warden/internal/mcp"
)

// ScanTool inspects a single tool descriptor for poisoning: hidden instructions
// in the name, description, or input schema, and invisible unicode smuggling.
func ScanTool(t mcp.Tool) []Finding {
	var findings []Finding
	surface := t.Name + "\n" + t.Description + "\n" + string(t.InputSchema)

	matches, invisible := scanInjection(surface)
	for _, m := range matches {
		findings = append(findings, Finding{
			Category: CatToolPoisoning,
			Severity: SevCritical,
			Rule:     "hidden-instruction",
			Detail:   fmt.Sprintf("tool metadata contains an instruction-like phrase: %q", m),
			Location: t.Name,
		})
	}
	if invisible {
		findings = append(findings, Finding{
			Category: CatToolPoisoning,
			Severity: SevCritical,
			Rule:     "invisible-unicode",
			Detail:   "tool metadata contains zero-width or unicode-tag characters (possible hidden instructions)",
			Location: t.Name,
		})
	}
	return findings
}

// ScanTools inspects every tool in a tools/list result.
func ScanTools(tools []mcp.Tool) []Finding {
	var findings []Finding
	for _, t := range tools {
		findings = append(findings, ScanTool(t)...)
	}
	return findings
}
