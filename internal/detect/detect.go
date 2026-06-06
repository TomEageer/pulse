// Package detect contains Warden's security inspectors. Every inspector is a
// pure function over MCP messages — no network, no LLM, no data leaves the
// process. This keeps detection deterministic and auditable, and means Warden
// can run fully offline in front of sensitive MCP servers.
package detect

// Severity ranks a finding.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Category groups findings by attack class (loosely tracking the MCP/agentic
// threat taxonomy).
type Category string

const (
	CatToolPoisoning Category = "tool_poisoning"
	CatRugPull       Category = "rug_pull"
	CatInjection     Category = "prompt_injection"
	CatExfiltration  Category = "data_exfiltration"
)

// Finding is a single detected issue.
type Finding struct {
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Rule     string   `json:"rule"`
	Detail   string   `json:"detail"`
	// Where the issue was found, e.g. tool name or RPC method.
	Location string `json:"location"`
}

// Decision is the policy outcome for a set of findings.
type Decision string

const (
	Allow Decision = "allow"
	Warn  Decision = "warn"
	Block Decision = "block"
)
