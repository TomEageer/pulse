package detect

import (
	"fmt"
	"regexp"
)

type secretRule struct {
	name string
	re   *regexp.Regexp
}

// secretRules match high-confidence credential shapes. Warden flags these when
// they appear in tool-call arguments (a tool trying to siphon a secret) or in
// tool results (a server leaking one).
var secretRules = []secretRule{
	{"aws-access-key-id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"github-token", regexp.MustCompile(`gh[opsru]_[A-Za-z0-9]{36,}`)},
	{"slack-token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"openai-key", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"private-key-block", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
}

// ScanSecrets reports credential-shaped strings in a blob (JSON args or result
// text). location describes where the blob came from.
func ScanSecrets(location string, blob string) []Finding {
	var findings []Finding
	for _, r := range secretRules {
		if r.re.MatchString(blob) {
			findings = append(findings, Finding{
				Category: CatExfiltration,
				Severity: SevCritical,
				Rule:     "secret:" + r.name,
				Detail:   fmt.Sprintf("%s detected in %s", r.name, location),
				Location: location,
			})
		}
	}
	return findings
}
