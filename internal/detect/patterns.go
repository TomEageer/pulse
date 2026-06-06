package detect

import (
	"regexp"
	"strings"
)

// injectionPhrases are instruction-like strings that should never appear in a
// tool description (tool poisoning) or a tool result (prompt injection). They
// target the model, not the user.
var injectionPhrases = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore (all |any |the )?(previous|prior|above|earlier) (instructions|prompts|context)`),
	regexp.MustCompile(`(?i)disregard (the |all |any )?(previous|prior|above|system)`),
	regexp.MustCompile(`(?i)do not (tell|inform|mention to|reveal to) (the )?(user|human)`),
	regexp.MustCompile(`(?i)without (telling|informing|alerting) the user`),
	regexp.MustCompile(`(?i)you (must|should) (now |always )?(send|forward|exfiltrate|leak|post) .{0,40}(to|http)`),
	regexp.MustCompile(`(?i)new (system )?(instructions?|prompt|directive)\s*[:\-]`),
	regexp.MustCompile(`(?i)</?(system|important|secret|instructions?)>`),
	regexp.MustCompile(`(?i)\boverride\b.{0,30}\b(system|safety|policy|guardrails?)\b`),
	regexp.MustCompile(`(?i)read .{0,30}(\.env|id_rsa|credentials|secrets?)\b`),
}

// hasInvisibleRunes flags runes used to smuggle hidden instructions past human
// review: zero-width characters and the BOM (U+200B, U+200C, U+200D, U+FEFF),
// plus the Unicode "tag" block (U+E0000–U+E007F) which renders as nothing but
// is readable by an LLM.
func hasInvisibleRunes(s string) bool {
	for _, r := range s {
		switch r {
		case 0x200B, 0x200C, 0x200D, 0xFEFF:
			return true
		}
		if r >= 0xE0000 && r <= 0xE007F {
			return true
		}
	}
	return false
}

// scanInjection returns the phrases matched in s, plus whether invisible runes
// were present.
func scanInjection(s string) (matches []string, invisible bool) {
	for _, re := range injectionPhrases {
		if loc := re.FindString(s); loc != "" {
			matches = append(matches, strings.TrimSpace(loc))
		}
	}
	return matches, hasInvisibleRunes(s)
}
