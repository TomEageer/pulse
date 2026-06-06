// Package config loads Warden's JSON configuration. JSON (not YAML) keeps
// Warden dependency-free — a deliberate choice for a security tool that sits in
// the trust path.
package config

import (
	"encoding/json"
	"os"
)

// Config controls the proxy.
type Config struct {
	// Listen is the address Warden listens on for MCP clients.
	Listen string `json:"listen"`
	// Upstream is the real MCP server URL Warden forwards to.
	Upstream string `json:"upstream"`
	// Lockfile pins approved tool hashes (see `warden pin`). Empty disables
	// rug-pull detection.
	Lockfile string `json:"lockfile"`
	// AuditLog is a path for JSONL audit records. Empty logs to stderr.
	AuditLog string `json:"auditLog"`
	// BlockOnCritical drops the offending message (returning a JSON-RPC error)
	// when a critical finding fires. When false, Warden only records.
	BlockOnCritical bool `json:"blockOnCritical"`
}

// Default returns config with sensible zero-config values.
func Default() Config {
	return Config{
		Listen:          "127.0.0.1:7000",
		Upstream:        "",
		Lockfile:        "warden.lock.json",
		BlockOnCritical: true,
	}
}

// Load reads a JSON config file, applying defaults for unset fields.
func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
