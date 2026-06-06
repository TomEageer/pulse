// Command warden is an inline security gateway and scanner for Model Context
// Protocol servers. It inspects MCP traffic for tool poisoning, rug pulls,
// prompt injection in tool results, and credential exfiltration — fully
// offline, no LLM, no data leaves the process.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/TomEageer/mcp-warden/internal/client"
	"github.com/TomEageer/mcp-warden/internal/config"
	"github.com/TomEageer/mcp-warden/internal/detect"
	"github.com/TomEageer/mcp-warden/internal/proxy"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "pin":
		err = cmdPin(os.Args[2:])
	case "proxy":
		err = cmdProxy(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("mcp-warden", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mcp-warden — security gateway & scanner for MCP servers

usage:
  warden scan  <server-url> [--lock warden.lock.json]   audit a server's tools (CI-friendly)
  warden pin   <server-url> [--out warden.lock.json]    record approved tool hashes
  warden proxy [--config warden.json]                   run the inline security gateway
  warden version
`)
}

// cmdScan audits a live server's tools and exits non-zero on a critical finding.
func cmdScan(args []string) error {
	url, rest := arg0(args)
	if url == "" {
		return fmt.Errorf("scan requires a server URL")
	}
	lock := flagValue(rest, "--lock", "")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tools, err := client.New(url).ListTools(ctx)
	if err != nil {
		return err
	}

	findings := detect.ScanTools(tools)
	if lock != "" {
		if base, err := loadBaseline(lock); err == nil {
			findings = append(findings, base.Check(tools)...)
		}
	}

	fmt.Printf("scanned %d tools at %s\n", len(tools), url)
	printFindings(findings)
	if anyCritical(findings) {
		return fmt.Errorf("%d finding(s), critical issues present", len(findings))
	}
	return nil
}

// cmdPin records the current tool set as the approved baseline.
func cmdPin(args []string) error {
	url, rest := arg0(args)
	if url == "" {
		return fmt.Errorf("pin requires a server URL")
	}
	out := flagValue(rest, "--out", "warden.lock.json")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tools, err := client.New(url).ListTools(ctx)
	if err != nil {
		return err
	}
	base := detect.Pin(tools)
	b, _ := json.MarshalIndent(base, "", "  ")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("pinned %d tools to %s\n", len(base), out)
	return nil
}

// cmdProxy runs the inline gateway.
func cmdProxy(args []string) error {
	cfgPath := flagValue(args, "--config", "warden.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config %s: %w", cfgPath, err)
	}
	if cfg.Upstream == "" {
		return fmt.Errorf("config %q has no upstream MCP server URL", cfgPath)
	}

	var baseline detect.Baseline
	if cfg.Lockfile != "" {
		if b, err := loadBaseline(cfg.Lockfile); err == nil {
			baseline = b
		}
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	audit := log
	if cfg.AuditLog != "" {
		f, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("open audit log: %w", err)
		}
		defer f.Close()
		audit = slog.New(slog.NewJSONHandler(f, nil))
	}

	p := proxy.New(cfg, baseline, audit, log)
	log.Info("warden proxy started", "listen", cfg.Listen, "upstream", cfg.Upstream,
		"blockOnCritical", cfg.BlockOnCritical, "pinnedTools", len(baseline))
	srv := &http.Server{Addr: cfg.Listen, Handler: p, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}

func loadBaseline(path string) (detect.Baseline, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var base detect.Baseline
	return base, json.Unmarshal(b, &base)
}

func printFindings(findings []detect.Finding) {
	if len(findings) == 0 {
		fmt.Println("no findings — clean")
		return
	}
	for _, f := range findings {
		fmt.Printf("  [%s] %s/%s @ %s: %s\n", f.Severity, f.Category, f.Rule, f.Location, f.Detail)
	}
}

func anyCritical(findings []detect.Finding) bool {
	for _, f := range findings {
		if f.Severity == detect.SevCritical {
			return true
		}
	}
	return false
}

// arg0 splits the first positional argument from the rest.
func arg0(args []string) (string, []string) {
	if len(args) == 0 || (len(args[0]) > 0 && args[0][0] == '-') {
		return "", args
	}
	return args[0], args[1:]
}

// flagValue returns the value following name, or def.
func flagValue(args []string, name, def string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return def
}
