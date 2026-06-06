// Package proxy is Warden's inline MCP security gateway. It sits between an MCP
// client and the real server, inspects JSON-RPC traffic in both directions, and
// (optionally) blocks messages that trip a critical detector.
package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/TomEageer/mcp-warden/internal/config"
	"github.com/TomEageer/mcp-warden/internal/detect"
	"github.com/TomEageer/mcp-warden/internal/mcp"
)

// Proxy inspects and forwards MCP traffic.
type Proxy struct {
	cfg      config.Config
	baseline detect.Baseline
	client   *http.Client
	audit    *slog.Logger
	log      *slog.Logger
}

// New builds a proxy. audit receives one structured record per request.
func New(cfg config.Config, baseline detect.Baseline, audit, log *slog.Logger) *Proxy {
	return &Proxy{
		cfg:      cfg,
		baseline: baseline,
		client:   &http.Client{Timeout: 60 * time.Second},
		audit:    audit,
		log:      log,
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var req mcp.Message
	_ = json.Unmarshal(body, &req) // best-effort; non-JSON-RPC bodies still forward

	// --- Request-side inspection (before forwarding) ---
	reqFindings, toolName := p.inspectRequest(req)
	if p.cfg.BlockOnCritical && hasCritical(reqFindings) {
		p.record(req.Method, toolName, reqFindings, detect.Block, "request")
		p.writeBlock(w, req.ID, reqFindings)
		return
	}

	// --- Forward to upstream ---
	resp, respBody, err := p.forward(r, body)
	if err != nil {
		p.log.Error("upstream error", "err", err)
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}

	// --- Response-side inspection ---
	respFindings := p.inspectResponse(req.Method, toolName, respBody)
	all := append(reqFindings, respFindings...)

	if p.cfg.BlockOnCritical && hasCritical(respFindings) {
		p.record(req.Method, toolName, all, detect.Block, "response")
		p.writeBlock(w, req.ID, respFindings)
		return
	}

	decision := detect.Allow
	if len(all) > 0 {
		decision = detect.Warn
	}
	p.record(req.Method, toolName, all, decision, "forwarded")

	// Pass the upstream response through unchanged.
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

func (p *Proxy) inspectRequest(req mcp.Message) ([]detect.Finding, string) {
	if req.Method != "tools/call" || len(req.Params) == 0 {
		return nil, ""
	}
	var params mcp.ToolCallParams
	_ = json.Unmarshal(req.Params, &params)
	findings := detect.ScanSecrets("tools/call arguments for "+params.Name, string(params.Arguments))
	return findings, params.Name
}

func (p *Proxy) inspectResponse(reqMethod, toolName string, respBody []byte) []detect.Finding {
	var findings []detect.Finding

	var msg mcp.Message
	if err := json.Unmarshal(respBody, &msg); err == nil && len(msg.Result) > 0 {
		switch reqMethod {
		case "tools/list":
			var res mcp.ToolsListResult
			if json.Unmarshal(msg.Result, &res) == nil {
				findings = append(findings, detect.ScanTools(res.Tools)...)
				findings = append(findings, p.baseline.Check(res.Tools)...)
			}
		case "tools/call":
			var res mcp.ToolCallResult
			if json.Unmarshal(msg.Result, &res) == nil {
				findings = append(findings, detect.ScanResult(toolName, res)...)
				var sb strings.Builder
				for _, b := range res.Content {
					sb.WriteString(b.Text)
					sb.WriteByte('\n')
				}
				findings = append(findings, detect.ScanSecrets("result of "+toolName, sb.String())...)
			}
		}
	}
	// Fallback: scan the raw body for secrets even if it wasn't JSON we parsed
	// (e.g. SSE framing). Dedupe is unnecessary — different location strings.
	if reqMethod != "tools/call" {
		findings = append(findings, detect.ScanSecrets("response body", string(respBody))...)
	}
	return findings
}

func (p *Proxy) forward(r *http.Request, body []byte) (*http.Response, []byte, error) {
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, p.cfg.Upstream, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	for k, vv := range r.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vv {
			upReq.Header.Add(k, v)
		}
	}
	resp, err := p.client.Do(upReq)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return resp, respBody, err
}

func (p *Proxy) writeBlock(w http.ResponseWriter, id json.RawMessage, findings []detect.Finding) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	data, _ := json.Marshal(map[string]any{"warden": "blocked", "findings": findings})
	out := mcp.Message{
		JSONRPC: "2.0",
		ID:      id,
		Error: &mcp.RPCError{
			Code:    -32001,
			Message: "blocked by mcp-warden security policy",
			Data:    data,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors ride on HTTP 200
	_ = json.NewEncoder(w).Encode(out)
}

func (p *Proxy) record(method, tool string, findings []detect.Finding, decision detect.Decision, stage string) {
	p.audit.Info("mcp",
		"method", method,
		"tool", tool,
		"decision", string(decision),
		"stage", stage,
		"findings", findings,
	)
	for _, f := range findings {
		p.log.Warn("finding",
			"severity", string(f.Severity),
			"category", string(f.Category),
			"rule", f.Rule,
			"location", f.Location,
			"detail", f.Detail,
		)
	}
}

func hasCritical(findings []detect.Finding) bool {
	for _, f := range findings {
		if f.Severity == detect.SevCritical {
			return true
		}
	}
	return false
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
