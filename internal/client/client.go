// Package client is a minimal MCP client over the Streamable HTTP transport —
// just enough to initialize a session and read tools/list, which is what
// `warden scan` and `warden pin` need.
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/TomEageer/mcp-warden/internal/mcp"
)

// Client speaks JSON-RPC to an MCP server endpoint.
type Client struct {
	url     string
	http    *http.Client
	session string
	id      int
}

// New returns a client for the given Streamable HTTP endpoint URL.
func New(url string) *Client {
	return &Client{url: url, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) call(ctx context.Context, method string, params any) (mcp.Message, error) {
	c.id++
	reqBody, _ := json.Marshal(mcp.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(fmt.Sprintf("%d", c.id)),
		Method:  method,
		Params:  mustRaw(params),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqBody))
	if err != nil {
		return mcp.Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return mcp.Message{}, err
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.session = sid
	}
	if resp.StatusCode >= 400 {
		return mcp.Message{}, fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	return parseResponse(resp)
}

// notify sends a JSON-RPC notification (no id, no response expected).
func (c *Client) notify(ctx context.Context, method string) {
	b, _ := json.Marshal(mcp.Message{JSONRPC: "2.0", Method: method})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if resp, err := c.http.Do(req); err == nil {
		resp.Body.Close()
	}
}

// ListTools performs the initialize handshake and returns the server's tools.
func (c *Client) ListTools(ctx context.Context) ([]mcp.Tool, error) {
	if _, err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcp-warden", "version": "0.1.0"},
	}); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	c.notify(ctx, "notifications/initialized")

	msg, err := c.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	if msg.Error != nil {
		return nil, fmt.Errorf("tools/list: %s", msg.Error.Message)
	}
	var res mcp.ToolsListResult
	if err := json.Unmarshal(msg.Result, &res); err != nil {
		return nil, fmt.Errorf("decode tools: %w", err)
	}
	return res.Tools, nil
}

// parseResponse handles both application/json and text/event-stream bodies,
// returning the first JSON-RPC message that carries a result or error.
func parseResponse(resp *http.Response) (mcp.Message, error) {
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
		for scanner.Scan() {
			line := scanner.Text()
			data, ok := strings.CutPrefix(line, "data:")
			if !ok {
				continue
			}
			var m mcp.Message
			if json.Unmarshal([]byte(strings.TrimSpace(data)), &m) == nil && m.IsResponse() {
				return m, nil
			}
		}
		return mcp.Message{}, fmt.Errorf("no JSON-RPC response in event stream")
	}
	var m mcp.Message
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&m); err != nil {
		return mcp.Message{}, err
	}
	return m, nil
}

func mustRaw(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	return b
}
