// Package mcp holds minimal JSON-RPC 2.0 and Model Context Protocol message
// types — just enough for Warden to inspect traffic between an MCP client and
// an MCP server. We intentionally keep params/results as raw JSON so unknown
// fields pass through untouched.
package mcp

import "encoding/json"

// Message is a JSON-RPC 2.0 envelope. A single object may be a request,
// response, or notification depending on which fields are populated.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is the JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// IsResponse reports whether the message carries a result or error.
func (m Message) IsResponse() bool { return len(m.Result) > 0 || m.Error != nil }

// Tool is an MCP tool descriptor as returned by tools/list.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ToolsListResult is the result payload of a tools/list response.
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

// ToolCallParams is the params payload of a tools/call request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ContentBlock is one block of a tools/call result. Text is the field Warden
// scans for injection and exfiltration.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolCallResult is the result payload of a tools/call response.
type ToolCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError"`
}
