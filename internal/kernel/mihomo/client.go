package mihomo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one mihomo instance's external controller.
//
// The API is the only way to observe a mihomo process: it exposes the live
// connection table, and that table is the sole source of per-user traffic and
// alive-IP data. See docs-mihomo-kernel.md for the contract and its caveats.
type Client struct {
	baseURL string
	secret  string
	http    *http.Client
}

// NewClient builds a client for 127.0.0.1:<port>. An empty secret disables the
// Authorization header (mihomo then leaves the API unauthenticated).
func NewClient(addr, secret string) *Client {
	addr = strings.TrimSpace(addr)
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	return &Client{
		baseURL: strings.TrimRight(addr, "/"),
		secret:  secret,
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ConnectionSnapshot is the response of GET /connections.
//
// Connections is nil (JSON null) when nothing is connected — never assume a
// non-nil slice.
type ConnectionSnapshot struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Memory        uint64       `json:"memory"`
	Connections   []Connection `json:"connections"`
}

// Connection is one live tracked connection.
type Connection struct {
	ID             string   `json:"id"`
	Upload         int64    `json:"upload"`
	Download       int64    `json:"download"`
	Start          string   `json:"start"`
	Chains         []string `json:"chains"`
	ProviderChains []string `json:"providerChains"`
	Rule           string   `json:"rule"`
	RulePayload    string   `json:"rulePayload"`
	Metadata       Metadata `json:"metadata"`
}

// Metadata mirrors the kernel's connection metadata. The port fields are JSON
// strings (Go `uint16` with `,string`), and `inboundUser` is always present —
// empty when the connection is unauthenticated.
type Metadata struct {
	Network         string `json:"network"`
	Type            string `json:"type"`
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationPort string `json:"destinationPort"`
	InboundIP       string `json:"inboundIP"`
	InboundPort     string `json:"inboundPort"`
	InboundName     string `json:"inboundName"`
	InboundUser     string `json:"inboundUser"`
	Host            string `json:"host"`
	SniffHost       string `json:"sniffHost"`
	Process         string `json:"process"`
	ProcessPath     string `json:"processPath"`
	RemoteDst       string `json:"remoteDestination"`
	DNSMode         string `json:"dnsMode"`
}

// VersionResponse is the response of GET /version.
type VersionResponse struct {
	Meta    bool   `json:"meta"`
	Version string `json:"version"`
}

// Connections fetches the current connection table.
func (c *Client) Connections(ctx context.Context) (*ConnectionSnapshot, error) {
	var snapshot ConnectionSnapshot
	if err := c.do(ctx, http.MethodGet, "/connections", nil, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// Version returns the kernel version string.
func (c *Client) Version(ctx context.Context) (string, error) {
	var response VersionResponse
	if err := c.do(ctx, http.MethodGet, "/version", nil, &response); err != nil {
		return "", err
	}
	return response.Version, nil
}

// CloseConnection terminates one connection. mihomo answers 204 even for an
// unknown id, so a nil error does not prove the connection existed.
func (c *Client) CloseConnection(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	return c.do(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
}

// CloseAllConnections terminates every live connection.
func (c *Client) CloseAllConnections(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/connections", nil, nil)
}

// CloseConnectionsForUser closes every connection authenticated as username and
// returns how many were closed. A per-user credential maps to exactly one
// inbound username, so this is how the agent force-disconnects a user.
func (c *Client) CloseConnectionsForUser(ctx context.Context, username string) (int, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return 0, nil
	}
	snapshot, err := c.Connections(ctx)
	if err != nil {
		return 0, err
	}
	closed := 0
	for _, connection := range snapshot.Connections {
		if connection.Metadata.InboundUser != username {
			continue
		}
		if err := c.CloseConnection(ctx, connection.ID); err != nil {
			return closed, err
		}
		closed++
	}
	return closed, nil
}

// Reload asks the kernel to re-read the config file.
//
// force must be the literal query value `true` to also cycle the legacy
// top-level ports. Note that PUT /configs does NOT reapply controller settings
// (external-controller, secret); use Process.Reload (SIGHUP) for that.
func (c *Client) Reload(ctx context.Context, configPath string) error {
	body := map[string]string{"path": configPath}
	return c.do(ctx, http.MethodPut, "/configs?force=true", body, nil)
}

// ReloadPayload applies config text without touching the file on disk.
func (c *Client) ReloadPayload(ctx context.Context, payload string) error {
	body := map[string]string{"payload": payload}
	return c.do(ctx, http.MethodPut, "/configs?force=true", body, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("mihomo api: encode body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("mihomo api: build request: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.secret != "" {
		request.Header.Set("Authorization", "Bearer "+c.secret)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("mihomo api: %s %s: %w", method, path, err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNoContent {
		return nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("mihomo api: %s %s: unexpected status %d: %s", method, path, response.StatusCode, strings.TrimSpace(string(message)))
	}

	if out == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		return fmt.Errorf("mihomo api: %s %s: decode response: %w", method, path, err)
	}
	return nil
}
