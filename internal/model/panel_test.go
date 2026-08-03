package model

import (
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestNodeSpecFromPanelValidated(t *testing.T) {
	t.Run("promote legacy flat Shadowsocks outbound for both kernels", func(t *testing.T) {
		node, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol: "tuic", ServerPort: 8443,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "awssg", Protocol: "shadowsocks",
				Settings: map[string]any{"address": "13.228.73.171", "port": 8388, "method": "chacha20-ietf-poly1305", "password": "secret"},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err != nil {
			t.Fatal(err)
		}
		outbound := node.CustomOutbounds[0]
		if !outbound.Normalized || outbound.Settings["server"] != "13.228.73.171" || outbound.Settings["server_port"] != 8388 {
			t.Fatalf("legacy outbound not normalized: %#v", outbound)
		}
		if _, exists := outbound.Settings["address"]; exists {
			t.Fatal("legacy address field must be removed")
		}
	})

	t.Run("accept normalized templates and Reality route profiles", func(t *testing.T) {
		node, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol: "vless", TLS: 2, ServerPort: 443, ConfigVersion: 7,
			OutboundTemplates: []panel.OutboundConfig{{
				Tag: "proxy", Protocol: "socks5", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080},
			}},
			RouteProfiles: []panel.RouteProfile{{ID: "profile-1", Name: "Proxy", OutboundTag: "proxy"}},
		}, config.KernelConfig{Type: "xray"})
		if err != nil {
			t.Fatalf("NodeSpecFromPanelValidated: %v", err)
		}
		if node.ConfigVersion != 7 || !node.CustomOutbounds[0].Normalized || node.CustomOutbounds[0].Protocol != "socks" {
			t.Fatalf("unexpected normalized node: %#v", node)
		}
	})

	t.Run("reject VLESS profiles without Reality", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol: "vless", TLS: 1, ServerPort: 443,
			RouteProfiles: []panel.RouteProfile{{ID: "profile-1", OutboundTag: "direct"}},
		}, config.KernelConfig{Type: "xray"})
		if err == nil || !strings.Contains(err.Error(), "VLESS route profiles require a Reality inbound") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("accept Shadowsocks route profiles", func(t *testing.T) {
		node, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol: "shadowsocks", ServerPort: 8388,
			OutboundTemplates: []panel.OutboundConfig{{
				Tag: "hinet", Protocol: "vless", Settings: map[string]any{
					"server": "hinet.example", "server_port": 10086,
					"uuid": "11111111-2222-4333-8444-555555555555", "network": "tcp", "tls": false,
				},
			}},
			RouteProfiles: []panel.RouteProfile{{ID: "profile-hinet", Name: "HiNet", OutboundTag: "hinet"}},
		}, config.KernelConfig{Type: "singbox"})
		if err != nil {
			t.Fatalf("NodeSpecFromPanelValidated: %v", err)
		}
		if len(node.RouteProfiles) != 1 || node.RouteProfiles[0].OutboundTag != "hinet" {
			t.Fatalf("unexpected route profiles: %#v", node.RouteProfiles)
		}
	})

	t.Run("valid custom outbounds and route targets", func(t *testing.T) {
		node, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{
				{Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"server": "1.1.1.1", "server_port": 2408, "private_key": "pk"}},
				{Tag: "proxy", Protocol: "socks", ProxyTag: "warp", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}},
			},
			CustomRouteRules: []panel.CustomRouteRule{{
				Action: panel.RouteAction{Type: "route", Target: "proxy"},
				Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err != nil {
			t.Fatalf("NodeSpecFromPanelValidated: %v", err)
		}
		if node == nil || len(node.CustomOutbounds) != 2 {
			t.Fatalf("unexpected node spec: %#v", node)
		}
	})

	t.Run("invalid custom outbounds", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "proxy", Protocol: "socks", ProxyTag: "missing", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `custom_outbounds[0].proxy_tag references unknown outbound "missing"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("reject unsupported protocol for kernel", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "hy2", Protocol: "hysteria2", Settings: map[string]any{"server": "2.2.2.2", "server_port": 8443},
			}},
		}, config.KernelConfig{Type: "xray"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `protocol "hysteria2" is not supported by kernel "xray"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("reject unknown route target", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"server": "1.1.1.1", "server_port": 2408, "private_key": "pk"},
			}},
			CustomRouteRules: []panel.CustomRouteRule{{
				Action: panel.RouteAction{Type: "route", Target: "missing"},
				Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `custom_route_rules[0].action.target references unknown outbound "missing"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
