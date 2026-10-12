package mihomo

import (
	"strings"

	"github.com/cedar2025/xboard-node/internal/model"
)

// proxyTypeAliases maps the panel's protocol names to mihomo's `type:` strings.
var proxyTypeAliases = map[string]string{
	"shadowsocks": "ss",
	"ss":          "ss",
	"socks":       "socks5",
	"socks5":      "socks5",
	"vmess":       "vmess",
	"vless":       "vless",
	"trojan":      "trojan",
	"http":        "http",
	"wireguard":   "wireguard",
	"hysteria":    "hysteria",
	"hysteria2":   "hysteria2",
	"tuic":        "tuic",
	"anytls":      "anytls",
	"snell":       "snell",
	"mieru":       "mieru",
	"ssr":         "ssr",
	"sudoku":      "sudoku",
	"shadowquic":  "shadowquic",
	"trusttunnel": "trusttunnel",
	"ssh":         "ssh",
}

// buildProxies materialises the panel's custom outbounds as mihomo proxies.
// Rule actions reference them by tag, so the proxy name is the panel tag.
func buildProxies(spec *model.NodeSpec) []map[string]any {
	if len(spec.CustomOutbounds) == 0 {
		return nil
	}

	proxies := make([]map[string]any, 0, len(spec.CustomOutbounds))
	for _, outbound := range spec.CustomOutbounds {
		name := strings.TrimSpace(outbound.Tag)
		if name == "" {
			continue
		}
		protocol := strings.ToLower(strings.TrimSpace(outbound.Protocol))
		proxyType, ok := proxyTypeAliases[protocol]
		if !ok {
			// Unknown protocols are skipped rather than emitted with a type
			// mihomo would reject ("unsupport proxy type").
			continue
		}

		settings := outbound.Settings
		if settings == nil {
			settings = map[string]any{}
		}

		proxy := map[string]any{
			"name": name,
			"type": proxyType,
		}

		if server := firstSettings(settings, "server", "address", "host"); server != nil {
			proxy["server"] = server
		}
		if port := firstSettings(settings, "server_port", "port"); port != nil {
			proxy["port"] = port
		}
		if dialer := strings.TrimSpace(outbound.ProxyTag); dialer != "" {
			proxy["dialer-proxy"] = dialer
		}

		copyProxySetting(proxy, settings, "udp", "udp")
		copyProxySetting(proxy, settings, "username", "username")
		copyProxySetting(proxy, settings, "password", "password")
		copyProxySetting(proxy, settings, "uuid", "uuid")
		copyProxySetting(proxy, settings, "flow", "flow")
		copyProxySetting(proxy, settings, "network", "network")
		copyProxySetting(proxy, settings, "servername", "server_name")
		copyProxySetting(proxy, settings, "servername", "servername")
		copyProxySetting(proxy, settings, "sni", "sni")
		copyProxySetting(proxy, settings, "skip-cert-verify", "allow_insecure")
		copyProxySetting(proxy, settings, "client-fingerprint", "client_fingerprint")
		copyProxySetting(proxy, settings, "tfo", "tfo")
		copyProxySetting(proxy, settings, "mptcp", "mptcp")

		switch proxyType {
		case "ss":
			copyProxySetting(proxy, settings, "cipher", "cipher")
			copyProxySetting(proxy, settings, "cipher", "method")
		case "vmess", "vless":
			// VMess/VLESS use `servername`; a `sni` key is silently ignored.
			if _, ok := proxy["servername"]; !ok {
				copyProxySetting(proxy, settings, "servername", "sni")
			}
			if _, ok := proxy["tls"]; !ok {
				copyBoolSetting(proxy, settings, "tls", "tls")
			}
		case "trojan", "anytls", "hysteria", "hysteria2", "tuic", "shadowquic":
			// These are TLS-only or use `sni` instead of `servername`.
			if _, ok := proxy["sni"]; !ok {
				copyProxySetting(proxy, settings, "sni", "server_name")
			}
		}

		// vless supports both ws and grpc service names; keep them if present.
		copyProxySetting(proxy, settings, "ws-path", "path")
		copyProxySetting(proxy, settings, "grpc-service-name", "service_name")

		proxies = append(proxies, proxy)
	}
	return proxies
}

func firstSettings(settings map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := settings[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

func copyProxySetting(dst, src map[string]any, dstKey, srcKey string) {
	if _, exists := dst[dstKey]; exists {
		return
	}
	if value, ok := src[srcKey]; ok && value != nil {
		dst[dstKey] = value
	}
}

func copyBoolSetting(dst, src map[string]any, dstKey, srcKey string) {
	if _, exists := dst[dstKey]; exists {
		return
	}
	switch value := src[srcKey].(type) {
	case bool:
		dst[dstKey] = value
	case int:
		dst[dstKey] = value != 0
	case float64:
		dst[dstKey] = value != 0
	}
}
