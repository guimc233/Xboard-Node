package xray

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// M is a shorthand for building JSON-like maps
type M = map[string]interface{}

func buildConfig(kcfg config.KernelConfig, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	var outbounds []M
	tags := make(map[string]bool)

	// Panel-defined custom outbounds (structured, converted to Xray native)
	for _, co := range nc.CustomOutbounds {
		outbounds = append(outbounds, outboundConfigToXray(co))
		tags[strings.ToLower(co.Tag)] = true
	}

	// Static outbounds from local config file
	for _, co := range kcfg.CustomOutbound {
		tag, _ := co["tag"].(string)
		if tag != "" {
			tags[strings.ToLower(tag)] = true
		}
		outbounds = append(outbounds, M(co))
	}

	// Add default outbounds only if not already defined (Issue #1: Panel priority)
	if !tags["direct"] {
		outbounds = append([]M{{"protocol": "freedom", "tag": "direct"}}, outbounds...)
	}
	if !tags["block"] {
		// block is often added after direct but before others for safety
		outbounds = append(outbounds, M{"protocol": "blackhole", "tag": "block"})
	}

	cfg := M{
		"log": M{
			"loglevel": xrayLogLevel(kcfg.LogLevel),
			"error":    "",
			"access":   "",
		},
		"stats": M{},
		"policy": M{
			"levels": M{
				"0": M{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
			"system": M{
				"statsInboundUplink":    true,
				"statsInboundDownlink":  true,
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
		"outbounds": outbounds,
	}

	inbound := buildInbound(nc, users, tc)
	if inbound != nil {
		cfg["inbounds"] = []M{inbound}
	} else {
		nlog.Core().Warn("xray: unsupported protocol, no inbound configured — node will not accept connections",
			"protocol", nc.Protocol,
			"supported", "vmess, vless, trojan, shadowsocks, hysteria, socks, http")
	}

	// Xray does not support sing-box .srs rule_set objects. Expand logical
	// rule-set references to Xray's geosite/geoip/ext selectors instead.
	xrayRouteRules := expandRuleSets(nc.CustomRouteRules, nc.RuleSets)
	mergedCustomRoutes := mergeRouteList(nc.CustomRoutes, kcfg.CustomRoute)
	if inbound != nil && kernel.NeedsDomainSniffing(nc.Routes, xrayRouteRules, mergedCustomRoutes) {
		// Keep the original destination while exposing HTTP Host, TLS SNI, or
		// QUIC SNI to the routing engine. This makes domain rules work even
		// when the client sends an already-resolved IP address.
		inbound["sniffing"] = M{
			"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true,
		}
	}
	cfg["routing"] = buildRouting(nc.Routes, xrayRouteRules, mergedCustomRoutes, users)

	mergeCustomXray(cfg, kcfg)
	return cfg
}

func expandRuleSets(rules []model.CustomRouteRule, ruleSets []model.RuleSet) []model.CustomRouteRule {
	definitions := make(map[string]*model.XrayRuleSet, len(ruleSets))
	for index := range ruleSets {
		if ruleSets[index].Xray != nil {
			definitions[strings.ToLower(strings.TrimSpace(ruleSets[index].Tag))] = ruleSets[index].Xray
		}
	}
	result := make([]model.CustomRouteRule, 0, len(rules))
	for _, rule := range rules {
		for _, logicalTag := range rule.Match.RuleSets {
			definition := definitions[strings.ToLower(strings.TrimSpace(logicalTag))]
			if definition == nil {
				continue
			}
			var selector string
			switch strings.ToLower(strings.TrimSpace(definition.Type)) {
			case "geosite":
				selector = "geosite:" + strings.TrimSpace(definition.Tag)
				rule.Match.Domains = append(rule.Match.Domains, selector)
			case "geoip":
				selector = "geoip:" + strings.TrimSpace(definition.Tag)
				rule.Match.IPCIDRs = append(rule.Match.IPCIDRs, selector)
			case "ext-domain":
				selector = "ext:" + strings.TrimSpace(definition.FileName) + ":" + strings.TrimSpace(definition.Tag)
				rule.Match.Domains = append(rule.Match.Domains, selector)
			case "ext-ip":
				selector = "ext:" + strings.TrimSpace(definition.FileName) + ":" + strings.TrimSpace(definition.Tag)
				rule.Match.IPCIDRs = append(rule.Match.IPCIDRs, selector)
			}
		}
		rule.Match.RuleSets = nil
		result = append(result, rule)
	}
	return result
}

// outboundConfigToXray converts a structured OutboundConfig (from the panel)
// into an Xray outbound object. Xray uses a nested layout where protocol-
// specific fields go inside a "settings" key, and chain proxying uses "proxySettings".
func outboundConfigToXray(oc model.OutboundConfig) M {
	if oc.Normalized {
		return normalizedOutboundToXray(oc)
	}
	m := M{
		"protocol": oc.Protocol,
		"tag":      oc.Tag,
	}
	if len(oc.Settings) > 0 {
		m["settings"] = oc.Settings
	}
	if oc.ProxyTag != "" {
		m["proxySettings"] = M{"tag": oc.ProxyTag}
	}
	return m
}

func normalizedOutboundToXray(oc model.OutboundConfig) M {
	server := M{
		"address": oc.Settings["server"],
		"port":    oc.Settings["server_port"],
	}
	switch strings.ToLower(oc.Protocol) {
	case "shadowsocks":
		server["method"] = oc.Settings["method"]
		server["password"] = oc.Settings["password"]
		return M{"protocol": "shadowsocks", "tag": oc.Tag, "settings": M{"servers": []M{server}}}
	case "socks":
		if username := strings.TrimSpace(fmt.Sprintf("%v", oc.Settings["username"])); username != "" && username != "<nil>" {
			server["users"] = []M{{"user": username, "pass": fmt.Sprintf("%v", oc.Settings["password"])}}
		}
		return M{"protocol": "socks", "tag": oc.Tag, "settings": M{"servers": []M{server}}}
	case "vless":
		user := M{"id": oc.Settings["uuid"], "encryption": "none"}
		if flow := strings.TrimSpace(fmt.Sprintf("%v", oc.Settings["flow"])); flow != "" && flow != "<nil>" {
			user["flow"] = flow
		}
		outbound := M{
			"protocol": "vless", "tag": oc.Tag,
			"settings": M{"vnext": []M{{
				"address": oc.Settings["server"], "port": oc.Settings["server_port"], "users": []M{user},
			}}},
		}
		network := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", oc.Settings["network"])))
		if network == "" || network == "<nil>" {
			network = "tcp"
		}
		stream := M{"network": network}
		if network == "ws" {
			stream["wsSettings"] = M{"path": oc.Settings["path"]}
		}
		if network == "grpc" {
			stream["grpcSettings"] = M{"serviceName": oc.Settings["service_name"]}
		}
		if tlsEnabled, _ := oc.Settings["tls"].(bool); tlsEnabled {
			stream["security"] = "tls"
			stream["tlsSettings"] = M{
				"serverName":    oc.Settings["server_name"],
				"allowInsecure": oc.Settings["allow_insecure"],
			}
		}
		outbound["streamSettings"] = stream
		return outbound
	default:
		return M{"protocol": oc.Protocol, "tag": oc.Tag, "settings": oc.Settings}
	}
}

func mergeRouteList(a, b []map[string]any) []map[string]any {
	res := make([]map[string]any, 0, len(a)+len(b))
	res = append(res, a...)
	res = append(res, b...)
	return res
}

// mergeCustomXray deep-merges a custom Xray config file into the generated config.
// Merge strategy (compatible with V2bX/XrayR custom DNS etc.):
//   - dns: custom replaces auto-generated
//   - outbounds: custom entries appended
//   - routing.rules: custom rules prepended (matched first)
//   - policy, api: custom deep-merges
//   - inbounds: NOT merged (panel-managed, authoritative)
func mergeCustomXray(cfg M, kcfg config.KernelConfig) {
	custom, err := kernel.LoadCustomConfig(kcfg.CustomConfig)
	if err != nil {
		nlog.Core().Error("failed to load custom xray config", "error", err)
		return
	}
	if custom == nil {
		return
	}

	// dns — custom replaces (same as V2bX DnsConfigPath)
	if v, ok := custom["dns"]; ok {
		cfg["dns"] = v
	}

	// outbounds — append custom entries
	if v, ok := custom["outbounds"]; ok {
		if existing, ok := cfg["outbounds"].([]M); ok {
			cfg["outbounds"] = kernel.MergeAppendList(existing, v)
		}
	}

	// routing — merge sub-fields
	if customRouting, ok := custom["routing"]; ok {
		if customRoutingMap, ok := customRouting.(map[string]any); ok {
			mergeCustomXrayRouting(cfg, customRoutingMap)
		}
	}

	// other top-level keys (policy, api, transport, etc.) — custom overrides,
	// but we protect auto-generated inbounds, stats, log, routing, outbounds
	protected := map[string]bool{
		"inbounds": true, "outbounds": true, "routing": true,
		"dns": true, "log": true, "stats": true, "policy": true,
	}
	for k, v := range custom {
		if !protected[k] {
			cfg[k] = v
		}
	}
}

func mergeCustomXrayRouting(cfg M, customRouting map[string]any) {
	routing, ok := cfg["routing"].(M)
	if !ok {
		routing = M{}
		cfg["routing"] = routing
	}

	// rules — custom rules prepended (so they match before panel rules)
	if v, ok := customRouting["rules"]; ok {
		if existing, ok := routing["rules"].([]M); ok {
			routing["rules"] = kernel.MergePrependList(existing, v)
		}
	}

	// domainStrategy, balancers, etc. — custom overrides
	for k, v := range customRouting {
		if k == "rules" {
			continue
		}
		routing[k] = v
	}
}

func xrayLogLevel(singboxLevel string) string {
	switch singboxLevel {
	case "trace", "debug":
		return "debug"
	case "info":
		return "info"
	case "warn":
		return "warning"
	case "error":
		return "error"
	case "fatal", "panic":
		return "error"
	default:
		return "warning"
	}
}

func buildInbound(nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	listenAddr := "::"
	if nc.ListenIP != "" {
		listenAddr = nc.ListenIP
	}
	base := M{
		"tag":      nc.Protocol + "-in",
		"listen":   listenAddr,
		"port":     nc.ServerPort,
		"protocol": nc.Protocol,
		"streamSettings": M{
			"sockopt": M{
				"reusePort": true,
			},
		},
	}

	switch nc.Protocol {
	case "vmess":
		return buildVMess(base, nc, users, tc)
	case "vless":
		return buildVLESS(base, nc, users, tc)
	case "trojan":
		return buildTrojan(base, nc, users, tc)
	case "shadowsocks":
		return buildShadowsocks(base, nc, users)
	case "socks":
		return buildSocks(base, users)
	case "http":
		return buildHTTP(base, nc, users, tc)
	case "hysteria":
		return buildHysteria(base, nc, users, tc)
	default:
		return nil
	}
}

// userEmail returns the stats-tracking email for a user.
// Format: "user@<id>" so we can parse back the user ID from stats counters.
func userEmail(userID int) string {
	return fmt.Sprintf("user@%d", userID)
}

func buildVMess(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	clients := make([]M, 0, len(users))
	for _, u := range users {
		clients = append(clients, M{
			"id":      u.UUID,
			"alterId": 0,
			"email":   userEmail(u.ID),
		})
	}
	base["settings"] = M{"clients": clients}

	applyStreamSettings(base, nc, tc)
	return base
}

func buildVLESS(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	clients := make([]M, 0, len(users))
	for _, u := range users {
		client := M{
			"id":    u.UUID,
			"email": userEmail(u.ID),
		}
		if nc.Flow != "" {
			client["flow"] = nc.Flow
		}
		clients = append(clients, client)
		for _, identity := range u.Identities {
			profileClient := M{"id": identity.UUID, "email": identity.AuthUser}
			if nc.Flow != "" {
				profileClient["flow"] = nc.Flow
			}
			clients = append(clients, profileClient)
		}
	}
	decryption := "none"
	if nc.Decryption != "" {
		decryption = nc.Decryption
	}
	base["settings"] = M{
		"clients":    clients,
		"decryption": decryption,
	}

	applyStreamSettings(base, nc, tc)
	return base
}

func buildTrojan(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	clients := make([]M, 0, len(users))
	for i := range users {
		u := &users[i]
		clients = append(clients, M{
			"password": u.UUID,
			"email":    userEmail(u.ID),
		})
		for _, identity := range u.Identities {
			clients = append(clients, M{
				"password": identity.UUID,
				"email":    identity.AuthUser,
			})
		}
	}
	base["settings"] = M{"clients": clients}

	applyStreamSettings(base, nc, tc)

	// Trojan requires TLS or Reality to be enabled.
	// If the panel didn't explicitly set TLS=1 or TLS=2, but we have certs,
	// we should enable a default TLS config to ensure the inbound can start.
	ss, _ := base["streamSettings"].(M)
	if security, ok := ss["security"].(string); !ok || (security != "tls" && security != "reality") {
		nc.TLS = 1 // Force internal state to trigger TLS build in applyStreamSettings
		applyStreamSettings(base, nc, tc)
	}

	return base
}

type ss2022Config struct {
	method string
	size   int
}

var ss2022Methods = map[string]ss2022Config{
	"2022-blake3-aes-128-gcm":       {"2022-blake3-aes-128-gcm", 16},
	"2022-blake3-aes-256-gcm":       {"2022-blake3-aes-256-gcm", 32},
	"2022-blake3-chacha20-poly1305": {"2022-blake3-chacha20-poly1305", 32},
}

func buildShadowsocks(base M, nc *model.NodeSpec, users []model.UserSpec) M {
	ss2022, isSS2022 := ss2022Methods[nc.Cipher]

	clients := make([]M, 0, len(users))

	if isSS2022 {
		// SS2022: server key at top level, per-user key must be Base64 of fixed-length raw bytes.
		// Only blake3-aes-* supports multi-user in Xray; chacha20 variant is single-user only.
		rawBuf := make([]byte, ss2022.size)
		for i := range users {
			u := &users[i]
			clients = append(clients, M{
				"password": shadowsocks2022UserKey(u.UUID, rawBuf),
				"email":    userEmail(u.ID),
			})
			for _, identity := range u.Identities {
				clients = append(clients, M{
					"password": shadowsocks2022UserKey(identity.UUID, rawBuf),
					"email":    identity.AuthUser,
				})
			}
		}
		base["settings"] = M{
			"method":   nc.Cipher,
			"password": nc.ServerKey,
			"clients":  clients,
			"network":  "tcp,udp",
		}
	} else {
		// Traditional ciphers: multi-user via clients array.
		// Each entry must carry its own "method" field for Xray to parse correctly.
		for i := range users {
			u := &users[i]
			clients = append(clients, M{
				"method":   nc.Cipher,
				"password": u.UUID,
				"email":    userEmail(u.ID),
			})
			for _, identity := range u.Identities {
				clients = append(clients, M{
					"method":   nc.Cipher,
					"password": identity.UUID,
					"email":    identity.AuthUser,
				})
			}
		}
		base["settings"] = M{
			"method":  nc.Cipher,
			"clients": clients,
			"network": "tcp,udp",
		}
	}
	return base
}

func shadowsocks2022UserKey(credential string, rawBuf []byte) string {
	for i := range rawBuf {
		rawBuf[i] = 0
	}
	copy(rawBuf, credential)
	return base64.StdEncoding.EncodeToString(rawBuf)
}

func buildSocks(base M, users []model.UserSpec) M {
	base["protocol"] = "socks"
	accounts := make([]M, 0, len(users))
	for _, u := range users {
		accounts = append(accounts, M{
			"user":  u.UUID,
			"pass":  u.UUID,
			"email": userEmail(u.ID),
		})
	}
	base["settings"] = M{
		"auth":     "password",
		"accounts": accounts,
		"udp":      true,
	}
	return base
}

func buildHTTP(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["protocol"] = "http"
	accounts := make([]M, 0, len(users))
	for _, u := range users {
		accounts = append(accounts, M{
			"user":  u.UUID,
			"pass":  u.UUID,
			"email": userEmail(u.ID),
		})
	}
	base["settings"] = M{
		"accounts": accounts,
	}

	if nc.TLS == 1 {
		applyStreamSettings(base, nc, tc)
	}
	return base
}

// buildHysteria creates a Hysteria v2 inbound for xray-core.
func buildHysteria(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	if nc.Version != 2 {
		nlog.Core().Warn("xray: only supports hysteria v2, skipping v1 inbound")
		return nil
	}

	clients := make([]M, 0, len(users))
	for _, u := range users {
		clients = append(clients, M{
			"auth":  u.UUID,
			"email": userEmail(u.ID),
		})
	}
	base["settings"] = M{"clients": clients}

	ss := M{
		"network": "hysteria",
		"hysteriaSettings": M{
			"version":        nc.Version,
			"udpIdleTimeout": 60,
		},
	}

	if nc.UpMbps > 0 || nc.DownMbps > 0 {
		quicParams := M{}
		if nc.UpMbps > 0 {
			quicParams["brutalUp"] = fmt.Sprintf("%d mbps", nc.UpMbps)
		}
		if nc.DownMbps > 0 {
			quicParams["brutalDown"] = fmt.Sprintf("%d mbps", nc.DownMbps)
		}
		ss["finalMask"] = M{
			"quicParams": quicParams,
		}
	}

	if tc.HasCert() {
		ss["security"] = "tls"
		tlsCert := M{
			"certificate": []string{string(tc.CertPEM)},
			"key":         []string{string(tc.KeyPEM)},
		}
		ss["tlsSettings"] = M{
			"certificates": []M{tlsCert},
			"alpn":         []string{"h3"},
		}
	} else {
		nlog.Core().Warn("hysteria requires TLS certificate files; configure cert_mode (self, file, http, dns, or content)")
	}

	if nc.GetProxyProtocol() {
		ss["sockopt"] = M{"acceptProxyProtocol": true}
	}

	base["streamSettings"] = ss
	return base
}

func applyStreamSettings(base M, nc *model.NodeSpec, tc kernel.TLSCert) {
	ss := M{}

	// Network / transport
	network := nc.Network
	if network == "" {
		network = "tcp"
	}
	ss["network"] = network

	switch network {
	case "ws":
		wsSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				wsSettings["path"] = v
			}
			headers := M{}
			if v, ok := nc.NetworkSettings["headers"]; ok {
				if headersMap, ok := v.(map[string]interface{}); ok {
					for k, val := range headersMap {
						headers[k] = val
					}
				}
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				headers["Host"] = v
			}
			if len(headers) > 0 {
				wsSettings["headers"] = headers
			}
		}
		ss["wsSettings"] = wsSettings

	case "grpc":
		grpcSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["serviceName"]; ok {
				grpcSettings["serviceName"] = v
			} else if v, ok := nc.NetworkSettings["service_name"]; ok {
				grpcSettings["serviceName"] = v
			}
		}
		ss["grpcSettings"] = grpcSettings

	case "httpupgrade":
		huSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				huSettings["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				huSettings["host"] = v
			}
		}
		ss["httpupgradeSettings"] = huSettings

	case "h2", "http":
		ss["network"] = "h2"
		h2Settings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				h2Settings["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				h2Settings["host"] = []interface{}{v}
			}
		}
		ss["httpSettings"] = h2Settings

	case "xhttp", "splithttp":
		ss["network"] = "xhttp"
		xhttpSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				xhttpSettings["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				xhttpSettings["host"] = v
			}
			if v, ok := nc.NetworkSettings["mode"]; ok {
				xhttpSettings["mode"] = v
			}
			if v, ok := nc.NetworkSettings["extra"]; ok {
				// PHP sends empty arrays [] instead of {} for empty objects;
				// xray rejects [] for fields that expect objects (e.g. sockopt, tlsSettings).
				// Recursively strip empty arrays from the extra map before passing to xray.
				if m, ok := v.(map[string]interface{}); ok && len(m) > 0 {
					sanitizeEmptyArrays(m)
					xhttpSettings["extra"] = m
				}
			}
		}
		ss["xhttpSettings"] = xhttpSettings

	case "tcp":
		// default, no extra settings
	}

	// TLS
	if nc.TLS == 1 {
		tlsSettings := M{}
		serverName := nc.ServerName
		if serverName == "" && nc.Host != "" {
			serverName = nc.Host
		}
		if serverName != "" {
			tlsSettings["serverName"] = serverName
		}
		if nc.TLSSettings != nil {
			if sn, ok := nc.TLSSettings["server_name"]; ok && sn != "" {
				tlsSettings["serverName"] = sn
			}
			// ECH server-side: extract key from tls_settings.ech
			if echKeys := extractECHServerKeys(nc.TLSSettings); echKeys != "" {
				tlsSettings["echServerKeys"] = echKeys
			}
		}
		if tc.HasCert() {
			tlsCert := M{
				"certificate": []string{string(tc.CertPEM)},
				"key":         []string{string(tc.KeyPEM)},
			}
			tlsSettings["certificates"] = []M{tlsCert}
		} else {
			// Fallback placeholder for auto-TLS environments.
			// Xray allows empty certificates array in more cases than sing-box,
			// but providing a placeholder helps documentation.
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = tlsSettings
	} else if nc.TLS == 2 {
		ss["security"] = "reality"
		ss["realitySettings"] = buildRealitySettings(nc)
	}

	// Proxy Protocol
	if nc.GetProxyProtocol() {
		sockopt, ok := base["streamSettings"].(M)["sockopt"].(M)
		if !ok {
			sockopt = M{}
		}
		sockopt["acceptProxyProtocol"] = true
		ss["sockopt"] = sockopt
	}

	base["streamSettings"] = ss
}

func buildRealitySettings(nc *model.NodeSpec) M {
	reality := M{"show": false}

	if nc.TLSSettings == nil {
		return reality
	}

	if pk, ok := nc.TLSSettings["private_key"]; ok {
		reality["privateKey"] = pk
	}
	if sid, ok := nc.TLSSettings["short_id"]; ok {
		switch v := sid.(type) {
		case string:
			reality["shortIds"] = []string{v}
		case []interface{}:
			ids := make([]string, 0, len(v))
			for _, item := range v {
				ids = append(ids, fmt.Sprintf("%v", item))
			}
			reality["shortIds"] = ids
		}
	}

	if dest, ok := nc.TLSSettings["dest"]; ok {
		destStr := fmt.Sprintf("%v", dest)
		reality["dest"] = destStr
	}
	if sn, ok := nc.TLSSettings["server_name"]; ok {
		reality["serverNames"] = []string{fmt.Sprintf("%v", sn)}
		if _, exists := reality["dest"]; !exists {
			reality["dest"] = fmt.Sprintf("%v:443", sn)
		}
	}

	return reality
}

func buildRouting(rules []model.RouteRule, customRouteRules []model.CustomRouteRule, customRules []map[string]any, userSets ...[]model.UserSpec) M {
	var xrayRules []M

	// Structured custom routes now take the highest priority for panel-managed overrides.
	for _, rule := range customRouteRules {
		if rule.Disabled {
			continue
		}
		xrayRules = append(xrayRules, compileCustomRouteRule(rule)...)
	}

	// Raw custom routes remain the escape hatch, but no longer outrank structured rules.
	for _, cr := range customRules {
		xrayRules = append(xrayRules, M(cr))
	}

	xrayRules = append(xrayRules, M{
		"type": "field",
		"ip": []string{
			"10.0.0.0/8",
			"100.64.0.0/10",
			"127.0.0.0/8",
			"169.254.0.0/16",
			"172.16.0.0/12",
			"192.0.0.0/24",
			"192.168.0.0/16",
			"198.18.0.0/15",
			"fc00::/7",
			"fe80::/10",
			"::1/128",
		},
		"outboundTag": "block",
	})

	for _, rule := range rules {
		xrayRules = append(xrayRules, compilePanelRouteRule(rule)...)
	}

	// An alternate authenticated credential selects a default outbound without
	// a second listening port. Explicit domain/IP policies above still win.
	if len(userSets) > 0 {
		for _, user := range userSets[0] {
			for _, identity := range user.Identities {
				if identity.AuthUser == "" || identity.OutboundTag == "" {
					continue
				}
				xrayRules = append(xrayRules, M{
					"type": "field", "user": []string{identity.AuthUser}, "outboundTag": identity.OutboundTag,
				})
			}
		}
	}

	return M{
		"domainStrategy": "AsIs",
		"rules":          xrayRules,
	}
}

func compilePanelRouteRule(rule model.RouteRule) []M {
	if len(rule.Match) == 0 {
		return nil
	}
	match := model.RouteMatch{}
	for _, item := range rule.Match {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "geoip:") || strings.Contains(item, "/") {
			match.IPCIDRs = append(match.IPCIDRs, item)
			continue
		}
		if strings.HasPrefix(item, "geosite:") {
			match.Domains = append(match.Domains, item)
			continue
		}
		match.DomainSuffixes = append(match.DomainSuffixes, strings.TrimPrefix(item, "*."))
	}
	action := model.RouteAction{Type: "block"}
	switch rule.Action {
	case "direct":
		action.Type = "direct"
	case "proxy":
		action.Type = "route"
		action.Target = rule.ActionValue
	}
	return compileCustomRouteRule(model.CustomRouteRule{Match: match, Action: action})
}

func compileCustomRouteRule(rule model.CustomRouteRule) []M {
	outbound := xrayOutboundForAction(rule.Action)
	var compiled []M

	if len(rule.Match.Domains) > 0 || len(rule.Match.DomainSuffixes) > 0 {
		domains := make([]string, 0, len(rule.Match.Domains)+len(rule.Match.DomainSuffixes))
		for _, value := range rule.Match.Domains {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			domains = append(domains, value)
		}
		for _, value := range rule.Match.DomainSuffixes {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			domains = append(domains, "domain:"+value)
		}
		if len(domains) > 0 {
			compiled = append(compiled, M{
				"type":        "field",
				"domain":      domains,
				"outboundTag": outbound,
			})
		}
	}
	if len(rule.Match.IPCIDRs) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"ip":          copyStrings(rule.Match.IPCIDRs),
			"outboundTag": outbound,
		})
	}
	if len(rule.Match.Ports) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"port":        strings.Join(rule.Match.Ports, ","),
			"outboundTag": outbound,
		})
	}
	if len(rule.Match.Networks) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"network":     strings.Join(rule.Match.Networks, ","),
			"outboundTag": outbound,
		})
	}
	if len(rule.Match.SourceCIDRs) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"source":      copyStrings(rule.Match.SourceCIDRs),
			"outboundTag": outbound,
		})
	}
	if len(rule.Match.SourcePorts) > 0 {
		compiled = append(compiled, M{
			"type":        "field",
			"sourcePort":  strings.Join(rule.Match.SourcePorts, ","),
			"outboundTag": outbound,
		})
	}
	return compiled
}

func xrayOutboundForAction(action model.RouteAction) string {
	switch action.Type {
	case "direct":
		return "direct"
	case "route":
		if action.Target != "" {
			return action.Target
		}
		return "block"
	default:
		return "block"
	}
}

func copyStrings(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// sanitizeEmptyArrays recursively removes empty slices from a map.
// PHP encodes empty objects as [] instead of {}; xray-core rejects []
// for fields that expect struct types (e.g. sockopt, tlsSettings).
func sanitizeEmptyArrays(m map[string]interface{}) {
	for k, v := range m {
		switch val := v.(type) {
		case []interface{}:
			if len(val) == 0 {
				delete(m, k)
			}
		case map[string]interface{}:
			sanitizeEmptyArrays(val)
		}
	}
}

// extractECHServerKeys extracts the ECH private key from tls_settings.ech
// and converts it from PEM to base64 for xray-core's echServerKeys field.
func extractECHServerKeys(tlsSettings map[string]interface{}) string {
	echRaw, ok := tlsSettings["ech"]
	if !ok {
		return ""
	}
	echMap, ok := echRaw.(map[string]interface{})
	if !ok {
		return ""
	}
	enabled, _ := echMap["enabled"].(bool)
	if !enabled {
		return ""
	}

	// Try inline key first, then key_path
	var pemData []byte
	if key, _ := echMap["key"].(string); key != "" {
		pemData = []byte(key)
	} else if keyPath, _ := echMap["key_path"].(string); keyPath != "" {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			nlog.Core().Warn("ECH enabled but key_path read failed", "error", err)
			return ""
		}
		pemData = data
	} else {
		nlog.Core().Warn("ECH enabled but no key or key_path provided")
		return ""
	}

	return echPEMToBase64(pemData)
}

// echPEMToBase64 parses an "ECH KEYS" PEM block and returns base64 of the raw bytes.
// If the input is not valid PEM or has the wrong type, it returns empty string.
func echPEMToBase64(data []byte) string {
	trimmed := strings.TrimSpace(string(data))
	if !strings.Contains(trimmed, "-----") {
		// Assume already raw base64
		return trimmed
	}
	block, _ := pem.Decode(data)
	if block == nil {
		nlog.Core().Warn("ECH key: invalid PEM data")
		return ""
	}
	if block.Type != "ECH KEYS" {
		nlog.Core().Warn("ECH key: unexpected PEM type", "expected", "ECH KEYS", "got", block.Type)
		return ""
	}
	return base64.StdEncoding.EncodeToString(block.Bytes)
}
