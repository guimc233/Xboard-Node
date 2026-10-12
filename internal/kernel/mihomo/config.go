// Package mihomo runs a mihomo (Clash.Meta) instance for a single node.
//
// Unlike sing-box and Xray, mihomo keeps its listener/route/tunnel state in
// process-global variables, so one mihomo instance is one OS process. The
// backend therefore writes a config.yaml into the node's runtime directory,
// spawns the mihomo binary, and drives it through the external-controller REST
// API for accounting and connection control.
package mihomo

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

// Options control the runtime-facing parts of the generated document.
type Options struct {
	Kernel config.KernelConfig
	// ExternalController is the host:port the agent will talk to. Empty
	// disables the API (and therefore accounting).
	ExternalController string
	// Secret is the bearer token for the external controller.
	Secret string
	// LogLevel is the mihomo log level (silent, error, warning, info, debug).
	LogLevel string
}

// BuildConfig renders the complete mihomo configuration document for a node.
//
// The panel already produces the kernel-native parts (listeners,
// rule-providers, rules, sub-rules, sniffer). This function adds the runtime
// envelope (controller, logging, geo data), injects the per-user credential
// list in the shape the listener expects, and materialises custom outbounds as
// mihomo proxies so rule actions can target them.
func BuildConfig(spec *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert, opts Options) (map[string]any, error) {
	if spec == nil {
		return nil, fmt.Errorf("mihomo: node spec is required")
	}

	doc := baseConfig(spec, opts)

	listeners, err := buildListeners(spec, users, tls)
	if err != nil {
		return nil, err
	}
	if len(listeners) > 0 {
		doc["listeners"] = listeners
	}

	if proxies := buildProxies(spec); len(proxies) > 0 {
		doc["proxies"] = proxies
	}

	rules := buildRules(spec, users)
	if len(rules) > 0 {
		doc["rules"] = rules
	}
	if spec.Mihomo != nil {
		if len(spec.Mihomo.RuleProviders) > 0 {
			doc["rule-providers"] = spec.Mihomo.RuleProviders
		}
		if len(spec.Mihomo.SubRules) > 0 {
			doc["sub-rules"] = spec.Mihomo.SubRules
		}
		if len(spec.Mihomo.Sniffer) > 0 {
			doc["sniffer"] = spec.Mihomo.Sniffer
		}
	}

	return doc, nil
}

// baseConfig emits the top-level options a proxy node needs. It deliberately
// keeps DNS/proxy-group defaults minimal: the panel's routing template and the
// listener rule set own the policy.
func baseConfig(spec *model.NodeSpec, opts Options) map[string]any {
	doc := map[string]any{
		"mode":      "rule",
		"log-level": firstNonEmpty(opts.LogLevel, spec.KernelLogLevel, "warning"),
		"ipv6":      true,
		"allow-lan": true,
		// A proxy node serves listeners; it must not also open the local
		// mixed-port proxy, so the port keys are explicitly disabled.
		"mixed-port":     0,
		"port":           0,
		"socks-port":     0,
		"tcp-concurrent": true,
		"unified-delay":  true,
		"profile": map[string]any{
			"store-selected": false,
			"store-fake-ip":  false,
		},
	}

	if opts.ExternalController != "" {
		doc["external-controller"] = opts.ExternalController
		if opts.Secret != "" {
			doc["secret"] = opts.Secret
		}
	}

	if dir := strings.TrimSpace(opts.Kernel.GeoDataDir); dir != "" {
		// Keep the geo databases shared between nodes instead of duplicating
		// them per runtime directory.
		doc["geodata-mode"] = false
	}

	return doc
}

type userEntry struct {
	Username string
	UUID     string
	Password string
}

// buildListeners clones the panel listeners and injects the user list.
func buildListeners(spec *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) ([]map[string]any, error) {
	if spec.Mihomo == nil || len(spec.Mihomo.Listeners) == 0 {
		return nil, fmt.Errorf("mihomo: node %q has no mihomo listeners in its config; upgrade the panel or re-save the node", spec.Protocol)
	}

	shape := strings.TrimSpace(spec.UsersShape)
	entries := userEntries(users)

	listeners := make([]map[string]any, 0, len(spec.Mihomo.Listeners))
	for _, raw := range spec.Mihomo.Listeners {
		listener := deepCopyMap(raw)

		if tls.HasCert() && !hasTLSMaterial(listener) {
			listener["certificate"] = string(tls.CertPEM)
			listener["private-key"] = string(tls.KeyPEM)
		}

		if shaped := shapeUsers(shape, entries); shaped != nil {
			listener["users"] = shaped
		}

		listeners = append(listeners, listener)
	}
	return listeners, nil
}

func hasTLSMaterial(listener map[string]any) bool {
	cert, _ := listener["certificate"].(string)
	key, _ := listener["private-key"].(string)
	return cert != "" && key != ""
}

// userEntries flattens panel users and their routing identities into the
// credential set the listener authenticates. The panel's `auth_user` is the
// stable login name; for the base identity it is derived from the user id.
func userEntries(users []model.UserSpec) []userEntry {
	entries := make([]userEntry, 0, len(users))
	for _, user := range users {
		if user.UUID == "" {
			continue
		}
		entries = append(entries, userEntry{
			Username: fmt.Sprintf("xb:u:%d", user.ID),
			UUID:     user.UUID,
			Password: user.UUID,
		})
		for _, identity := range user.Identities {
			username := strings.TrimSpace(identity.AuthUser)
			if username == "" {
				username = fmt.Sprintf("xb:u:%d:rp:%s", user.ID, identity.ProfileID)
			}
			credential := identity.UUID
			if credential == "" {
				credential = user.UUID
			}
			entries = append(entries, userEntry{
				Username: username,
				UUID:     credential,
				Password: credential,
			})
		}
	}
	return entries
}

// shapeUsers renders the container mihomo expects for the inbound type.
// A nil result means the inbound authenticates with a single credential
// (shadowsocks, snell) and must not carry a users list.
func shapeUsers(shape string, entries []userEntry) any {
	if shape == "" || len(entries) == 0 {
		return nil
	}

	switch shape {
	case model.MihomoUsersMap:
		out := make(map[string]string, len(entries))
		for _, entry := range entries {
			out[entry.Username] = entry.Password
		}
		return out
	case model.MihomoUsersArrayUserPassword:
		out := make([]map[string]any, 0, len(entries))
		for _, entry := range entries {
			out = append(out, map[string]any{"username": entry.Username, "password": entry.Password})
		}
		return out
	case model.MihomoUsersArrayUUID:
		out := make([]map[string]any, 0, len(entries))
		for _, entry := range entries {
			out = append(out, map[string]any{"username": entry.Username, "uuid": entry.UUID})
		}
		return out
	case model.MihomoUsersArrayPassword:
		out := make([]map[string]any, 0, len(entries))
		for _, entry := range entries {
			out = append(out, map[string]any{"username": entry.Username, "password": entry.Password})
		}
		return out
	default:
		return nil
	}
}

// buildRules prepends the per-route-profile dispatch rules. mihomo selects an
// exit with IN-USER, which is how the panel's route profiles are expressed for
// this kernel.
func buildRules(spec *model.NodeSpec, users []model.UserSpec) []string {
	var rules []string

	profilesByUser := routeProfileTargets(spec, users)
	if len(profilesByUser) > 0 {
		ordered := make([]string, 0, len(profilesByUser))
		for username := range profilesByUser {
			ordered = append(ordered, username)
		}
		sort.Strings(ordered)
		for _, username := range ordered {
			rules = append(rules, fmt.Sprintf("IN-USER,%s,%s", username, profilesByUser[username]))
		}
	}

	if spec.Mihomo != nil {
		rules = append(rules, spec.Mihomo.Rules...)
	}

	// The panel's rules already terminate with MATCH; add a default only when
	// nothing else would catch the traffic.
	if !hasMatchRule(rules) {
		rules = append(rules, "MATCH,DIRECT")
	}
	return rules
}

// routeProfileTargets maps each identity's auth-user to its outbound tag.
func routeProfileTargets(spec *model.NodeSpec, users []model.UserSpec) map[string]string {
	if len(spec.RouteProfiles) == 0 || len(users) == 0 {
		return nil
	}
	byProfile := make(map[string]string, len(spec.RouteProfiles))
	for _, profile := range spec.RouteProfiles {
		if profile.ID == "" || strings.TrimSpace(profile.OutboundTag) == "" {
			continue
		}
		byProfile[profile.ID] = profile.OutboundTag
	}
	if len(byProfile) == 0 {
		return nil
	}

	out := map[string]string{}
	for _, user := range users {
		for _, identity := range user.Identities {
			target, ok := byProfile[identity.ProfileID]
			if !ok {
				continue
			}
			username := strings.TrimSpace(identity.AuthUser)
			if username == "" {
				continue
			}
			out[username] = target
		}
	}
	return out
}

func hasMatchRule(rules []string) bool {
	for _, rule := range rules {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(rule)), "MATCH,") {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
