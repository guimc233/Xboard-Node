package kernel

import (
	"strings"

	"github.com/cedar2025/xboard-node/internal/model"
)

func NeedsGeoIPRules(rules []model.CustomRouteRule) bool {
	for _, r := range rules {
		for _, v := range r.Match.IPCIDRs {
			if strings.HasPrefix(v, "geoip:") {
				return true
			}
		}
		for _, v := range r.Match.SourceCIDRs {
			if strings.HasPrefix(v, "geoip:") {
				return true
			}
		}
	}
	return false
}

func NeedsGeoSiteRules(rules []model.CustomRouteRule) bool {
	for _, r := range rules {
		for _, v := range r.Match.Domains {
			if strings.HasPrefix(v, "geosite:") {
				return true
			}
		}
		for _, v := range r.Match.DomainSuffixes {
			if strings.HasPrefix(v, "geosite:") {
				return true
			}
		}
	}
	return false
}

// NeedsDomainSniffing reports whether routing contains a domain-aware matcher.
// Proxy clients may send an already-resolved IP address to the server. In that
// case TLS/HTTP/QUIC sniffing is required before domain and domain rule-set
// matches can work.
func NeedsDomainSniffing(routes []model.RouteRule, rules []model.CustomRouteRule, raw []map[string]any) bool {
	for _, route := range routes {
		for _, match := range route.Match {
			match = strings.TrimSpace(match)
			if match != "" && !strings.Contains(match, "/") {
				return true
			}
		}
	}

	for _, rule := range rules {
		if rule.Disabled {
			continue
		}
		if len(rule.Match.RuleSets) > 0 || len(rule.Match.Domains) > 0 || len(rule.Match.DomainSuffixes) > 0 {
			return true
		}
	}

	for _, rule := range raw {
		for _, key := range []string{"domain", "domain_suffix", "domain_keyword", "domain_regex", "geosite", "rule_set"} {
			if hasRouteValues(rule[key]) {
				return true
			}
		}
	}
	return false
}

func hasRouteValues(value any) bool {
	switch values := value.(type) {
	case string:
		return strings.TrimSpace(values) != ""
	case []string:
		for _, item := range values {
			if strings.TrimSpace(item) != "" {
				return true
			}
		}
	case []any:
		for _, item := range values {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				return true
			}
		}
	}
	return false
}
