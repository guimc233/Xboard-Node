package model

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var ruleSetTagPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func ValidateRuleSets(ruleSets []RuleSet, kernelType string) (map[string]struct{}, error) {
	available := make(map[string]struct{}, len(ruleSets))
	for index, ruleSet := range ruleSets {
		tag := strings.TrimSpace(ruleSet.Tag)
		if tag == "" || !ruleSetTagPattern.MatchString(tag) {
			return nil, fmt.Errorf("rule_sets[%d].tag is invalid", index)
		}
		key := strings.ToLower(tag)
		if _, exists := available[key]; exists {
			return nil, fmt.Errorf("rule_sets[%d].tag %q is duplicated", index, tag)
		}
		available[key] = struct{}{}

		if err := validateMihomoRuleSet(index, ruleSet.Mihomo); err != nil {
			return nil, err
		}
	}
	return available, nil
}

func ValidateRouteRuleSetReferences(rules []CustomRouteRule, available map[string]struct{}) error {
	for ruleIndex, rule := range rules {
		for setIndex, tag := range rule.Match.RuleSets {
			key := strings.ToLower(strings.TrimSpace(tag))
			if _, exists := available[key]; !exists {
				return fmt.Errorf("custom_route_rules[%d].match.rule_sets[%d] references unknown rule set %q", ruleIndex, setIndex, tag)
			}
		}
	}
	return nil
}

// validateMihomoRuleSet checks one mihomo rule-provider entry. The enum values
// mirror the kernel exactly: an unknown type/behavior/format aborts the whole
// config there, so it must be caught before the node is started.
func validateMihomoRuleSet(index int, ruleSet *MihomoRuleSet) error {
	if ruleSet == nil {
		return fmt.Errorf("rule_sets[%d].mihomo is required for mihomo", index)
	}

	typeName := strings.ToLower(strings.TrimSpace(ruleSet.Type))
	if typeName == "" {
		typeName = "http"
	}
	switch typeName {
	case "http", "file", "inline":
	default:
		return fmt.Errorf("rule_sets[%d].mihomo.type must be http, file or inline", index)
	}

	behavior := strings.ToLower(strings.TrimSpace(ruleSet.Behavior))
	switch behavior {
	case "domain", "ipcidr", "classical":
	default:
		return fmt.Errorf("rule_sets[%d].mihomo.behavior must be domain, ipcidr or classical", index)
	}

	format := strings.ToLower(strings.TrimSpace(ruleSet.Format))
	if format == "" {
		format = "yaml"
	}
	switch format {
	case "yaml", "text", "mrs":
	default:
		return fmt.Errorf("rule_sets[%d].mihomo.format must be yaml, text or mrs", index)
	}
	// MRS is a binary format whose header encodes domain/ipcidr only.
	if format == "mrs" && behavior == "classical" {
		return fmt.Errorf("rule_sets[%d].mihomo.format mrs does not support the classical behavior", index)
	}

	switch typeName {
	case "http":
		return validateHTTPURL(ruleSet.URL, fmt.Sprintf("rule_sets[%d].mihomo.url", index))
	case "file":
		if strings.TrimSpace(ruleSet.Path) == "" {
			return fmt.Errorf("rule_sets[%d].mihomo.path is required for a local rule provider", index)
		}
	case "inline":
		if len(ruleSet.Payload) == 0 {
			return fmt.Errorf("rule_sets[%d].mihomo.payload is required for an inline rule provider", index)
		}
		for lineIndex, line := range ruleSet.Payload {
			trimmed := strings.ToUpper(strings.TrimSpace(line))
			if behavior == "classical" &&
				(strings.HasPrefix(trimmed, "MATCH,") ||
					strings.HasPrefix(trimmed, "RULE-SET,") ||
					strings.HasPrefix(trimmed, "SUB-RULE,")) {
				return fmt.Errorf("rule_sets[%d].mihomo.payload[%d] cannot use MATCH, RULE-SET or SUB-RULE inside a classical provider", index, lineIndex)
			}
		}
	}
	return nil
}

func validateHTTPURL(value, field string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return fmt.Errorf("%s must be an http(s) URL", field)
	}
	return nil
}
