package model

import (
	"fmt"
	"net/url"
	"path/filepath"
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

		switch kernelType {
		case "mihomo":
			if err := validateMihomoRuleSet(index, ruleSet.Mihomo); err != nil {
				return nil, err
			}
		case "singbox":
			if err := validateSingboxRuleSet(index, ruleSet.Singbox); err != nil {
				return nil, err
			}
		case "xray":
			if err := validateXrayRuleSet(index, ruleSet.Xray); err != nil {
				return nil, err
			}
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

func validateSingboxRuleSet(index int, ruleSet *SingboxRuleSet) error {
	if ruleSet == nil {
		return fmt.Errorf("rule_sets[%d].singbox is required for sing-box", index)
	}
	typeName := strings.ToLower(strings.TrimSpace(ruleSet.Type))
	if typeName == "" {
		typeName = "remote"
	}
	if typeName != "remote" && typeName != "local" {
		return fmt.Errorf("rule_sets[%d].singbox.type must be remote or local", index)
	}
	format := strings.ToLower(strings.TrimSpace(ruleSet.Format))
	if format != "binary" && format != "source" {
		return fmt.Errorf("rule_sets[%d].singbox.format must be binary or source", index)
	}
	if typeName == "remote" {
		return validateHTTPURL(ruleSet.URL, fmt.Sprintf("rule_sets[%d].singbox.url", index))
	}
	if strings.TrimSpace(ruleSet.Path) == "" {
		return fmt.Errorf("rule_sets[%d].singbox.path is required for a local rule set", index)
	}
	return nil
}

func validateXrayRuleSet(index int, ruleSet *XrayRuleSet) error {
	if ruleSet == nil {
		return fmt.Errorf("rule_sets[%d].xray is required for Xray", index)
	}
	typeName := strings.ToLower(strings.TrimSpace(ruleSet.Type))
	switch typeName {
	case "geosite", "geoip":
		if strings.TrimSpace(ruleSet.Tag) == "" {
			return fmt.Errorf("rule_sets[%d].xray.tag is required", index)
		}
	case "ext-domain", "ext-ip":
		if strings.TrimSpace(ruleSet.Tag) == "" {
			return fmt.Errorf("rule_sets[%d].xray.tag is required", index)
		}
		fileName := strings.TrimSpace(ruleSet.FileName)
		if fileName == "" || filepath.Base(fileName) != fileName {
			return fmt.Errorf("rule_sets[%d].xray.file_name must be a base file name", index)
		}
		if strings.TrimSpace(ruleSet.URL) != "" {
			return validateHTTPURL(ruleSet.URL, fmt.Sprintf("rule_sets[%d].xray.url", index))
		}
	default:
		return fmt.Errorf("rule_sets[%d].xray.type %q is unsupported", index, ruleSet.Type)
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
