package model

import (
	"fmt"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
)

func ValidateNodeSpec(n *NodeSpec, kcfg config.KernelConfig) error {
	if n == nil {
		return nil
	}

	effectiveKernelType := strings.TrimSpace(kcfg.Type)
	if effectiveKernelType == "" {
		effectiveKernelType = strings.TrimSpace(n.KernelType)
	}
	kernelType, err := normalizeKernelType(effectiveKernelType)
	if err != nil {
		return fmt.Errorf("normalize kernel type: %w", err)
	}

	additionalOutboundSources, err := collectAdditionalOutboundTagSources(kcfg.CustomConfig, kcfg.CustomOutbound)
	if err != nil {
		return fmt.Errorf("collect additional outbound tags: %w", err)
	}
	if err := validateOutboundTagCollisions(n.CustomOutbounds, additionalOutboundSources); err != nil {
		return fmt.Errorf("validate outbound tags: %w", err)
	}
	additionalTags := additionalTagNames(additionalOutboundSources)
	availableTags := buildAvailableOutboundTags(n.CustomOutbounds, additionalTags)
	if err := ValidateCustomOutboundsForKernel(n.CustomOutbounds, kernelType, additionalTags); err != nil {
		return fmt.Errorf("validate custom outbounds: %w", err)
	}
	availableRuleSets, err := ValidateRuleSets(n.RuleSets, kernelType)
	if err != nil {
		return fmt.Errorf("validate rule sets: %w", err)
	}
	if err := ValidateRouteRuleSetReferences(n.CustomRouteRules, availableRuleSets); err != nil {
		return fmt.Errorf("validate route rule sets: %w", err)
	}
	if err := ValidateCustomRouteRules(n.CustomRouteRules, kernelType, availableTags); err != nil {
		return fmt.Errorf("validate custom route rules: %w", err)
	}
	if len(n.RouteProfiles) > 0 {
		for i, profile := range n.RouteProfiles {
			if strings.TrimSpace(profile.ID) == "" {
				return fmt.Errorf("route_profiles[%d].id is required", i)
			}
			tag := strings.ToLower(strings.TrimSpace(profile.OutboundTag))
			if _, ok := availableTags[tag]; !ok {
				return fmt.Errorf("route_profiles[%d].outbound_tag references unknown outbound %q", i, profile.OutboundTag)
			}
		}
	}
	return nil
}

// normalizeKernelType accepts the mihomo aliases and defaults an empty value
// to mihomo. sing-box and Xray are retired, so anything else is rejected.
func normalizeKernelType(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "mihomo", "clash", "clashmeta", "clash-meta", "clash.meta", "meta":
		return "mihomo", nil
	default:
		return "", fmt.Errorf("unsupported kernel type %q (only mihomo is supported)", value)
	}
}

func buildAvailableOutboundTags(structured []OutboundConfig, rawTags []string) map[string]struct{} {
	available := map[string]struct{}{
		"direct": {},
		"block":  {},
	}
	for _, outbound := range structured {
		tag := strings.ToLower(strings.TrimSpace(outbound.Tag))
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	for _, tag := range rawTags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	return available
}
