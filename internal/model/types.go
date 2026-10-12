package model

import "github.com/cedar2025/xboard-node/internal/config"

type NodeSpec struct {
	Protocol        string
	ListenIP        string
	ServerPort      int
	Network         string
	NetworkSettings map[string]any
	Routes          []RouteRule

	KernelType       string
	KernelLogLevel   string
	CustomOutbounds  []OutboundConfig
	CustomRoutes     []map[string]any
	CustomRouteRules []CustomRouteRule
	RuleSets         []RuleSet
	ConfigVersion    uint64
	RouteProfiles    []RouteProfile
	CertConfig       *config.CertConfig
	AutoTLS          bool
	Domain           string

	// Mihomo is the panel-generated mihomo document fragment (listeners,
	// rule-providers, rules, sub-rules, sniffer). Nil for legacy payloads.
	Mihomo *MihomoConfig
	// UsersShape is the `users` container the active listener expects.
	UsersShape string

	Cipher    string
	Plugin    string
	PluginOpt string
	ServerKey string

	TLS         int
	Flow        string
	Decryption  string
	TLSSettings map[string]any

	Host       string
	ServerName string

	Version      int
	UpMbps       int
	DownMbps     int
	Obfs         string
	ObfsPassword string

	CongestionControl string
	PaddingScheme     string
	Transport         string
	TrafficPattern    string

	Multiplex           *MultiplexConfig
	AcceptProxyProtocol bool
}

type OutboundConfig struct {
	Tag      string
	Protocol string
	Settings map[string]any
	ProxyTag string
	// Normalized marks panel templates whose common schema must be translated
	// into the native schema of the selected kernel.
	Normalized bool
}

type RouteProfile struct {
	ID          string
	Name        string
	OutboundTag string
}

type RuleSet struct {
	Tag     string
	Mihomo  *MihomoRuleSet
	Singbox *SingboxRuleSet
	Xray    *XrayRuleSet
}

// MihomoRuleSet is one mihomo `rule-providers` entry.
type MihomoRuleSet struct {
	Type      string
	Behavior  string
	Format    string
	URL       string
	Path      string
	Interval  int
	Proxy     string
	SizeLimit int
	Header    map[string][]string
	Payload   []string
}

// MihomoConfig is the mihomo document fragment produced by the panel.
type MihomoConfig struct {
	Listeners     []map[string]any
	RuleProviders map[string]any
	Rules         []string
	SubRules      map[string][]string
	Sniffer       map[string]any
}

// MihomoUsersShape enumerates the `users` container shapes mihomo accepts.
const (
	MihomoUsersMap               = "map"
	MihomoUsersArrayUserPassword = "array_user_password"
	MihomoUsersArrayUUID         = "array_uuid"
	MihomoUsersArrayPassword     = "array_password"
)

type SingboxRuleSet struct {
	Type           string
	Format         string
	URL            string
	Path           string
	DownloadDetour string
	UpdateInterval string
}

type XrayRuleSet struct {
	Type     string
	Tag      string
	URL      string
	FileName string
}

type RouteRule struct {
	ID          int
	Match       []string
	Action      string
	ActionValue string
}

type MultiplexConfig struct {
	Enabled        bool
	Protocol       string
	MaxConnections int
	MinStreams     int
	MaxStreams     int
	Padding        bool
	Brutal         *BrutalConfig
}

type BrutalConfig struct {
	Enabled  bool
	UpMbps   int
	DownMbps int
}

type UserSpec struct {
	ID          int
	UUID        string
	SpeedLimit  int
	DeviceLimit int
	Identities  []UserIdentity
}

type UserIdentity struct {
	ProfileID   string
	ProfileName string
	UUID        string
	AuthUser    string
	OutboundTag string
}

func (n *NodeSpec) GetProxyProtocol() bool {
	if n == nil {
		return false
	}
	if n.AcceptProxyProtocol {
		return true
	}
	if n.NetworkSettings != nil {
		if v, ok := n.NetworkSettings["acceptProxyProtocol"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return false
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneMapSlice(src []map[string]any) []map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(src))
	for _, item := range src {
		out = append(out, cloneAnyMap(item))
	}
	return out
}

func cloneStringSliceMap(src map[string][]string) map[string][]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string][]string, len(src))
	for key, values := range src {
		out[key] = cloneStringSlice(values)
	}
	return out
}

func cloneStringSlice(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}
