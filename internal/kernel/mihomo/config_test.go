package mihomo

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func testSpec(shape string) *model.NodeSpec {
	return &model.NodeSpec{
		Protocol:   "vless",
		KernelType: "mihomo",
		UsersShape: shape,
		Mihomo: &model.MihomoConfig{
			Listeners: []map[string]any{{
				"name":   "hk-1",
				"type":   "vless",
				"listen": "0.0.0.0",
				"port":   "8443",
			}},
			RuleProviders: map[string]any{
				"ai": map[string]any{"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.com/ai.yaml"},
			},
			Rules: []string{"RULE-SET,ai,DIRECT", "MATCH,DIRECT"},
			SubRules: map[string][]string{
				"streaming": {"DOMAIN-SUFFIX,netflix.com,warp"},
			},
			Sniffer: map[string]any{"enable": true},
		},
		RouteProfiles: []model.RouteProfile{{ID: "profile-1", Name: "HK exit", OutboundTag: "warp"}},
		CustomOutbounds: []model.OutboundConfig{{
			Tag:      "warp",
			Protocol: "socks5",
			Settings: map[string]any{"server": "127.0.0.1", "server_port": 1080},
		}},
	}
}

func testUsers() []model.UserSpec {
	return []model.UserSpec{
		{
			ID:   7,
			UUID: "11111111-1111-1111-1111-111111111111",
			Identities: []model.UserIdentity{{
				ProfileID: "profile-1",
				UUID:      "22222222-2222-2222-2222-222222222222",
				AuthUser:  "xb:u:7:rp:profile-1",
			}},
		},
		{ID: 8, UUID: "33333333-3333-3333-3333-333333333333"},
	}
}

func TestBuildConfigInjectsUsersMapShape(t *testing.T) {
	doc, err := BuildConfig(testSpec(model.MihomoUsersMap), testUsers(), kernel.TLSCert{}, Options{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	listeners, ok := doc["listeners"].([]map[string]any)
	if !ok || len(listeners) != 1 {
		t.Fatalf("expected one listener, got %#v", doc["listeners"])
	}
	users, ok := listeners[0]["users"].(map[string]string)
	if !ok {
		t.Fatalf("expected map users, got %#v", listeners[0]["users"])
	}
	if users["xb:u:7"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("base user missing: %#v", users)
	}
	if users["xb:u:7:rp:profile-1"] != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("route profile identity missing: %#v", users)
	}
	if users["xb:u:8"] != "33333333-3333-3333-3333-333333333333" {
		t.Errorf("second user missing: %#v", users)
	}
}

func TestBuildConfigShapesUsersPerInbound(t *testing.T) {
	cases := []struct {
		shape string
		check func(t *testing.T, users any)
	}{
		{
			shape: model.MihomoUsersArrayUUID,
			check: func(t *testing.T, users any) {
				list, ok := users.([]map[string]any)
				if !ok || len(list) != 3 {
					t.Fatalf("expected 3 array entries, got %#v", users)
				}
				if list[0]["uuid"] != "11111111-1111-1111-1111-111111111111" {
					t.Errorf("uuid missing: %#v", list[0])
				}
				if _, hasPassword := list[0]["password"]; hasPassword {
					t.Errorf("array_uuid must not carry a password: %#v", list[0])
				}
			},
		},
		{
			shape: model.MihomoUsersArrayUserPassword,
			check: func(t *testing.T, users any) {
				list, ok := users.([]map[string]any)
				if !ok || len(list) != 3 {
					t.Fatalf("expected 3 array entries, got %#v", users)
				}
				if list[0]["password"] == nil {
					t.Errorf("password missing: %#v", list[0])
				}
			},
		},
		{
			shape: model.MihomoUsersArrayPassword,
			check: func(t *testing.T, users any) {
				list, ok := users.([]map[string]any)
				if !ok || len(list) != 3 {
					t.Fatalf("expected 3 array entries, got %#v", users)
				}
				if list[0]["username"] != "xb:u:7" {
					t.Errorf("username missing: %#v", list[0])
				}
			},
		},
		{
			// Single-credential inbounds must not carry a users list at all.
			shape: "",
			check: func(t *testing.T, users any) {
				if users != nil {
					t.Fatalf("expected no users for a single-credential inbound, got %#v", users)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.shape, func(t *testing.T) {
			doc, err := BuildConfig(testSpec(tc.shape), testUsers(), kernel.TLSCert{}, Options{})
			if err != nil {
				t.Fatalf("BuildConfig: %v", err)
			}
			tc.check(t, doc["listeners"].([]map[string]any)[0]["users"])
		})
	}
}

func TestBuildConfigRouteProfileRules(t *testing.T) {
	doc, err := BuildConfig(testSpec(model.MihomoUsersMap), testUsers(), kernel.TLSCert{}, Options{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	rules, ok := doc["rules"].([]string)
	if !ok || len(rules) == 0 {
		t.Fatalf("expected rules, got %#v", doc["rules"])
	}
	if rules[0] != "IN-USER,xb:u:7:rp:profile-1,warp" {
		t.Errorf("route profile rule must come first, got %q", rules[0])
	}
	// The panel's own rules and the terminal MATCH must survive.
	if rules[len(rules)-1] != "MATCH,DIRECT" {
		t.Errorf("terminal MATCH missing: %#v", rules)
	}
}

func TestBuildConfigPassesThroughRouting(t *testing.T) {
	doc, err := BuildConfig(testSpec(model.MihomoUsersMap), testUsers(), kernel.TLSCert{}, Options{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if _, ok := doc["rule-providers"].(map[string]any)["ai"]; !ok {
		t.Errorf("rule providers must pass through")
	}
	if _, ok := doc["sub-rules"].(map[string][]string)["streaming"]; !ok {
		t.Errorf("sub rules must pass through")
	}
	if doc["sniffer"] == nil {
		t.Errorf("sniffer must pass through")
	}
}

func TestBuildConfigCustomOutboundBecomesProxy(t *testing.T) {
	doc, err := BuildConfig(testSpec(model.MihomoUsersMap), testUsers(), kernel.TLSCert{}, Options{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	proxies, ok := doc["proxies"].([]map[string]any)
	if !ok || len(proxies) != 1 {
		t.Fatalf("expected one proxy, got %#v", doc["proxies"])
	}
	if proxies[0]["name"] != "warp" || proxies[0]["type"] != "socks5" {
		t.Errorf("unexpected proxy: %#v", proxies[0])
	}
	if proxies[0]["port"] != 1080 {
		t.Errorf("server_port must map to port: %#v", proxies[0])
	}
}

func TestBuildConfigInjectsTLSMaterial(t *testing.T) {
	tls := kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")}
	doc, err := BuildConfig(testSpec(model.MihomoUsersArrayUUID), testUsers(), tls, Options{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	listener := doc["listeners"].([]map[string]any)[0]
	if listener["certificate"] != "CERT" || listener["private-key"] != "KEY" {
		t.Errorf("TLS material must be injected: %#v", listener)
	}
}

func TestBuildConfigKeepsPanelTLSMaterial(t *testing.T) {
	spec := testSpec(model.MihomoUsersArrayUUID)
	spec.Mihomo.Listeners[0]["certificate"] = "PANEL-CERT"
	spec.Mihomo.Listeners[0]["private-key"] = "PANEL-KEY"

	doc, err := BuildConfig(spec, testUsers(), kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")}, Options{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	listener := doc["listeners"].([]map[string]any)[0]
	if listener["certificate"] != "PANEL-CERT" {
		t.Errorf("panel TLS material must win: %#v", listener)
	}
}

func TestBuildConfigExternalController(t *testing.T) {
	opts := Options{ExternalController: "127.0.0.1:19090", Secret: "s3cret", LogLevel: "info", Kernel: config.KernelConfig{}}
	doc, err := BuildConfig(testSpec(model.MihomoUsersMap), testUsers(), kernel.TLSCert{}, opts)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if doc["external-controller"] != "127.0.0.1:19090" || doc["secret"] != "s3cret" {
		t.Errorf("controller settings missing: %#v", doc)
	}
	if doc["log-level"] != "info" {
		t.Errorf("log level not applied: %#v", doc["log-level"])
	}
}

func TestBuildConfigRejectsMissingListeners(t *testing.T) {
	spec := &model.NodeSpec{Protocol: "vless"}
	if _, err := BuildConfig(spec, nil, kernel.TLSCert{}, Options{}); err == nil {
		t.Fatal("expected an error when the panel payload has no mihomo listeners")
	}
}

func TestBuildConfigMergesLocalOverride(t *testing.T) {
	opts := Options{
		ExtraProxies: []map[string]any{{"name": "local-warp", "type": "socks5", "server": "127.0.0.1", "port": 1081}},
		CustomConfig: map[string]any{
			// A local rule must win over the generated policy.
			"rules": []string{"DOMAIN-SUFFIX,internal.example,DIRECT"},
			// Maps merge recursively.
			"profile": map[string]any{"store-selected": true},
			// Scalars are replaced.
			"log-level": "debug",
		},
	}
	doc, err := BuildConfig(testSpec(model.MihomoUsersMap), testUsers(), kernel.TLSCert{}, opts)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	rules := doc["rules"].([]string)
	if rules[0] != "DOMAIN-SUFFIX,internal.example,DIRECT" {
		t.Errorf("local rules must be prepended, got %#v", rules)
	}
	if doc["log-level"] != "debug" {
		t.Errorf("local scalars must win, got %#v", doc["log-level"])
	}
	profile, _ := doc["profile"].(map[string]any)
	if profile["store-selected"] != true || profile["store-fake-ip"] != false {
		t.Errorf("maps must merge recursively, got %#v", profile)
	}
	proxies, _ := doc["proxies"].([]map[string]any)
	if len(proxies) != 2 || proxies[1]["name"] != "local-warp" {
		t.Errorf("local proxies must be appended, got %#v", proxies)
	}
}
