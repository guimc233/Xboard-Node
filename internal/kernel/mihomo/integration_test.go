//go:build !windows

package mihomo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

// selfSignedCert builds a throwaway TLS pair for the TLS-only inbounds.
func selfSignedCert(t *testing.T) kernel.TLSCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return kernel.TLSCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

// TestGeneratedConfigsAreAcceptedByRealMihomo renders a config per listener
// family and runs the real kernel's `-t` parser over it. It is the check that
// keeps the generator honest about the kernel's schema: an unknown key or a
// missing required field fails here rather than at node start.
//
// Enable with: MIHOMO_BIN=/path/to/mihomo go test ./internal/kernel/mihomo/
func TestGeneratedConfigsAreAcceptedByRealMihomo(t *testing.T) {
	binary := os.Getenv("MIHOMO_BIN")
	if binary == "" {
		t.Skip("set MIHOMO_BIN to validate generated configs against the real kernel")
	}
	tls := selfSignedCert(t)
	ssPassword := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	user := model.UserSpec{ID: 7, UUID: "11111111-1111-1111-1111-111111111111"}

	baseListener := func(kind string) map[string]any {
		return map[string]any{"name": "test-" + kind, "type": kind, "listen": "127.0.0.1", "port": 28443}
	}

	cases := []struct {
		name  string
		shape string
		build func() map[string]any
	}{
		{
			name:  "vless",
			shape: model.MihomoUsersArrayUUID,
			build: func() map[string]any {
				listener := baseListener("vless")
				listener["tls"] = false
				return listener
			},
		},
		{
			name:  "vmess",
			shape: model.MihomoUsersArrayUUID,
			build: func() map[string]any { return baseListener("vmess") },
		},
		{
			name:  "trojan",
			shape: model.MihomoUsersArrayPassword,
			build: func() map[string]any { return baseListener("trojan") },
		},
		{
			name:  "http",
			shape: model.MihomoUsersArrayUserPassword,
			build: func() map[string]any { return baseListener("http") },
		},
		{
			name:  "socks",
			shape: model.MihomoUsersArrayUserPassword,
			build: func() map[string]any { return baseListener("socks") },
		},
		{
			name:  "mixed",
			shape: model.MihomoUsersArrayUserPassword,
			build: func() map[string]any { return baseListener("mixed") },
		},
		{
			name:  "hysteria2",
			shape: model.MihomoUsersMap,
			build: func() map[string]any { return baseListener("hysteria2") },
		},
		{
			name:  "tuic",
			shape: model.MihomoUsersMap,
			build: func() map[string]any { return baseListener("tuic") },
		},
		{
			name:  "anytls",
			shape: model.MihomoUsersMap,
			build: func() map[string]any { return baseListener("anytls") },
		},
		{
			name:  "shadowsocks",
			shape: "",
			build: func() map[string]any {
				listener := baseListener("shadowsocks")
				listener["cipher"] = "2022-blake3-aes-256-gcm"
				listener["password"] = ssPassword
				return listener
			},
		},
		{
			name:  "snell",
			shape: "",
			build: func() map[string]any {
				listener := baseListener("snell")
				listener["psk"] = "test-psk"
				return listener
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &model.NodeSpec{
				Protocol:   tc.name,
				KernelType: "mihomo",
				UsersShape: tc.shape,
				Mihomo: &model.MihomoConfig{
					Listeners: []map[string]any{tc.build()},
					RuleProviders: map[string]any{
						"ai": map[string]any{
							"type": "inline", "behavior": "domain", "format": "yaml",
							"payload": []string{"+.openai.com"},
						},
					},
					Rules:    []string{"RULE-SET,ai,DIRECT", "MATCH,DIRECT"},
					SubRules: map[string][]string{"test": {"DOMAIN-SUFFIX,example.com,DIRECT"}},
					Sniffer:  map[string]any{"enable": true},
				},
			}

			dir := t.TempDir()
			home := filepath.Join(dir, "node-7")
			process := NewProcess(binary, home, filepath.Join(home, "config.yaml"), filepath.Join(home, "mihomo.log"))

			doc, err := BuildConfig(spec, []model.UserSpec{user}, tls, Options{
				Kernel:             config.KernelConfig{ConfigDir: home},
				ExternalController: "127.0.0.1:29090",
				Secret:             "test-secret",
				LogLevel:           "warning",
			})
			if err != nil {
				t.Fatalf("BuildConfig: %v", err)
			}
			if err := process.WriteConfig(doc); err != nil {
				t.Fatalf("WriteConfig: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if err := process.Validate(ctx); err != nil {
				raw, _ := os.ReadFile(process.ConfigPath())
				t.Fatalf("the real kernel rejected the generated config: %v\n---\n%s", err, raw)
			}
		})
	}
}

// TestRuntimeEndToEnd starts a real mihomo process through the backend, sends
// traffic through its listener, and checks that the accounting attributes the
// bytes to the authenticated user.
//
// Enable with: MIHOMO_BIN=/path/to/mihomo go test ./internal/kernel/mihomo/
func TestRuntimeEndToEnd(t *testing.T) {
	binary := os.Getenv("MIHOMO_BIN")
	if binary == "" {
		t.Skip("set MIHOMO_BIN to exercise the kernel runtime")
	}

	// A local origin, so the test does not depend on the internet.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 4096))
	}))
	defer origin.Close()

	listenAddr, err := freeControllerAddress()
	if err != nil {
		t.Fatalf("reserve listener port: %v", err)
	}
	_, listenPort, _ := net.SplitHostPort(listenAddr)

	const username = "11111111-1111-1111-1111-111111111111"
	const password = "11111111-1111-1111-1111-111111111111"

	spec := &model.NodeSpec{
		Protocol:   "mixed",
		KernelType: "mihomo",
		UsersShape: model.MihomoUsersArrayUserPassword,
		Mihomo: &model.MihomoConfig{
			Listeners: []map[string]any{{
				"name": "test-mixed", "type": "mixed",
				"listen": "127.0.0.1", "port": listenPort,
			}},
			Rules: []string{"MATCH,DIRECT"},
		},
	}
	users := []model.UserSpec{{ID: 7, UUID: password}}

	k := New(config.KernelConfig{
		BinaryPath: binary,
		ConfigDir:  t.TempDir(),
		LogLevel:   "warning",
	})
	if err := k.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer k.Stop()

	if !k.IsRunning() {
		t.Fatal("kernel must report running after Start")
	}
	caps := k.Capabilities()
	if !caps.ForceCloseConnection || !caps.AliveIPTracking || caps.PerUserSpeedLimit {
		t.Errorf("unexpected capabilities: %#v", caps)
	}

	// Send a request through the HTTP proxy interface of the mixed listener.
	// The username contains colons, so the credentials are set explicitly via
	// Proxy-Authorization rather than a userinfo URL.
	proxyFunc := func(*http.Request) (*url.URL, error) {
		return url.Parse("http://127.0.0.1:" + listenPort)
	}
	transport := &http.Transport{Proxy: proxyFunc}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}

	request, err := http.NewRequest(http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request through the kernel listener failed: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", response.StatusCode)
	}

	// Let the connection table settle, then check attribution.
	var traffic map[int][2]int64
	var alive map[int]map[string]bool
	var connCount int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		traffic, _, alive, connCount, err = k.GetUserTraffic(context.Background())
		if err != nil {
			t.Fatalf("GetUserTraffic: %v", err)
		}
		if connCount > 0 && len(alive[7]) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if connCount == 0 {
		t.Fatalf("the kernel reported no live connections; accounting cannot work")
	}
	if !alive[7]["127.0.0.1"] {
		t.Errorf("alive IP tracking did not see the client: %#v", alive)
	}
	counters, ok := traffic[7]
	if !ok {
		t.Fatalf("traffic was not attributed to user 7: %#v", traffic)
	}
	if counters[0]+counters[1] == 0 {
		t.Errorf("attributed zero bytes: %#v", counters)
	}

	// Force-disconnect the user and confirm the connection is gone.
	if err := k.CloseUserConnections(context.Background(), password); err != nil {
		t.Fatalf("CloseUserConnections: %v", err)
	}
}
