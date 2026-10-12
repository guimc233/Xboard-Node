package mihomo

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMain lets the test binary impersonate the mihomo CLI. Re-executing the
// test binary is the portable way to get a child process that handles Unix
// signals natively — a shell script's HUP trap is unreliable under dash.
func TestMain(m *testing.M) {
	if os.Getenv("MIHOMO_FAKE_BINARY") == "1" {
		fakeMihomoMain()
		return
	}
	os.Exit(m.Run())
}

func fakeMihomoMain() {
	for _, arg := range os.Args[1:] {
		if arg == "-t" {
			if os.Getenv("MIHOMO_FAKE_VALIDATE_FAIL") == "1" {
				fmt.Fprintln(os.Stderr, "configuration file test failed: yaml: unmarshal errors")
				os.Exit(1)
			}
			fmt.Println("configuration file test is successful")
			os.Exit(0)
		}
	}

	marker := os.Getenv("MIHOMO_FAKE_MARKER")
	// Announce readiness so the parent never races the signal handler
	// registration: SIGHUP's default action is to terminate the process.
	if ready := os.Getenv("MIHOMO_FAKE_READY"); ready != "" {
		_ = os.WriteFile(ready, []byte("ready"), 0o600)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	for sig := range signals {
		if sig == syscall.SIGHUP {
			if marker != "" {
				_ = os.WriteFile(marker, []byte("reloaded"), 0o600)
			}
			continue
		}
		os.Exit(0)
	}
}

func fakeBinary(t *testing.T) (binary, marker, ready string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "reloaded")
	ready = filepath.Join(dir, "ready")
	t.Setenv("MIHOMO_FAKE_BINARY", "1")
	t.Setenv("MIHOMO_FAKE_MARKER", marker)
	t.Setenv("MIHOMO_FAKE_READY", ready)
	return os.Args[0], marker, ready
}

func waitForFile(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestWriteConfigRendersYAML(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "node-1")
	configPath := filepath.Join(home, "config.yaml")

	process := NewProcess("mihomo", home, configPath, filepath.Join(home, "mihomo.log"))
	doc := map[string]any{
		"mode":                "rule",
		"log-level":           "warning",
		"external-controller": "127.0.0.1:19090",
		"secret":              "s3cret",
		"listeners": []map[string]any{{
			"name": "hk-1",
			"type": "vless",
			"port": "8443",
			"users": []map[string]any{
				{"username": "xb:u:7", "uuid": "11111111-1111-1111-1111-111111111111"},
			},
		}},
	}
	if err := process.WriteConfig(doc); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(raw)
	for _, want := range []string{"mode: rule", "external-controller: 127.0.0.1:19090", "xb:u:7", "vless"} {
		if !strings.Contains(text, want) {
			t.Errorf("config.yaml missing %q:\n%s", want, text)
		}
	}
}

func TestValidateSucceedsAndFails(t *testing.T) {
	binary, _, _ := fakeBinary(t)
	dir := t.TempDir()
	process := NewProcess(binary, dir, filepath.Join(dir, "config.yaml"), "")

	if err := process.Validate(context.Background()); err != nil {
		t.Fatalf("Validate should succeed: %v", err)
	}

	t.Setenv("MIHOMO_FAKE_VALIDATE_FAIL", "1")
	err := process.Validate(context.Background())
	if err == nil {
		t.Fatal("Validate should fail when the kernel rejects the config")
	}
	if !strings.Contains(err.Error(), "test failed") {
		t.Errorf("error must surface the kernel output, got %v", err)
	}
}

func TestProcessLifecycle(t *testing.T) {
	binary, marker, ready := fakeBinary(t)
	dir := t.TempDir()
	home := filepath.Join(dir, "node-1")
	process := NewProcess(binary, home, filepath.Join(home, "config.yaml"), filepath.Join(home, "mihomo.log"))
	if err := process.WriteConfig(map[string]any{"mode": "rule"}); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	if process.Running() {
		t.Fatal("process must not report running before Start")
	}
	if err := process.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer process.Stop()

	if !process.Running() {
		t.Fatal("process must report running after Start")
	}
	if !waitForFile(t, ready, 3*time.Second) {
		t.Fatal("the fake kernel never became ready")
	}

	// SIGHUP is the full-reload path and must reach the child.
	if err := process.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !waitForFile(t, marker, 3*time.Second) {
		t.Fatal("SIGHUP was not delivered")
	}
	if !process.Running() {
		t.Fatal("a reload must not stop the process")
	}

	process.Stop()
	if process.Running() {
		t.Fatal("process must not report running after Stop")
	}
}

func TestStartTwiceFails(t *testing.T) {
	binary, _, _ := fakeBinary(t)
	dir := t.TempDir()
	process := NewProcess(binary, dir, filepath.Join(dir, "config.yaml"), "")
	if err := process.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer process.Stop()

	if err := process.Start(); err == nil {
		t.Fatal("a second Start must fail while the process runs")
	}
}

func TestReloadWithoutProcessFails(t *testing.T) {
	process := NewProcess("mihomo", t.TempDir(), "config.yaml", "")
	if err := process.Reload(); err == nil {
		t.Fatal("Reload must fail when nothing is running")
	}
}

func TestResolveBinary(t *testing.T) {
	if _, err := ResolveBinary("/nonexistent/mihomo"); err == nil {
		t.Fatal("a missing explicit binary must fail")
	}
	path, err := ResolveBinary("")
	if err != nil {
		t.Fatalf("expected to find a binary on PATH: %v", err)
	}
	if path == "" {
		t.Fatal("expected a resolved path")
	}
}
