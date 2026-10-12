package mihomo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultBinaryName is looked up on PATH when no explicit binary is set.
const DefaultBinaryName = "mihomo"

// stopGrace is how long Stop waits after SIGTERM before killing the process.
const stopGrace = 5 * time.Second

// Process owns the mihomo OS process for one node.
//
// mihomo keeps its listener, tunnel and statistics state in process globals, so
// a process is the unit of isolation: one node, one process, one home
// directory, one external controller.
type Process struct {
	binary     string
	homeDir    string
	configPath string
	logPath    string

	mu      sync.Mutex
	cmd     *exec.Cmd
	logFile *os.File
	done    chan struct{}
}

// NewProcess prepares the paths for a node runtime. The directory is created on
// WriteConfig.
func NewProcess(binary, homeDir, configPath, logPath string) *Process {
	if strings.TrimSpace(binary) == "" {
		binary = DefaultBinaryName
	}
	return &Process{
		binary:     binary,
		homeDir:    homeDir,
		configPath: configPath,
		logPath:    logPath,
	}
}

// ResolveBinary returns the binary path, preferring an explicit path and
// falling back to PATH lookup.
func ResolveBinary(explicit string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("mihomo: binary %q is not usable: %w", explicit, err)
		}
		return explicit, nil
	}
	found, err := exec.LookPath(DefaultBinaryName)
	if err != nil {
		return "", fmt.Errorf("mihomo: %q not found on PATH; set kernel.binary_path or install it", DefaultBinaryName)
	}
	return found, nil
}

// HomeDir returns the -d directory.
func (p *Process) HomeDir() string { return p.homeDir }

// ConfigPath returns the -f path.
func (p *Process) ConfigPath() string { return p.configPath }

// WriteConfig renders the document to the node's config.yaml.
func (p *Process) WriteConfig(doc map[string]any) error {
	encoded, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("mihomo: encode config: %w", err)
	}
	if err := os.MkdirAll(p.homeDir, 0o700); err != nil {
		return fmt.Errorf("mihomo: create home dir: %w", err)
	}
	if dir := filepath.Dir(p.configPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mihomo: create config dir: %w", err)
		}
	}
	if err := os.WriteFile(p.configPath, encoded, 0o600); err != nil {
		return fmt.Errorf("mihomo: write config: %w", err)
	}
	return nil
}

// Validate runs `mihomo -d <home> -f <config> -t`, which parses the config and
// exits. It is the cheapest way to catch a config the kernel would reject.
func (p *Process) Validate(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, p.binary, "-d", p.homeDir, "-f", p.configPath, "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mihomo: config test failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// Start launches the kernel. It is a no-op error when already running.
func (p *Process) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil {
		return errors.New("mihomo: process already running")
	}
	if err := os.MkdirAll(p.homeDir, 0o700); err != nil {
		return fmt.Errorf("mihomo: create home dir: %w", err)
	}

	cmd := exec.Command(p.binary, "-d", p.homeDir, "-f", p.configPath)
	// Put the child in its own process group where the platform supports it, so
	// a signal to the agent is not forwarded to every node at once.
	cmd.SysProcAttr = newSysProcAttr()

	if p.logPath != "" {
		if err := os.MkdirAll(filepath.Dir(p.logPath), 0o700); err != nil {
			return fmt.Errorf("mihomo: create log dir: %w", err)
		}
		logFile, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("mihomo: open log file: %w", err)
		}
		p.logFile = logFile
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	if err := cmd.Start(); err != nil {
		if p.logFile != nil {
			_ = p.logFile.Close()
			p.logFile = nil
		}
		return fmt.Errorf("mihomo: start: %w", err)
	}

	p.cmd = cmd
	p.done = make(chan struct{})
	go func(done chan struct{}) {
		_ = cmd.Wait()
		close(done)
	}(p.done)

	return nil
}

// Stop terminates the process, draining for a grace period before killing it.
func (p *Process) Stop() {
	p.mu.Lock()
	cmd := p.cmd
	done := p.done
	logFile := p.logFile
	p.cmd = nil
	p.done = nil
	p.logFile = nil
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		return
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(stopGrace):
		_ = cmd.Process.Kill()
		<-done
	}
	if logFile != nil {
		_ = logFile.Close()
	}
}

// Reload sends SIGHUP, which makes mihomo re-read the config file and reapply
// everything including the external controller. Unlike PUT /configs it does not
// drop the controller's settings.
func (p *Process) Reload() error {
	p.mu.Lock()
	cmd := p.cmd
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return errors.New("mihomo: process is not running")
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("mihomo: reload: %w", err)
	}
	return nil
}

// Running reports whether the process is currently alive.
func (p *Process) Running() bool {
	p.mu.Lock()
	cmd := p.cmd
	done := p.done
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}
