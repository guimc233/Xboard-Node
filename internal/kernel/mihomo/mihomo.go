package mihomo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// pollInterval is how often the live connection table is sampled. mihomo has no
// event hook, so accounting is delta-polling: a shorter interval captures more
// of the short-lived connections.
const pollInterval = time.Second

// controllerStartTimeout bounds how long Start waits for the API to answer.
const controllerStartTimeout = 15 * time.Second

// Mihomo implements kernel.Kernel for a single node backed by one mihomo
// process.
//
// sing-box and Xray are embedded as libraries because they expose per-instance
// handles. mihomo does not — its listeners, tunnel and statistics live in
// process globals — so a node is one process, and everything the agent observes
// comes from the external-controller REST API.
type Mihomo struct {
	cfg config.KernelConfig

	mu         sync.RWMutex
	process    *Process
	client     *Client
	secret     string
	controller string
	running    bool
	spec       *model.NodeSpec
	users      []model.UserSpec
	tls        kernel.TLSCert

	// Local overrides from kernel.custom_config / kernel.custom_outbound.
	customConfig map[string]any
	extraProxies []map[string]any

	speedLimitFunc  func(string) *rate.Limiter
	deviceLimitFunc func(string) (int, bool)

	// accounting is filled by the poller and read by GetUserTraffic.
	accMu          sync.Mutex
	userTraffic    map[int][2]int64
	profileTraffic map[string][2]int64
	aliveIPs       map[int]map[string]bool
	connCount      int
	samples        map[string]connSample
	usernameUser   map[string]int
	usernameToProf map[string]string
	uuidUsernames  map[string][]string

	pollCancel context.CancelFunc
	pollDone   chan struct{}
}

type connSample struct {
	upload   int64
	download int64
}

func New(cfg config.KernelConfig) *Mihomo {
	return &Mihomo{cfg: cfg}
}

var _ kernel.Kernel = (*Mihomo)(nil)

func (m *Mihomo) Name() string { return "mihomo" }

// Protocols lists the inbounds this backend can serve. Every entry is a
// subscription-capable mihomo listener.
func (m *Mihomo) Protocols() []string {
	return []string{
		"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic",
		"anytls", "snell", "mieru", "sudoku", "shadowquic", "trusttunnel",
		"socks", "mixed", "http",
	}
}

// Capabilities reflects what a subprocess + REST API can actually do:
// accounting is polled, and neither a per-user speed limit nor a device gate
// exists inside mihomo.
func (m *Mihomo) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    false,
		DeviceLimit:          false,
		BuiltInTrafficStats:  false,
		AliveIPTracking:      true,
		ForceCloseConnection: true,
		ForceCloseUser:       true,
	}
}

// ─── Lifecycle ──────────────────────────────────────────────────────────────

func (m *Mihomo) Start(nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	// A start on a running kernel replaces the old process.
	m.Stop()

	if nc == nil {
		return errors.New("mihomo: node config is required")
	}

	binary, err := ResolveBinary(m.cfg.BinaryPath)
	if err != nil {
		return err
	}
	homeDir := strings.TrimSpace(m.cfg.ConfigDir)
	if homeDir == "" {
		return errors.New("mihomo: kernel.config_dir is required")
	}

	secret, err := randomSecret()
	if err != nil {
		return err
	}
	controller, err := freeControllerAddress()
	if err != nil {
		return err
	}

	customConfig, err := kernel.LoadCustomConfig(m.cfg.CustomConfig)
	if err != nil {
		return err
	}
	if len(m.cfg.CustomRoute) > 0 {
		nlog.Core().Warn("kernel.custom_route is ignored by the mihomo backend; put rules in kernel.custom_config instead")
	}

	process := NewProcess(binary, homeDir, filepath.Join(homeDir, "config.yaml"), filepath.Join(homeDir, "mihomo.log"))
	client := NewClient(controller, secret)

	doc, err := BuildConfig(nc, users, tls, Options{
		Kernel:             m.cfg,
		ExternalController: controller,
		Secret:             secret,
		LogLevel:           m.cfg.LogLevel,
		CustomConfig:       customConfig,
		ExtraProxies:       m.cfg.CustomOutbound,
	})
	if err != nil {
		return err
	}

	if err := process.WriteConfig(doc); err != nil {
		return err
	}
	// `-t` parses the config and exits, catching anything the kernel would
	// reject before a process is left half-started.
	validateCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	err = process.Validate(validateCtx)
	cancel()
	if err != nil {
		return err
	}

	if err := process.Start(); err != nil {
		return err
	}

	waitCtx, cancelWait := context.WithTimeout(context.Background(), controllerStartTimeout)
	err = waitForController(waitCtx, client)
	cancelWait()
	if err != nil {
		process.Stop()
		return err
	}

	m.mu.Lock()
	m.process = process
	m.client = client
	m.secret = secret
	m.controller = controller
	m.running = true
	m.spec = nc
	m.tls = tls
	m.users = cloneUsers(users)
	m.customConfig = customConfig
	m.extraProxies = m.cfg.CustomOutbound
	m.mu.Unlock()

	m.resetAccounting(users)
	m.startPoller()

	return nil
}

func (m *Mihomo) Stop() {
	m.stopPoller()

	m.mu.Lock()
	process := m.process
	m.process = nil
	m.client = nil
	m.running = false
	m.mu.Unlock()

	if process != nil {
		process.Stop()
	}
}

func (m *Mihomo) IsRunning() bool {
	m.mu.RLock()
	running := m.running
	m.mu.RUnlock()
	return running
}

// Reload regenerates the full config and makes mihomo re-read it via SIGHUP.
// SIGHUP is used instead of PUT /configs because only the former reapplies
// controller settings; either way a listener whose users changed is closed and
// re-listened by the kernel.
func (m *Mihomo) Reload(nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	if nc == nil {
		return errors.New("mihomo: node config is required")
	}

	m.mu.RLock()
	process := m.process
	controller := m.controller
	secret := m.secret
	m.mu.RUnlock()

	if process == nil {
		return errors.New("mihomo: reload requested but the process is not running")
	}

	m.mu.RLock()
	customConfig := m.customConfig
	extraProxies := m.extraProxies
	m.mu.RUnlock()

	doc, err := BuildConfig(nc, users, tls, Options{
		Kernel:             m.cfg,
		ExternalController: controller,
		Secret:             secret,
		LogLevel:           m.cfg.LogLevel,
		CustomConfig:       customConfig,
		ExtraProxies:       extraProxies,
	})
	if err != nil {
		return err
	}
	if err := process.WriteConfig(doc); err != nil {
		return err
	}

	m.mu.Lock()
	m.spec = nc
	m.tls = tls
	m.users = cloneUsers(users)
	m.mu.Unlock()

	m.resetAccounting(users)

	if err := process.Reload(); err != nil {
		return err
	}
	// The poller survived the reload; restart it only if it is not running.
	m.startPoller()
	return nil
}

// ─── User management ────────────────────────────────────────────────────────

// AddUsers applies users on top of the current set. mihomo has no hot user
// API: a listener whose `users` changed is closed and re-listened, which drops
// the connections on that listener only.
func (m *Mihomo) AddUsers(users []model.UserSpec) (int, error) {
	m.mu.RLock()
	current := cloneUsers(m.users)
	m.mu.RUnlock()

	merged := mergeUsers(current, users)
	added, _ := kernel.UserDiff(current, merged)
	if len(added) == 0 {
		return 0, nil
	}
	if err := m.applyUsers(merged); err != nil {
		return 0, err
	}
	return len(added), nil
}

// RemoveUsers drops the given users from the running set.
func (m *Mihomo) RemoveUsers(users []model.UserSpec) (int, error) {
	m.mu.RLock()
	current := cloneUsers(m.users)
	m.mu.RUnlock()

	removeIDs := make(map[int]struct{}, len(users))
	for _, user := range users {
		removeIDs[user.ID] = struct{}{}
	}
	remaining := make([]model.UserSpec, 0, len(current))
	for _, user := range current {
		if _, drop := removeIDs[user.ID]; !drop {
			remaining = append(remaining, user)
		}
	}

	_, removed := kernel.UserDiff(current, remaining)
	if len(removed) == 0 {
		return 0, nil
	}
	if err := m.applyUsers(remaining); err != nil {
		return 0, err
	}
	return len(removed), nil
}

// UpdateUsers replaces the whole user set atomically.
func (m *Mihomo) UpdateUsers(users []model.UserSpec) (int, int, error) {
	m.mu.RLock()
	current := cloneUsers(m.users)
	m.mu.RUnlock()

	added, removed := kernel.UserDiff(current, users)
	if len(added) == 0 && len(removed) == 0 {
		return 0, 0, nil
	}
	if err := m.applyUsers(users); err != nil {
		return 0, 0, err
	}
	return len(added), len(removed), nil
}

// applyUsers rewrites the config with the new user set and reloads it.
func (m *Mihomo) applyUsers(users []model.UserSpec) error {
	m.mu.RLock()
	spec := m.spec
	tls := m.tls
	process := m.process
	controller := m.controller
	secret := m.secret
	m.mu.RUnlock()

	if spec == nil || process == nil {
		return errors.New("mihomo: cannot update users before the kernel is started")
	}

	m.mu.RLock()
	customConfig := m.customConfig
	extraProxies := m.extraProxies
	m.mu.RUnlock()

	doc, err := BuildConfig(spec, users, tls, Options{
		Kernel:             m.cfg,
		ExternalController: controller,
		Secret:             secret,
		LogLevel:           m.cfg.LogLevel,
		CustomConfig:       customConfig,
		ExtraProxies:       extraProxies,
	})
	if err != nil {
		return err
	}
	if err := process.WriteConfig(doc); err != nil {
		return err
	}

	m.mu.Lock()
	m.users = cloneUsers(users)
	m.mu.Unlock()

	m.resetAccounting(users)
	return process.Reload()
}

// ─── Observability ──────────────────────────────────────────────────────────

func (m *Mihomo) GetUserTraffic(ctx context.Context) (map[int][2]int64, map[string][2]int64, map[int]map[string]bool, int, error) {
	if !m.IsRunning() {
		return nil, nil, nil, 0, nil
	}

	// Sample once synchronously so a caller that polls faster than the
	// background loop still sees fresh numbers.
	m.sample(ctx)

	m.accMu.Lock()
	defer m.accMu.Unlock()

	traffic := make(map[int][2]int64, len(m.userTraffic))
	for id, counters := range m.userTraffic {
		traffic[id] = counters
	}
	profileTraffic := make(map[string][2]int64, len(m.profileTraffic))
	for key, counters := range m.profileTraffic {
		profileTraffic[key] = counters
	}
	alive := make(map[int]map[string]bool, len(m.aliveIPs))
	for id, ips := range m.aliveIPs {
		copied := make(map[string]bool, len(ips))
		for ip := range ips {
			copied[ip] = true
		}
		alive[id] = copied
	}
	return traffic, profileTraffic, alive, m.connCount, nil
}

func (m *Mihomo) CloseConnection(ctx context.Context, connID string) error {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	if client == nil {
		return errors.New("mihomo: kernel is not running")
	}
	return client.CloseConnection(ctx, connID)
}

// CloseUserConnections closes every connection authenticated as any credential
// belonging to the user. The interface passes a UUID, so the identity table is
// used to resolve the usernames mihomo reports.
func (m *Mihomo) CloseUserConnections(ctx context.Context, uuid string) error {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	if client == nil {
		return errors.New("mihomo: kernel is not running")
	}

	m.accMu.Lock()
	usernames := append([]string(nil), m.uuidUsernames[uuid]...)
	m.accMu.Unlock()
	if len(usernames) == 0 {
		// Fall back to scanning by the UUID itself: for several protocols the
		// credential is the username.
		usernames = []string{uuid}
	}

	var firstErr error
	for _, username := range usernames {
		if _, err := client.CloseConnectionsForUser(ctx, username); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// SetSpeedLimitFunc is accepted for interface compatibility but has no effect:
// mihomo exposes no per-user bandwidth control. The service degrades to its own
// limiter based on Capabilities().
func (m *Mihomo) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	m.mu.Lock()
	m.speedLimitFunc = fn
	m.mu.Unlock()
}

// SetDeviceLimitFunc is accepted for interface compatibility but has no effect:
// mihomo cannot gate devices. Device state is enforced by the agent from the
// alive-IP set.
func (m *Mihomo) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	m.mu.Lock()
	m.deviceLimitFunc = fn
	m.mu.Unlock()
}

// UpdateGlobalDevices is a no-op: mihomo has no device state to seed.
func (m *Mihomo) UpdateGlobalDevices(users map[int][]string) {}

// ClearGlobalDevices is a no-op, see UpdateGlobalDevices.
func (m *Mihomo) ClearGlobalDevices() {}

// ─── Accounting ─────────────────────────────────────────────────────────────

func (m *Mihomo) resetAccounting(users []model.UserSpec) {
	m.accMu.Lock()
	defer m.accMu.Unlock()

	m.userTraffic = make(map[int][2]int64)
	m.profileTraffic = make(map[string][2]int64)
	m.aliveIPs = make(map[int]map[string]bool)
	m.connCount = 0
	m.samples = make(map[string]connSample)
	m.usernameUser = make(map[string]int, len(users)*2)
	m.usernameToProf = make(map[string]string)
	m.uuidUsernames = make(map[string][]string, len(users))

	for _, user := range users {
		base := baseUsername(user.ID)
		m.usernameUser[base] = user.ID
		// The interface closes connections by the user's own UUID, so every
		// credential of that user (base + route-profile identities) is filed
		// under it.
		if user.UUID != "" {
			m.uuidUsernames[user.UUID] = append(m.uuidUsernames[user.UUID], base)
		}
		for _, identity := range user.Identities {
			username := strings.TrimSpace(identity.AuthUser)
			if username == "" {
				continue
			}
			m.usernameUser[username] = user.ID
			if identity.ProfileID != "" {
				m.usernameToProf[username] = identity.ProfileID
			}
			if user.UUID != "" {
				m.uuidUsernames[user.UUID] = append(m.uuidUsernames[user.UUID], username)
			}
		}
	}
}

func (m *Mihomo) startPoller() {
	m.mu.Lock()
	if m.pollCancel != nil {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.pollCancel = cancel
	m.pollDone = done
	m.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !m.processAlive() {
					m.mu.Lock()
					m.running = false
					m.mu.Unlock()
					return
				}
				m.sample(ctx)
			}
		}
	}()
}

// processAlive reports whether the child is still running. The poller uses it
// to notice a crashed kernel instead of reporting stale accounting forever.
func (m *Mihomo) processAlive() bool {
	m.mu.RLock()
	process := m.process
	m.mu.RUnlock()
	return process == nil || process.Running()
}

func (m *Mihomo) stopPoller() {
	m.mu.Lock()
	cancel := m.pollCancel
	done := m.pollDone
	m.pollCancel = nil
	m.pollDone = nil
	m.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

// sample reads the live connection table and folds the per-connection deltas
// into per-user totals. `upload`/`download` are cumulative per connection, so
// each poll only adds what grew since the previous poll.
func (m *Mihomo) sample(ctx context.Context) {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	if client == nil {
		return
	}

	snapshot, err := client.Connections(ctx)
	if err != nil {
		return
	}

	m.accMu.Lock()
	defer m.accMu.Unlock()
	if m.samples == nil {
		return
	}

	alive := make(map[int]map[string]bool)
	next := make(map[string]connSample, len(snapshot.Connections))

	for _, connection := range snapshot.Connections {
		previous, seen := m.samples[connection.ID]
		deltaUp := connection.Upload - previous.upload
		deltaDown := connection.Download - previous.download
		if !seen {
			deltaUp = connection.Upload
			deltaDown = connection.Download
		}
		if deltaUp < 0 {
			deltaUp = 0
		}
		if deltaDown < 0 {
			deltaDown = 0
		}
		next[connection.ID] = connSample{upload: connection.Upload, download: connection.Download}

		username := strings.TrimSpace(connection.Metadata.InboundUser)
		if username == "" {
			// Unauthenticated (or shadowsocks, which has no users list): the
			// bytes cannot be attributed to a user.
			continue
		}
		userID, ok := m.usernameUser[username]
		if !ok {
			// Unknown credential: the user set changed under us. Skip rather
			// than invent an id.
			continue
		}

		counters := m.userTraffic[userID]
		counters[0] += deltaUp
		counters[1] += deltaDown
		m.userTraffic[userID] = counters

		if profileID, isProfile := m.usernameToProf[username]; isProfile {
			profileCounters := m.profileTraffic[profileID]
			profileCounters[0] += deltaUp
			profileCounters[1] += deltaDown
			m.profileTraffic[profileID] = profileCounters
		}

		if ip := strings.TrimSpace(connection.Metadata.SourceIP); ip != "" {
			if alive[userID] == nil {
				alive[userID] = make(map[string]bool)
			}
			alive[userID][ip] = true
		}
	}

	m.samples = next
	m.aliveIPs = alive
	m.connCount = len(snapshot.Connections)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func baseUsername(userID int) string {
	return fmt.Sprintf("xb:u:%d", userID)
}

func randomSecret() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mihomo: generate controller secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// freeControllerAddress asks the OS for an unused loopback port. The port is
// released immediately; mihomo binds it moments later.
func freeControllerAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("mihomo: reserve controller port: %w", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address, nil
}

func waitForController(ctx context.Context, client *Client) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		if _, err := client.Version(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("mihomo: external controller did not come up: %w", lastErr)
		case <-ticker.C:
		}
	}
}

func cloneUsers(users []model.UserSpec) []model.UserSpec {
	if users == nil {
		return nil
	}
	out := make([]model.UserSpec, len(users))
	copy(out, users)
	for i := range out {
		if users[i].Identities != nil {
			identities := make([]model.UserIdentity, len(users[i].Identities))
			copy(identities, users[i].Identities)
			out[i].Identities = identities
		}
	}
	return out
}

func mergeUsers(existing, incoming []model.UserSpec) []model.UserSpec {
	merged := cloneUsers(existing)
	index := make(map[int]int, len(merged))
	for i, user := range merged {
		index[user.ID] = i
	}
	for _, user := range incoming {
		if position, ok := index[user.ID]; ok {
			merged[position] = user
			continue
		}
		index[user.ID] = len(merged)
		merged = append(merged, user)
	}
	return merged
}
