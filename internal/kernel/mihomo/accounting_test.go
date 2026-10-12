package mihomo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

// scriptedController serves a sequence of /connections payloads and records
// DELETE calls.
type scriptedController struct {
	mu       sync.Mutex
	payloads []string
	calls    int
	closed   []string
}

func (s *scriptedController) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		if r.Method == http.MethodDelete {
			s.closed = append(s.closed, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		index := s.calls
		if index >= len(s.payloads) {
			index = len(s.payloads) - 1
		}
		s.calls++
		_, _ = w.Write([]byte(s.payloads[index]))
	}
}

func (s *scriptedController) callsMade() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *scriptedController) closedPaths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.closed...)
}

func accountingKernel(t *testing.T, payloads []string, users []model.UserSpec) (*Mihomo, *scriptedController) {
	t.Helper()
	script := &scriptedController{payloads: payloads}
	server := httptest.NewServer(script.handler())
	t.Cleanup(server.Close)

	k := New(config.KernelConfig{})
	k.client = NewClient(server.URL, "")
	k.running = true
	k.resetAccounting(users)
	return k, script
}

func accountingUsers() []model.UserSpec {
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

const firstPoll = `{
  "connections": [
    {"id":"a","upload":100,"download":1000,"metadata":{"inboundUser":"xb:u:7","sourceIP":"203.0.113.1"}},
    {"id":"b","upload":50,"download":500,"metadata":{"inboundUser":"xb:u:7:rp:profile-1","sourceIP":"203.0.113.2"}},
    {"id":"c","upload":10,"download":20,"metadata":{"inboundUser":"","sourceIP":"203.0.113.3"}},
    {"id":"d","upload":5,"download":5,"metadata":{"inboundUser":"xb:u:999","sourceIP":"203.0.113.4"}}
  ]
}`

// Second poll: connection "a" grew, "b" is gone, "e" is new.
const secondPoll = `{
  "connections": [
    {"id":"a","upload":150,"download":1600,"metadata":{"inboundUser":"xb:u:7","sourceIP":"203.0.113.1"}},
    {"id":"e","upload":7,"download":7,"metadata":{"inboundUser":"xb:u:8","sourceIP":"203.0.113.5"}}
  ]
}`

func TestAccountingAccumulatesDeltas(t *testing.T) {
	k, _ := accountingKernel(t, []string{firstPoll, secondPoll, secondPoll}, accountingUsers())
	ctx := context.Background()

	k.sample(ctx)
	traffic, profiles, alive, connCount, err := k.GetUserTraffic(ctx)
	if err != nil {
		t.Fatalf("GetUserTraffic: %v", err)
	}

	// Two polls have been folded in: the first saw (100,1000) on connection
	// "a" plus (50,500) on the profile, the second added the growth to
	// (150,1600) while connection "b" disappeared.
	if traffic[7] != [2]int64{200, 2100} {
		t.Errorf("user 7 totals wrong: %#v", traffic[7])
	}
	if profiles["profile-1"] != [2]int64{50, 500} {
		t.Errorf("profile traffic must not be double counted: %#v", profiles)
	}
	if _, ok := traffic[999]; ok {
		t.Errorf("unknown credentials must be skipped")
	}
	if traffic[8] != [2]int64{7, 7} {
		t.Errorf("new user totals wrong: %#v", traffic[8])
	}
	// Unauthenticated and unknown credentials are never invented.
	if _, ok := traffic[999]; ok {
		t.Errorf("unknown user must be skipped: %#v", traffic)
	}
	if connCount != 2 {
		t.Errorf("expected 2 live connections, got %d", connCount)
	}
	// Alive IPs reflect the latest poll only.
	if !alive[7]["203.0.113.1"] || alive[7]["203.0.113.2"] {
		t.Errorf("alive IPs must reflect the current poll: %#v", alive)
	}
}

func TestAccountingIsNotDoubleCountedAcrossPolls(t *testing.T) {
	k, _ := accountingKernel(t, []string{firstPoll, firstPoll, firstPoll}, accountingUsers())
	ctx := context.Background()

	k.sample(ctx)
	first, _, _, _, _ := k.GetUserTraffic(ctx)
	k.sample(ctx)
	second, _, _, _, _ := k.GetUserTraffic(ctx)

	if first[7] != second[7] {
		t.Errorf("unchanged counters must not accumulate twice: %#v vs %#v", first[7], second[7])
	}
}

func TestAccountingHandlesClosedConnections(t *testing.T) {
	k, _ := accountingKernel(t, []string{firstPoll, secondPoll}, accountingUsers())
	ctx := context.Background()

	k.sample(ctx) // connection "b" contributes (50, 500) to the profile
	_, profiles, _, _, _ := k.GetUserTraffic(ctx)
	if profiles["profile-1"] != [2]int64{50, 500} {
		t.Errorf("profile bytes from a closed connection must be kept: %#v", profiles)
	}
}

func TestCloseUserConnectionsResolvesCredentials(t *testing.T) {
	k, script := accountingKernel(t, []string{
		`{"connections":[
		   {"id":"a","metadata":{"inboundUser":"xb:u:7"}},
		   {"id":"b","metadata":{"inboundUser":"xb:u:7:rp:profile-1"}},
		   {"id":"c","metadata":{"inboundUser":"xb:u:8"}}
		 ]}`,
		`{"connections":[
		   {"id":"a","metadata":{"inboundUser":"xb:u:7"}},
		   {"id":"b","metadata":{"inboundUser":"xb:u:7:rp:profile-1"}},
		   {"id":"c","metadata":{"inboundUser":"xb:u:8"}}
		 ]}`,
	}, accountingUsers())

	if err := k.CloseUserConnections(context.Background(), "11111111-1111-1111-1111-111111111111"); err != nil {
		t.Fatalf("CloseUserConnections: %v", err)
	}
	closed := script.closedPaths()
	if len(closed) != 2 {
		t.Fatalf("expected the two credentials of user 7 to be closed, got %#v", closed)
	}
}

func TestUpdateUsersNoOpWhenUnchanged(t *testing.T) {
	k := New(config.KernelConfig{})
	users := accountingUsers()
	k.users = cloneUsers(users)

	added, removed, err := k.UpdateUsers(users)
	if err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	if added != 0 || removed != 0 {
		t.Errorf("an unchanged user set must not trigger a reload: +%d -%d", added, removed)
	}
}

func TestGetUserTrafficStopsWhenNotRunning(t *testing.T) {
	k := New(config.KernelConfig{})
	traffic, profiles, alive, count, err := k.GetUserTraffic(context.Background())
	if err != nil || traffic != nil || profiles != nil || alive != nil || count != 0 {
		t.Fatalf("a stopped kernel must report nothing: %v %v %v %v %v", err, traffic, profiles, alive, count)
	}
}
