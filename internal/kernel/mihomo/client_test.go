package mihomo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc, secret string) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewClient(strings.TrimPrefix(server.URL, "http://"), secret)
}

func TestConnectionsParsesWireFormat(t *testing.T) {
	const payload = `{
	  "downloadTotal": 1007934,
	  "uploadTotal": 164,
	  "memory": 51503104,
	  "connections": [
	    {
	      "id": "62ebc574-1fd5-469e-985b-6d4edd5784a9",
	      "metadata": {
	        "network": "tcp",
	        "type": "Vless",
	        "sourceIP": "203.0.113.9",
	        "sourcePort": "51816",
	        "destinationPort": "443",
	        "inboundPort": "8443",
	        "inboundName": "hk-1",
	        "inboundUser": "xb:u:7"
	      },
	      "upload": 82,
	      "download": 502943,
	      "start": "2026-10-12T19:29:12.281928755+08:00",
	      "chains": ["warp"],
	      "providerChains": [""],
	      "rule": "Match",
	      "rulePayload": ""
	    }
	  ]
	}`

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connections" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}, "")

	snapshot, err := client.Connections(context.Background())
	if err != nil {
		t.Fatalf("Connections: %v", err)
	}
	if snapshot.DownloadTotal != 1007934 || snapshot.UploadTotal != 164 {
		t.Errorf("totals not parsed: %#v", snapshot)
	}
	if len(snapshot.Connections) != 1 {
		t.Fatalf("expected one connection, got %#v", snapshot.Connections)
	}
	connection := snapshot.Connections[0]
	if connection.Metadata.InboundUser != "xb:u:7" {
		t.Errorf("inboundUser must be parsed: %#v", connection.Metadata)
	}
	// The port fields are JSON strings and must not be decoded as numbers.
	if connection.Metadata.SourcePort != "51816" || connection.Metadata.InboundPort != "8443" {
		t.Errorf("ports must stay strings: %#v", connection.Metadata)
	}
	if connection.Upload != 82 || connection.Download != 502943 {
		t.Errorf("per-connection counters not parsed: %#v", connection)
	}
}

func TestConnectionsHandlesNullList(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"downloadTotal":0,"uploadTotal":0,"memory":0,"connections":null}`))
	}, "")
	snapshot, err := client.Connections(context.Background())
	if err != nil {
		t.Fatalf("Connections: %v", err)
	}
	if snapshot.Connections != nil {
		t.Errorf("null connections must stay nil, got %#v", snapshot.Connections)
	}
}

func TestClientSendsBearerSecret(t *testing.T) {
	var gotAuth string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"version":"v1.19.32","meta":true}`))
	}, "s3cret")

	if _, err := client.Version(context.Background()); err != nil {
		t.Fatalf("Version: %v", err)
	}
	if gotAuth != "Bearer s3cret" {
		t.Errorf("unexpected Authorization header %q", gotAuth)
	}
}

func TestCloseConnectionAndAll(t *testing.T) {
	var paths []string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}, "")

	ctx := context.Background()
	if err := client.CloseConnection(ctx, "abc"); err != nil {
		t.Fatalf("CloseConnection: %v", err)
	}
	if err := client.CloseAllConnections(ctx); err != nil {
		t.Fatalf("CloseAllConnections: %v", err)
	}
	if len(paths) != 2 || paths[0] != "/connections/abc" || paths[1] != "/connections" {
		t.Errorf("unexpected paths %#v", paths)
	}
}

func TestCloseConnectionsForUserFiltersByUsername(t *testing.T) {
	var deleted []string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_, _ = w.Write([]byte(`{"connections":[
			  {"id":"a","metadata":{"inboundUser":"xb:u:7"}},
			  {"id":"b","metadata":{"inboundUser":"xb:u:8"}},
			  {"id":"c","metadata":{"inboundUser":"xb:u:7"}}
			]}`))
		case r.Method == http.MethodDelete:
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/connections/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}, "")

	closed, err := client.CloseConnectionsForUser(context.Background(), "xb:u:7")
	if err != nil {
		t.Fatalf("CloseConnectionsForUser: %v", err)
	}
	if closed != 2 {
		t.Errorf("expected 2 closed, got %d", closed)
	}
	if len(deleted) != 2 || deleted[0] != "a" || deleted[1] != "c" {
		t.Errorf("unexpected deletions %#v", deleted)
	}
}

func TestReloadUsesForceTrueAndAbsolutePath(t *testing.T) {
	var method, query string
	var body map[string]string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		query = r.URL.RawQuery
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusNoContent)
	}, "")

	if err := client.Reload(context.Background(), "/etc/xboard-node/node-1/config.yaml"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if method != http.MethodPut {
		t.Errorf("expected PUT, got %s", method)
	}
	if query != "force=true" {
		t.Errorf("force must be the literal true, got %q", query)
	}
	if body["path"] != "/etc/xboard-node/node-1/config.yaml" {
		t.Errorf("unexpected body %#v", body)
	}
}

func TestAPIErrorSurfacesMessage(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
	}, "wrong")

	if _, err := client.Connections(context.Background()); err == nil {
		t.Fatal("expected an error for a 401 response")
	} else if !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("error must include the kernel message, got %v", err)
	}
}
