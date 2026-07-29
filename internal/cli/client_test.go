package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aidanhopper/gateway/internal/api"
)

func TestClientAPIAndFallback(t *testing.T) {
	ctx := context.Background()

	// 1. Test live API mock
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/listeners":
			if r.Method == "GET" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"name":"ln1","address":":8080","protocol":"tcp"}]`))
			} else if r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"name":"ln1","address":":8080","protocol":"tcp"}`))
			}
		case "/api/v1/listeners/ln1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"deleted"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "gateway-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	dbPath := filepath.Join(tmpDir, "test.db")

	client := newClientDirect(server.URL, "test-token", dbPath)

	// Test Health
	health, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health failed: %v", err)
	}
	if health["status"] != "ok" {
		t.Errorf("expected status ok, got %v", health["status"])
	}

	// Test ListListeners
	lns, err := client.ListListeners(ctx)
	if err != nil {
		t.Fatalf("ListListeners failed: %v", err)
	}
	if len(lns) != 1 || lns[0].Name != "ln1" {
		t.Errorf("unexpected listeners: %+v", lns)
	}

	// Test CreateListener
	err = client.CreateListener(ctx, api.ListenerSpec{Name: "ln1", Address: ":8080", Protocol: "tcp"})
	if err != nil {
		t.Fatalf("CreateListener failed: %v", err)
	}

	// Test DeleteListener
	err = client.DeleteListener(ctx, "ln1")
	if err != nil {
		t.Fatalf("DeleteListener failed: %v", err)
	}

	// 2. Test Offline SQLite Fallback
	offlineClient := newClientDirect("http://127.0.0.1:59999", "", dbPath) // Unreachable port

	// Create listener directly in DB
	err = offlineClient.CreateListener(ctx, api.ListenerSpec{Name: "offline-ln", Address: ":9090", Protocol: "tcp"})
	if err != nil {
		t.Fatalf("offline CreateListener failed: %v", err)
	}

	// List listeners from DB
	offlineLns, err := offlineClient.ListListeners(ctx)
	if err != nil {
		t.Fatalf("offline ListListeners failed: %v", err)
	}
	if len(offlineLns) != 1 || offlineLns[0].Name != "offline-ln" {
		t.Errorf("unexpected offline listeners: %+v", offlineLns)
	}

	// Delete listener from DB
	err = offlineClient.DeleteListener(ctx, "offline-ln")
	if err != nil {
		t.Fatalf("offline DeleteListener failed: %v", err)
	}
}

func TestResolveSiteName(t *testing.T) {
	client := NewClient("production")
	if client.SiteName != "production" {
		t.Errorf("expected SiteName production, got %q", client.SiteName)
	}

	defaultClient := NewClient("")
	if defaultClient.SiteName == "" {
		t.Errorf("expected non-empty SiteName for default client")
	}
}

// Unused DB import check suppressor
var _ = json.Unmarshal
