package acme

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v4/lego"
)

func TestACMEEmailRequired(t *testing.T) {
	os.Unsetenv("GATEWAY_ACME_EMAIL")

	_, err := NewManager(Config{Domains: []string{"test-domain.org"}})
	if err == nil {
		t.Fatalf("expected NewManager to fail without email, got nil")
	}
}

func TestACMEManagerInitWithEnvVar(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "acme-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	os.Setenv("GATEWAY_ACME_EMAIL", "admin@test-domain.org")
	defer os.Unsetenv("GATEWAY_ACME_EMAIL")

	mgr, err := NewManager(Config{
		Domains:   []string{"test-domain.org"},
		CacheDir:  filepath.Join(tmpDir, "certs"),
		Directory: lego.LEDirectoryStaging,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if mgr == nil {
		t.Fatal("expected non-nil ACME Manager")
	}
}

func TestACMEHTTP01ChallengeHandlerFallback(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "acme-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	os.Setenv("GATEWAY_ACME_EMAIL", "admin@test-domain.org")
	defer os.Unsetenv("GATEWAY_ACME_EMAIL")

	mgr, err := NewManager(Config{
		Domains:   []string{"test-domain.org"},
		CacheDir:  filepath.Join(tmpDir, "certs"),
		Directory: lego.LEDirectoryStaging,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("FALLBACK_OK"))
	})

	handler := mgr.HTTPHandler(fallback)

	// Test non-ACME request passes through to fallback handler
	req := httptest.NewRequest("GET", "/hello", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "FALLBACK_OK" {
		t.Errorf("expected fallback handler response, got status %d body %q", rec.Code, rec.Body.String())
	}
}
