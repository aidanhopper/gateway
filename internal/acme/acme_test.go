package acme

import (
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

func TestACMEManagerWithCloudflareTokenAndStagingDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "acme-cf-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr, err := NewManager(Config{
		Email:           "admin@test-domain.org",
		Domains:         []string{"test-domain.org"},
		CacheDir:        filepath.Join(tmpDir, "certs"),
		Directory:       lego.LEDirectoryStaging,
		CloudflareToken: "test_cf_api_token_12345",
	})
	if err != nil {
		t.Fatalf("NewManager with CF token failed: %v", err)
	}

	if mgr == nil {
		t.Fatal("expected non-nil ACME Manager")
	}

	if !mgr.HasDNSProvider() {
		t.Errorf("expected HasDNSProvider() to be true when CloudflareToken is provided")
	}
}



func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := GenerateSelfSignedCert([]string{"example.com", "test.dev"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected non-empty cert")
	}
}

func TestWildcardMatchingAndRootDomain(t *testing.T) {
	if got := ExtractRootDomain("app.example.com"); got != "example.com" {
		t.Errorf("ExtractRootDomain(app.example.com) = %q, want example.com", got)
	}
	if got := ExtractRootDomain("*.example.com"); got != "example.com" {
		t.Errorf("ExtractRootDomain(*.example.com) = %q, want example.com", got)
	}

	if !matchWildcardDomain("*.example.com", "app.example.com") {
		t.Error("expected *.example.com to match app.example.com")
	}
	if !matchWildcardDomain("*.example.com", "api.example.com") {
		t.Error("expected *.example.com to match api.example.com")
	}
	if !matchWildcardDomain("*.example.com", "example.com") {
		t.Error("expected *.example.com to match example.com")
	}
	if matchWildcardDomain("*.example.com", "sub.app.example.com") {
		t.Error("did not expect *.example.com to match sub.app.example.com")
	}
}
