package acme

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

func TestACMECacheReloadPreventsIssuance(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "acme-cache-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cacheDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create a valid self-signed certificate for cached-domain.com
	cert, err := GenerateSelfSignedCert([]string{"cached-domain.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// Encode PEM cert block
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})

	privKeyBytes, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("MarshalECPrivateKey failed: %v", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Write cert and key to disk cache
	crtPath := filepath.Join(cacheDir, "cached-domain.com.crt")
	keyPath := filepath.Join(cacheDir, "cached-domain.com.key")
	if err := os.WriteFile(crtPath, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, privKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	mgr, err := NewManager(Config{
		Email:    "admin@cached-domain.com",
		CacheDir: cacheDir,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Verify GetCertificate returns cached cert
	retrievedCert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.cached-domain.com"})
	if err != nil {
		t.Fatalf("GetCertificate failed to return cached cert: %v", err)
	}
	if retrievedCert == nil {
		t.Fatal("expected cached certificate, got nil")
	}

	// ObtainWildcardCertificate should return cached cert WITHOUT calling Lego network issuance
	obtainedCert, err := mgr.ObtainWildcardCertificate("cached-domain.com")
	if err != nil {
		t.Fatalf("ObtainWildcardCertificate failed on cached cert: %v", err)
	}
	if obtainedCert == nil {
		t.Fatal("expected obtainedCert from cache, got nil")
	}
}
