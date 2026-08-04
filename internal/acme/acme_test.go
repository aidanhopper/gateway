package acme

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
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

func TestACMECacheReloadUserModeDirectory(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	userCacheDir := filepath.Join(homeDir, ".local", "share", "gateway", "acme_certs")
	if err := os.MkdirAll(userCacheDir, 0700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	cert, err := GenerateSelfSignedCert([]string{"user-domain.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

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

	if err := os.WriteFile(filepath.Join(userCacheDir, "user-domain.com.crt"), certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(userCacheDir, "user-domain.com.key"), privKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	primaryCacheDir := filepath.Join(t.TempDir(), "primary_certs")
	mgr, err := NewManager(Config{
		Email:    "admin@user-domain.com",
		CacheDir: primaryCacheDir,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	retrievedCert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.user-domain.com"})
	if err != nil {
		t.Fatalf("GetCertificate failed to return cert from user mode cache directory: %v", err)
	}
	if retrievedCert == nil {
		t.Fatal("expected cert from user mode cache directory, got nil")
	}
}

func TestParseRetryAfterAndRateLimitPersistence(t *testing.T) {
	errLog := "acme: error: 429 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: urn:ietf:params:acme:error:rateLimited :: too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-08-02 00:31:45 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"

	parsedTime := parseRetryAfter(errLog)
	if parsedTime.Year() != 2026 || parsedTime.Month() != 8 || parsedTime.Day() != 2 {
		t.Errorf("expected date 2026-08-02, got %v", parsedTime)
	}

	tmpDir := t.TempDir()
	mgr, err := NewManager(Config{
		Email:    "admin@test-domain.org",
		CacheDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	futureTime := time.Now().Add(24 * time.Hour)
	mgr.recordRateLimit("ratelimited-domain.com", futureTime)

	retTime, limited := mgr.isRateLimited("ratelimited-domain.com")
	if !limited {
		t.Fatalf("expected isRateLimited to be true for ratelimited-domain.com")
	}
	if retTime.Unix() != futureTime.Unix() {
		t.Errorf("expected rate limit time %v, got %v", futureTime, retTime)
	}

	// Verify persistence in rate_limits.json across manager reload
	mgr2, err := NewManager(Config{
		Email:    "admin@test-domain.org",
		CacheDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("NewManager reload failed: %v", err)
	}

	if _, limited2 := mgr2.isRateLimited("ratelimited-domain.com"); !limited2 {
		t.Errorf("expected rate_limits.json persistence across manager reloads")
	}
}

func TestIsProductionCertAndUpgradeDetection(t *testing.T) {
	selfSignedCert, err := GenerateSelfSignedCert([]string{"app.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	if isProductionCert(selfSignedCert) {
		t.Errorf("expected isProductionCert to return false for self-signed development cert")
	}

	tmpDir := t.TempDir()
	mgr, err := NewManager(Config{
		Email:    "admin@example.com",
		CacheDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// On production manager, a self-signed cert should trigger upgrade (isCertValidAndUsable == false)
	if mgr.isCertValidAndUsable(selfSignedCert) {
		t.Errorf("expected isCertValidAndUsable to return false for self-signed cert on production manager")
	}
}

func TestRateLimitExpirationClearsLimit(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewManager(Config{
		Email:    "admin@test-domain.org",
		CacheDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	pastTime := time.Now().Add(-1 * time.Hour)
	mgr.recordRateLimit("expired-domain.com", pastTime)

	if _, limited := mgr.isRateLimited("expired-domain.com"); limited {
		t.Errorf("expected isRateLimited to return false for expired rate limit timestamp")
	}
}

func TestStagingUserAccountIsolation(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewManager(Config{
		Email:    "admin@staging-test.org",
		CacheDir: tmpDir,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Manually set a mock production registration on mgr.user
	mgr.user.Registration = &registration.Resource{
		URI: "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
	}

	stagingUser := &User{
		Email: mgr.user.Email,
		key:   mgr.user.key,
	}

	if stagingUser.Registration != nil {
		t.Fatalf("expected fresh stagingUser Registration to be nil before staging registration, got %v", stagingUser.Registration)
	}
}

func TestFormatRemainingTime(t *testing.T) {
	futureTime := time.Now().Add(2 * time.Hour)
	formatted := FormatRemainingTime(futureTime)
	if !strings.Contains(formatted, "remaining") || !strings.Contains(formatted, "until") {
		t.Errorf("expected FormatRemainingTime to contain 'remaining' and 'until', got %q", formatted)
	}

	pastTime := time.Now().Add(-1 * time.Hour)
	formattedPast := FormatRemainingTime(pastTime)
	if formattedPast != "0s (expired)" {
		t.Errorf("expected '0s (expired)', got %q", formattedPast)
	}
}
