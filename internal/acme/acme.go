package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aidanhopper/gateway/internal/config"
	"github.com/aidanhopper/gateway/internal/gateway"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

type acmeLoggerAdapter struct{}

func (a *acmeLoggerAdapter) Fatal(args ...interface{}) {
	msg := strings.TrimSpace(fmt.Sprintln(args...))
	a.log("ERROR", msg)
	os.Exit(1)
}

func (a *acmeLoggerAdapter) Fatalf(format string, args ...interface{}) {
	msg := strings.TrimSpace(fmt.Sprintf(format, args...))
	a.log("ERROR", msg)
	os.Exit(1)
}

func (a *acmeLoggerAdapter) Fatalln(args ...interface{}) {
	msg := strings.TrimSpace(fmt.Sprintln(args...))
	a.log("ERROR", msg)
	os.Exit(1)
}

func (a *acmeLoggerAdapter) Print(args ...interface{}) {
	msg := strings.TrimSpace(fmt.Sprint(args...))
	a.log("INFO", msg)
}

func (a *acmeLoggerAdapter) Printf(format string, args ...interface{}) {
	msg := strings.TrimSpace(fmt.Sprintf(format, args...))
	a.log("INFO", msg)
}

func (a *acmeLoggerAdapter) Println(args ...interface{}) {
	msg := strings.TrimSpace(fmt.Sprintln(args...))
	a.log("INFO", msg)
}

func (a *acmeLoggerAdapter) log(defaultLevel, msg string) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	level := defaultLevel
	if strings.HasPrefix(msg, "[INFO]") {
		level = "INFO"
		msg = strings.TrimSpace(strings.TrimPrefix(msg, "[INFO]"))
	} else if strings.HasPrefix(msg, "[WARN]") || strings.HasPrefix(msg, "[WARNING]") {
		level = "WARN"
		msg = strings.TrimPrefix(msg, "[WARN]")
		msg = strings.TrimPrefix(msg, "[WARNING]")
		msg = strings.TrimSpace(msg)
	} else if strings.HasPrefix(msg, "[ERR]") || strings.HasPrefix(msg, "[ERROR]") {
		level = "ERROR"
		msg = strings.TrimPrefix(msg, "[ERR]")
		msg = strings.TrimPrefix(msg, "[ERROR]")
		msg = strings.TrimSpace(msg)
	}

	switch level {
	case "WARN", "WARNING":
		gateway.LogWarn("ACME", "%s", msg)
	case "ERROR", "ERR":
		gateway.LogError("ACME", "%s", msg)
	default:
		gateway.LogInfo("ACME", "%s", msg)
	}
}

func init() {
	legolog.Logger = &acmeLoggerAdapter{}
}

// GenerateSelfSignedCert creates an in-memory self-signed tls.Certificate valid for localhost, IPs, and given domains.
func GenerateSelfSignedCert(dnsNames []string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Gateway Development TLS"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string{"localhost"}, dnsNames...),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create self-signed certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// DefaultMockObtainer generates a mock certificate.Resource with self-signed PEM bytes.
func DefaultMockObtainer(domains []string) (*certificate.Resource, error) {
	cert, err := GenerateSelfSignedCert(domains)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mock cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})

	privKeyBytes, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal mock private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	domain := "mock-domain"
	if len(domains) > 0 {
		domain = domains[0]
	}

	return &certificate.Resource{
		Domain:            domain,
		CertURL:           "https://mock-acme.local/cert/1",
		CertStableURL:     "https://mock-acme.local/cert/1",
		PrivateKey:        keyPEM,
		Certificate:       certPEM,
		IssuerCertificate: certPEM,
	}, nil
}

// User represents an ACME user account for Lego.
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string                        { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.key }

// Config defines options for initializing an ACME Manager using lego.
type Config struct {
	Email           string   // ACME contact email (defaults to GATEWAY_ACME_EMAIL)
	Domains         []string // List of root domains for wildcard certificate issuance
	CacheDir        string   // Path to cache directory (defaults to ~/.gateway/acme_certs)
	Directory       string   // ACME directory URL (defaults to Let's Encrypt production; set to "mock" for testing)
	CloudflareToken string   // Cloudflare API token for DNS-01 wildcard certificates
	MockObtainer    func(domains []string) (*certificate.Resource, error) // Optional mock certificate obtainer for testing
}

// Manager manages ACME wildcard certificate issuance and caching via Lego DNS-01.
type Manager struct {
	user         *User
	client       *lego.Client
	cacheDir     string
	hasDNS       bool
	isProduction bool
	isMock       bool
	mockObtainer func(domains []string) (*certificate.Resource, error)
	mu           sync.RWMutex
	certs        map[string]*tls.Certificate
	rateLimits   map[string]time.Time
	registered   bool
}

func (m *Manager) HasDNSProvider() bool {
	return m.hasDNS
}

// NewManager initializes an ACME Manager using lego with DNS-01 wildcard challenge solving.
func NewManager(cfg Config) (*Manager, error) {
	email := strings.TrimSpace(cfg.Email)
	if email == "" {
		email = strings.TrimSpace(os.Getenv("GATEWAY_ACME_EMAIL"))
	}
	if email == "" {
		return nil, errors.New("ACME auto-cert requires an email (set email in /etc/gateway/server.yaml or GATEWAY_ACME_EMAIL)")
	}

	cacheDir := strings.TrimSpace(cfg.CacheDir)
	if cacheDir == "" {
		cacheDir = config.ACMECacheDir()
	}

	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create ACME cert cache directory: %w", err)
	}

	accountKeyPath := filepath.Join(cacheDir, "user_account.key")
	privateKey, err := loadPrivateKey(accountKeyPath)
	if err != nil {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		_ = savePrivateKey(accountKeyPath, privateKey)
	}

	user := &User{
		Email: email,
		key:   privateKey,
	}

	legoCfg := lego.NewConfig(user)
	dirURL := strings.TrimSpace(cfg.Directory)
	if dirURL == "" {
		dirURL = strings.TrimSpace(os.Getenv("GATEWAY_ACME_DIRECTORY"))
	}

	isMock := dirURL == "mock" || strings.HasPrefix(dirURL, "mock://") || cfg.MockObtainer != nil
	mockObtainer := cfg.MockObtainer
	hasDNS := false
	var client *lego.Client
	isProduction := false

	if isMock {
		hasDNS = true
		if mockObtainer == nil {
			mockObtainer = DefaultMockObtainer
		}
	} else {
		if dirURL != "" {
			legoCfg.CADirURL = dirURL
		}
		isProduction = dirURL == "" || dirURL == lego.LEDirectoryProduction

		var err error
		client, err = lego.NewClient(legoCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create lego client: %w", err)
		}

		cfToken := strings.TrimSpace(cfg.CloudflareToken)
		if cfToken == "" {
			cfToken = strings.TrimSpace(os.Getenv("CF_DNS_API_TOKEN"))
		}
		if cfToken == "" {
			cfToken = strings.TrimSpace(os.Getenv("CLOUDFLARE_DNS_API_TOKEN"))
		}

		if cfToken != "" {
			_ = os.Setenv("CLOUDFLARE_DNS_API_TOKEN", cfToken)
			cfConfig := cloudflare.NewDefaultConfig()
			cfConfig.AuthToken = cfToken
			if dnsProvider, err := cloudflare.NewDNSProviderConfig(cfConfig); err == nil {
				_ = client.Challenge.SetDNS01Provider(dnsProvider)
				hasDNS = true
			}
		} else if dnsProvider, err := cloudflare.NewDNSProvider(); err == nil {
			_ = client.Challenge.SetDNS01Provider(dnsProvider)
			hasDNS = true
		}
	}

	mgr := &Manager{
		user:         user,
		cacheDir:     cacheDir,
		client:       client,
		hasDNS:       hasDNS,
		isProduction: isProduction,
		isMock:       isMock,
		mockObtainer: mockObtainer,
		certs:        make(map[string]*tls.Certificate),
		rateLimits:   make(map[string]time.Time),
	}
	mgr.loadRateLimits()
	mgr.loadCachedCertificates()
	return mgr, nil
}

func (m *Manager) loadCachedCertificates() {
	candidateDirs := []string{m.cacheDir}
	if home, err := os.UserHomeDir(); err == nil {
		candidateDirs = append(candidateDirs, filepath.Join(home, ".local", "share", "gateway", "acme_certs"))
	}
	if rootHome := "/root/.local/share/gateway/acme_certs"; rootHome != m.cacheDir {
		candidateDirs = append(candidateDirs, rootHome)
	}

	for _, dir := range candidateDirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".crt") {
				domain := strings.TrimSuffix(f.Name(), ".crt")
				crtPath := filepath.Join(dir, f.Name())
				keyPath := filepath.Join(dir, domain+".key")
				certBytes, err1 := os.ReadFile(crtPath)
				keyBytes, err2 := os.ReadFile(keyPath)
				if err1 == nil && err2 == nil {
					tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
					if err == nil {
						m.mu.Lock()
						m.certs["*."+domain] = &tlsCert
						m.certs[domain] = &tlsCert
						m.mu.Unlock()
					}
				}
			}
		}
	}
}

func matchWildcardDomain(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)

	if pattern == host {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		root := pattern[2:]
		if host == root {
			return true
		}
		suffix := pattern[1:]
		if strings.HasSuffix(host, suffix) {
			prefix := host[:len(host)-len(suffix)]
			if !strings.Contains(prefix, ".") {
				return true
			}
		}
	}

	return false
}

// ExtractRootDomain converts "app.example.com" or "*.example.com" to root domain "example.com".
func ExtractRootDomain(domain string) string {
	domain = strings.TrimPrefix(domain, "*.")
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return domain
}

func (m *Manager) ensureRegistered() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.registered {
		return nil
	}

	if m.isMock {
		m.user.Registration = &registration.Resource{
			URI: "https://mock-acme.local/acct/1",
		}
		m.registered = true
		return nil
	}

	reg, err := m.client.Registration.ResolveAccountByKey()
	if err == nil && reg != nil {
		m.user.Registration = reg
		m.registered = true
		return nil
	}

	reg, err = m.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %w", err)
	}

	m.user.Registration = reg
	m.registered = true
	return nil
}

func savePrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func isProductionCert(cert *tls.Certificate) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return false
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	issuer := strings.ToUpper(x509Cert.Issuer.CommonName + " " + strings.Join(x509Cert.Issuer.Organization, " "))
	if strings.Contains(issuer, "STAGING") || strings.Contains(issuer, "FAKE LE") || strings.Contains(issuer, "GATEWAY DEVELOPMENT") {
		return false
	}
	return true
}

// FormatRemainingTime formats a future timestamp into human-readable duration and UTC time string.
func FormatRemainingTime(t time.Time) string {
	rem := time.Until(t).Round(time.Second)
	if rem <= 0 {
		return "0s (expired)"
	}
	formattedTime := t.UTC().Format("2006-01-02 15:04:05 MST")
	return fmt.Sprintf("%v remaining (until %s)", rem, formattedTime)
}

func (m *Manager) isCertValidAndUsable(cert *tls.Certificate, domains ...string) bool {
	if !isCertValid(cert) {
		return false
	}
	if m.isProduction && !isProductionCert(cert) {
		for _, d := range domains {
			if d != "" {
				rootDomain := ExtractRootDomain(d)
				if retryAfter, limited := m.isRateLimited(rootDomain); limited {
					gateway.LogInfo("ACME", "using cached staging certificate for %s because production rate limit is active (%s)", rootDomain, FormatRemainingTime(retryAfter))
					return true
				}
				gateway.LogInfo("ACME", "rate limit for %s is no longer active, will request production certificate from Let's Encrypt", rootDomain)
			}
		}
		return false
	}
	return true
}

func isCertValid(cert *tls.Certificate) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return false
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	return time.Now().Add(7 * 24 * time.Hour).Before(x509Cert.NotAfter)
}

func parseRetryAfter(errStr string) time.Time {
	idx := strings.Index(errStr, "retry after ")
	if idx != -1 {
		rest := errStr[idx+len("retry after "):]
		if end := strings.IndexAny(rest, ":\n,"); end != -1 {
			candidate := strings.TrimSpace(rest[:end])
			if t, err := time.Parse("2006-01-02 15:04:05 MST", candidate); err == nil {
				return t
			}
		}
		if len(rest) >= 23 {
			candidate := strings.TrimSpace(rest[:23])
			if t, err := time.Parse("2006-01-02 15:04:05 MST", candidate); err == nil {
				return t
			}
		}
	}
	return time.Now().Add(24 * time.Hour)
}

func (m *Manager) rateLimitsPath() string {
	return filepath.Join(m.cacheDir, "rate_limits.json")
}

func (m *Manager) loadRateLimits() {
	data, err := os.ReadFile(m.rateLimitsPath())
	if err != nil {
		return
	}
	var raw map[string]time.Time
	if err := json.Unmarshal(data, &raw); err == nil {
		m.mu.Lock()
		for k, v := range raw {
			m.rateLimits[k] = v
			if time.Now().Before(v) {
				gateway.LogInfo("ACME", "loaded active rate limit for %s: %s", k, FormatRemainingTime(v))
			} else {
				gateway.LogInfo("ACME", "stored rate limit for %s has expired", k)
			}
		}
		m.mu.Unlock()
	}
}

func (m *Manager) saveRateLimits() {
	m.mu.RLock()
	data, err := json.MarshalIndent(m.rateLimits, "", "  ")
	m.mu.RUnlock()
	if err == nil {
		_ = os.WriteFile(m.rateLimitsPath(), data, 0600)
	}
}

func (m *Manager) isRateLimited(domain string) (time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.rateLimits[domain]
	if !ok {
		return time.Time{}, false
	}
	if time.Now().After(t) {
		return time.Time{}, false
	}
	return t, true
}

func (m *Manager) recordRateLimit(domain string, retryAfter time.Time) {
	m.mu.Lock()
	m.rateLimits[domain] = retryAfter
	m.mu.Unlock()
	m.saveRateLimits()
}

func (m *Manager) obtainMockCertificate(request certificate.ObtainRequest, rootDomain, domain string) (*tls.Certificate, error) {
	res, err := m.mockObtainer(request.Domains)
	if err != nil {
		return nil, fmt.Errorf("mock obtain wildcard cert failed for %s: %w", rootDomain, err)
	}
	tlsCert, err := tls.X509KeyPair(res.Certificate, res.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mock wildcard cert pair: %w", err)
	}

	crtPath := filepath.Join(m.cacheDir, rootDomain+".crt")
	keyPath := filepath.Join(m.cacheDir, rootDomain+".key")
	_ = os.WriteFile(crtPath, res.Certificate, 0600)
	_ = os.WriteFile(keyPath, res.PrivateKey, 0600)

	wildcardDomain := "*." + rootDomain
	m.mu.Lock()
	m.certs[wildcardDomain] = &tlsCert
	m.certs[rootDomain] = &tlsCert
	m.certs[domain] = &tlsCert
	m.mu.Unlock()

	return &tlsCert, nil
}

func (m *Manager) obtainStagingCertificate(request certificate.ObtainRequest, rootDomain, domain string) (*tls.Certificate, error) {
	if m.isMock {
		return m.obtainMockCertificate(request, rootDomain, domain)
	}

	stagingUser := &User{
		Email: m.user.Email,
		key:   m.user.key,
	}

	stagingCfg := lego.NewConfig(stagingUser)
	stagingCfg.CADirURL = lego.LEDirectoryStaging
	stagingClient, err := lego.NewClient(stagingCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME staging client: %w", err)
	}

	reg, regErr := stagingClient.Registration.ResolveAccountByKey()
	if regErr != nil || reg == nil {
		reg, regErr = stagingClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if regErr == nil && reg != nil {
		stagingUser.Registration = reg
	}

	cfToken := os.Getenv("CLOUDFLARE_DNS_API_TOKEN")
	if cfToken != "" {
		cfConfig := cloudflare.NewDefaultConfig()
		cfConfig.AuthToken = cfToken
		if dnsProvider, pErr := cloudflare.NewDNSProviderConfig(cfConfig); pErr == nil {
			_ = stagingClient.Challenge.SetDNS01Provider(dnsProvider)
		}
	}

	certificates, err := stagingClient.Certificate.Obtain(request)
	if err != nil {
		m.mu.RLock()
		if existingCert, ok := m.certs[rootDomain]; ok && isCertValid(existingCert) {
			m.mu.RUnlock()
			return existingCert, nil
		}
		if existingCert, ok := m.certs[domain]; ok && isCertValid(existingCert) {
			m.mu.RUnlock()
			return existingCert, nil
		}
		m.mu.RUnlock()
		return nil, fmt.Errorf("acme obtain staging cert failed for %s: %w", rootDomain, err)
	}

	tlsCert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse staging cert pair: %w", err)
	}

	crtPath := filepath.Join(m.cacheDir, rootDomain+".crt")
	keyPath := filepath.Join(m.cacheDir, rootDomain+".key")
	_ = os.WriteFile(crtPath, certificates.Certificate, 0600)
	_ = os.WriteFile(keyPath, certificates.PrivateKey, 0600)

	wildcardDomain := "*." + rootDomain
	m.mu.Lock()
	m.certs[wildcardDomain] = &tlsCert
	m.certs[rootDomain] = &tlsCert
	m.mu.Unlock()

	return &tlsCert, nil
}

// ObtainWildcardCertificate requests a wildcard SAN certificate (*.domain and domain) via Lego DNS-01.
func (m *Manager) ObtainWildcardCertificate(domain string) (*tls.Certificate, error) {
	rootDomain := ExtractRootDomain(domain)
	wildcardDomain := "*." + rootDomain

	m.mu.RLock()
	if existingCert, ok := m.certs[rootDomain]; ok && m.isCertValidAndUsable(existingCert, rootDomain) {
		m.mu.RUnlock()
		return existingCert, nil
	}
	if existingCert, ok := m.certs[wildcardDomain]; ok && m.isCertValidAndUsable(existingCert, wildcardDomain) {
		m.mu.RUnlock()
		return existingCert, nil
	}
	if existingCert, ok := m.certs[domain]; ok && m.isCertValidAndUsable(existingCert, domain) {
		m.mu.RUnlock()
		return existingCert, nil
	}
	m.mu.RUnlock()

	request := certificate.ObtainRequest{
		Domains: []string{wildcardDomain, rootDomain},
		Bundle:  true,
	}

	if m.isMock {
		return m.obtainMockCertificate(request, rootDomain, domain)
	}

	if retryAfter, limited := m.isRateLimited(rootDomain); limited {
		gateway.LogInfo("ACME", "skipping production certificate request for %s due to rate limit (%s), falling back to staging...", rootDomain, FormatRemainingTime(retryAfter))
		return m.obtainStagingCertificate(request, rootDomain, domain)
	}

	if err := m.ensureRegistered(); err != nil {
		return nil, err
	}

	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		if strings.Contains(err.Error(), "rateLimited") || strings.Contains(err.Error(), "too many certificates") {
			retryAfter := parseRetryAfter(err.Error())
			m.recordRateLimit(rootDomain, retryAfter)
			gateway.LogWarn("ACME", "production rate limit hit for %s (%s), falling back to Let's Encrypt staging...", rootDomain, FormatRemainingTime(retryAfter))
			return m.obtainStagingCertificate(request, rootDomain, domain)
		}
		if err != nil {
			m.mu.RLock()
			if existingCert, ok := m.certs[rootDomain]; ok && isCertValid(existingCert) {
				m.mu.RUnlock()
				return existingCert, nil
			}
			if existingCert, ok := m.certs[domain]; ok && isCertValid(existingCert) {
				m.mu.RUnlock()
				return existingCert, nil
			}
			m.mu.RUnlock()
			return nil, fmt.Errorf("acme obtain wildcard cert failed for %s: %w", rootDomain, err)
		}
	}

	tlsCert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse obtained wildcard cert pair: %w", err)
	}

	crtPath := filepath.Join(m.cacheDir, rootDomain+".crt")
	keyPath := filepath.Join(m.cacheDir, rootDomain+".key")
	_ = os.WriteFile(crtPath, certificates.Certificate, 0600)
	_ = os.WriteFile(keyPath, certificates.PrivateKey, 0600)

	m.mu.Lock()
	m.certs[wildcardDomain] = &tlsCert
	m.certs[rootDomain] = &tlsCert
	m.mu.Unlock()

	return &tlsCert, nil
}

// GetCertificate returns a cached certificate for a client hello or matches wildcard domain.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := strings.ToLower(hello.ServerName)
	if serverName == "" {
		serverName = "localhost"
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. Direct match
	if cert, ok := m.certs[serverName]; ok && cert != nil {
		return cert, nil
	}

	// 2. Wildcard SNI match
	for certDomain, cert := range m.certs {
		if cert != nil && matchWildcardDomain(certDomain, serverName) {
			return cert, nil
		}
	}

	// 3. Fallback to any cached cert
	for _, cert := range m.certs {
		if cert != nil {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("no certificate available for %s", serverName)
}
