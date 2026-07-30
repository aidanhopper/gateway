package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aidanhopper/gateway/internal/config"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

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
	Directory       string   // ACME directory URL (defaults to Let's Encrypt production)
	CloudflareToken string   // Cloudflare API token for DNS-01 wildcard certificates
}

// Manager manages ACME wildcard certificate issuance and caching via Lego DNS-01.
type Manager struct {
	user       *User
	client     *lego.Client
	cacheDir   string
	hasDNS     bool
	mu         sync.RWMutex
	certs      map[string]*tls.Certificate
	registered bool
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

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
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
	if dirURL != "" {
		legoCfg.CADirURL = dirURL
	}

	client, err := lego.NewClient(legoCfg)
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

	hasDNS := false
	if cfToken != "" {
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

	return &Manager{
		user:     user,
		cacheDir: cacheDir,
		client:   client,
		hasDNS:   hasDNS,
		certs:    make(map[string]*tls.Certificate),
	}, nil
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

	reg, err := m.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %w", err)
	}

	m.user.Registration = reg
	m.registered = true
	return nil
}

// ObtainWildcardCertificate requests a wildcard SAN certificate (*.domain and domain) via Lego DNS-01.
func (m *Manager) ObtainWildcardCertificate(domain string) (*tls.Certificate, error) {
	rootDomain := ExtractRootDomain(domain)
	wildcardDomain := "*." + rootDomain

	if err := m.ensureRegistered(); err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: []string{wildcardDomain, rootDomain},
		Bundle:  true,
	}

	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("acme obtain wildcard cert failed for %s: %w", rootDomain, err)
	}

	tlsCert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse obtained wildcard cert pair: %w", err)
	}

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
