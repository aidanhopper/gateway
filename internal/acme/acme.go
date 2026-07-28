package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// User represents an ACME user account for Lego.
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}
func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// Config defines options for initializing an ACME Manager using lego.
type Config struct {
	Email     string   // ACME contact email (defaults to GATEWAY_ACME_EMAIL)
	Domains   []string // List of allowed domains for certificate issuance
	CacheDir  string   // Path to cache directory (defaults to ~/.gateway/acme_certs)
	Directory string   // ACME directory URL (defaults to Let's Encrypt production)
}

// Manager manages ACME certificate issuance, caching, and HTTP-01 challenge solving via lego.
type Manager struct {
	user       *User
	client     *lego.Client
	httpSvr    *http01.ProviderServer
	cacheDir   string
	mu         sync.RWMutex
	certs      map[string]*tls.Certificate
	registered bool
}

// NewManager initializes an ACME Manager using lego.
func NewManager(cfg Config) (*Manager, error) {
	email := strings.TrimSpace(cfg.Email)
	if email == "" {
		email = strings.TrimSpace(os.Getenv("GATEWAY_ACME_EMAIL"))
	}
	if email == "" {
		return nil, errors.New("ACME auto-cert requires an email (set GATEWAY_ACME_EMAIL or specify email)")
	}

	cacheDir := strings.TrimSpace(cfg.CacheDir)
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			cacheDir = os.TempDir()
		} else {
			cacheDir = filepath.Join(homeDir, ".gateway", "acme_certs")
		}
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
	if cfg.Directory != "" {
		legoCfg.CADirURL = cfg.Directory
	}

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	provider := http01.NewProviderServer("", "80")
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, fmt.Errorf("failed to set HTTP-01 provider: %w", err)
	}

	return &Manager{
		user:     user,
		cacheDir: cacheDir,
		client:   client,
		httpSvr:  provider,
		certs:    make(map[string]*tls.Certificate),
	}, nil
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

// ObtainCertificate requests a certificate for the given domains via Lego and caches it.
func (m *Manager) ObtainCertificate(domains []string) (*tls.Certificate, error) {
	if len(domains) == 0 {
		return nil, errors.New("no domains provided for ACME certificate request")
	}

	if err := m.ensureRegistered(); err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("acme obtain cert failed for domains %v: %w", domains, err)
	}

	tlsCert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse obtained cert pair: %w", err)
	}

	m.mu.Lock()
	for _, domain := range domains {
		m.certs[domain] = &tlsCert
	}
	m.mu.Unlock()

	return &tlsCert, nil
}

// GetCertificate returns a cached certificate for a client hello.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	cert, ok := m.certs[hello.ServerName]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no certificate available for %s", hello.ServerName)
	}
	return cert, nil
}

// HTTPHandler returns an http.Handler for solving HTTP-01 challenges.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			return
		}
		if fallback != nil {
			fallback.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})
}
