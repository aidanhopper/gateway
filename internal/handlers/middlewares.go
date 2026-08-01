package handlers

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aidanhopper/gateway/internal/gateway"
)

// --- HTTP Middlewares ---

// HTTPStripPrefix strips a URL prefix before passing the request to the Next handler.
type HTTPStripPrefix struct {
	Prefix string
	Next   http.Handler
}

func (h *HTTPStripPrefix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Prefix != "" && h.Prefix != "/" {
		cleanPrefix := strings.TrimSuffix(h.Prefix, "/")
		if r.URL.Path == cleanPrefix {
			targetURL := cleanPrefix + "/"
			if r.URL.RawQuery != "" {
				targetURL += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, targetURL, http.StatusMovedPermanently)
			return
		}

		if strings.HasPrefix(r.URL.Path, cleanPrefix+"/") {
			r2 := new(http.Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.URL.Path = strings.TrimPrefix(r.URL.Path, cleanPrefix)
			if !strings.HasPrefix(r2.URL.Path, "/") {
				r2.URL.Path = "/" + r2.URL.Path
			}
			if h.Next != nil {
				h.Next.ServeHTTP(w, r2)
			}
			return
		}
	}
	if h.Next != nil {
		h.Next.ServeHTTP(w, r)
	}
}

// HTTPAddPrefix prepends a URL prefix before passing the request to the Next handler.
type HTTPAddPrefix struct {
	Prefix string
	Next   http.Handler
}

func (h *HTTPAddPrefix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Prefix != "" {
		r2 := new(http.Request)
		*r2 = *r
		r2.URL = new(url.URL)
		*r2.URL = *r.URL
		r2.URL.Path = h.Prefix + r.URL.Path
		if h.Next != nil {
			h.Next.ServeHTTP(w, r2)
		}
		return
	}
	if h.Next != nil {
		h.Next.ServeHTTP(w, r)
	}
}

// HTTPHeaders injects and removes request and response headers.
type HTTPHeaders struct {
	AddRequestHeaders     map[string]string
	AddResponseHeaders    map[string]string
	RemoveResponseHeaders []string
	Next                  http.Handler
}

func (h *HTTPHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for k, v := range h.AddRequestHeaders {
		r.Header.Set(k, v)
	}

	for k, v := range h.AddResponseHeaders {
		w.Header().Set(k, v)
	}

	if h.Next != nil {
		h.Next.ServeHTTP(w, r)
	}

	for _, k := range h.RemoveResponseHeaders {
		w.Header().Del(k)
	}
}

// HTTPRedirect performs HTTP 301/302/307/308 URL redirects.
type HTTPRedirect struct {
	URL         string
	Status      int
	ForwardPath bool
	StripPrefix string
	KeepQuery   bool
}

func (h *HTTPRedirect) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status := h.Status
	if status == 0 {
		status = http.StatusMovedPermanently
	}

	targetURL := strings.TrimSpace(h.URL)
	reqURI := r.URL.RequestURI()

	if targetURL == "" {
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		targetURL = "https://" + host + reqURI
	} else if strings.HasPrefix(targetURL, "https://") || strings.HasPrefix(targetURL, "http://") {
		if h.ForwardPath {
			reqPath := r.URL.Path
			subPath := reqPath
			if h.StripPrefix != "" {
				subPath = strings.TrimPrefix(reqPath, h.StripPrefix)
			}
			targetURL = strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(subPath, "/")
		} else if strings.HasSuffix(targetURL, "/") {
			schemeEnd := strings.Index(targetURL, "://")
			if schemeEnd != -1 {
				rest := targetURL[schemeEnd+3:]
				pathStart := strings.Index(rest, "/")
				if pathStart == -1 || rest[pathStart:] == "/" {
					base := strings.TrimRight(targetURL, "/")
					targetURL = base + reqURI
				}
			}
		}
	}

	if h.KeepQuery && r.URL.RawQuery != "" {
		if strings.Contains(targetURL, "?") {
			targetURL += "&" + r.URL.RawQuery
		} else {
			targetURL += "?" + r.URL.RawQuery
		}
	}

	http.Redirect(w, r, targetURL, status)
}

// HTTPBasicAuth verifies HTTP Basic Auth credentials.
type HTTPBasicAuth struct {
	Username string
	Password string
	Next     http.Handler
}

func (h *HTTPBasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(h.Username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(h.Password)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if h.Next != nil {
		h.Next.ServeHTTP(w, r)
	}
}

// HTTPIPAccess implements IP / CIDR whitelist (allow) or blacklist (deny) filtering.
type HTTPIPAccess struct {
	Mode string // "allow" or "deny"
	Nets []*net.IPNet
	Next http.Handler
}

func NewHTTPIPAccess(mode string, cidrs []string, next http.Handler) (*HTTPIPAccess, error) {
	var parsed []*net.IPNet
	for _, raw := range cidrs {
		if !strings.Contains(raw, "/") {
			if strings.Contains(raw, ":") {
				raw = raw + "/128"
			} else {
				raw = raw + "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		parsed = append(parsed, ipNet)
	}
	return &HTTPIPAccess{
		Mode: strings.ToLower(mode),
		Nets: parsed,
		Next: next,
	}, nil
}

func (h *HTTPIPAccess) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)

	matched := false
	if ip != nil {
		for _, net := range h.Nets {
			if net.Contains(ip) {
				matched = true
				break
			}
		}
	}

	if h.Mode == "allow" && !matched {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if h.Mode == "deny" && matched {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if h.Next != nil {
		h.Next.ServeHTTP(w, r)
	}
}

// HTTPRateLimit token-bucket rate limits HTTP requests per client IP.
type HTTPRateLimit struct {
	Rate  float64 // tokens per second
	Burst int
	Next  http.Handler

	mu      sync.Mutex
	buckets map[string]*rateBucket
}

type rateBucket struct {
	tokens     float64
	lastUpdate time.Time
}

func NewHTTPRateLimit(rate float64, burst int, next http.Handler) *HTTPRateLimit {
	if burst <= 0 {
		burst = 10
	}
	if rate <= 0 {
		rate = 5
	}
	return &HTTPRateLimit{
		Rate:    rate,
		Burst:   burst,
		Next:    next,
		buckets: make(map[string]*rateBucket),
	}
}

func (h *HTTPRateLimit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	h.mu.Lock()
	now := time.Now()
	b, ok := h.buckets[host]
	if !ok {
		b = &rateBucket{tokens: float64(h.Burst), lastUpdate: now}
		h.buckets[host] = b
	} else {
		elapsed := now.Sub(b.lastUpdate).Seconds()
		b.tokens += elapsed * h.Rate
		if b.tokens > float64(h.Burst) {
			b.tokens = float64(h.Burst)
		}
		b.lastUpdate = now
	}

	if b.tokens < 1.0 {
		h.mu.Unlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	b.tokens -= 1.0
	h.mu.Unlock()

	if h.Next != nil {
		h.Next.ServeHTTP(w, r)
	}
}

// --- TCP & UDP Middlewares & Handlers ---

// TCPBlackhole accepts connections and silently drops or consumes data.
type TCPBlackhole struct{}

func (h *TCPBlackhole) ServeTCP(conn net.Conn, metadata gateway.TCPMetadata) {
	buf := make([]byte, 4096)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			return
		}
	}
}

// UDPBlackhole silently drops incoming UDP packets.
type UDPBlackhole struct{}

func (h *UDPBlackhole) ServeUDP(conn net.Conn, metadata gateway.UDPMetadata) {
	buf := make([]byte, 65535)
	_, _ = conn.Read(buf)
}

// TCPIPAccess filters TCP connections based on IP / CIDR whitelist or blacklist.
type TCPIPAccess struct {
	Mode string // "allow" or "deny"
	Nets []*net.IPNet
	Next gateway.TCPHandler
}

func NewTCPIPAccess(mode string, cidrs []string, next gateway.TCPHandler) (*TCPIPAccess, error) {
	var parsed []*net.IPNet
	for _, raw := range cidrs {
		if !strings.Contains(raw, "/") {
			if strings.Contains(raw, ":") {
				raw = raw + "/128"
			} else {
				raw = raw + "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		parsed = append(parsed, ipNet)
	}
	return &TCPIPAccess{
		Mode: strings.ToLower(mode),
		Nets: parsed,
		Next: next,
	}, nil
}

func (h *TCPIPAccess) ServeTCP(conn net.Conn, metadata gateway.TCPMetadata) {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	ip := net.ParseIP(host)

	matched := false
	if ip != nil {
		for _, net := range h.Nets {
			if net.Contains(ip) {
				matched = true
				break
			}
		}
	}

	if h.Mode == "allow" && !matched {
		conn.Close()
		return
	}
	if h.Mode == "deny" && matched {
		conn.Close()
		return
	}

	if h.Next != nil {
		h.Next.ServeTCP(conn, metadata)
	}
}

