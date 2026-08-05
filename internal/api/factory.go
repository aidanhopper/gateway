package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/aidanhopper/gateway/internal/gateway"
	"github.com/aidanhopper/gateway/internal/handlers"
)

// BuildNextFunc is a callback passed to HandlerFactory.Build to recursively build a nested HandlerSpec.
type BuildNextFunc func(spec HandlerSpec) (any, error)

// HandlerFactory defines the interface for creating and validating a specific handler type.
type HandlerFactory interface {
	Protocol() string
	Validate(spec HandlerSpec) error
	Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error)
}

// HandlerRegistry maintains a collection of registered HandlerFactories.
type HandlerRegistry struct {
	mu        sync.RWMutex
	factories map[string]HandlerFactory
}

// DefaultHandlerRegistry is the global registry used by default.
var DefaultHandlerRegistry = NewHandlerRegistry()

func init() {
	// TCP Load Balancers & Middlewares
	tcpProxyFactory := TCPProxyFactory{}
	DefaultHandlerRegistry.Register("tcp_echo", TCPEchoFactory{})
	DefaultHandlerRegistry.Register("tcp_proxy", tcpProxyFactory)
	DefaultHandlerRegistry.Register("tcp_lb", tcpProxyFactory)
	DefaultHandlerRegistry.Register("tcp_reverse_proxy", tcpProxyFactory)
	DefaultHandlerRegistry.Register("tcp_ip_allow", TCPIPAccessFactory{Mode: "allow"})
	DefaultHandlerRegistry.Register("tcp_ip_deny", TCPIPAccessFactory{Mode: "deny"})
	DefaultHandlerRegistry.Register("tcp_blackhole", TCPBlackholeFactory{})

	// HTTP Load Balancers & Traefik-Inspired Middlewares
	httpProxyFactory := HTTPProxyFactory{}
	DefaultHandlerRegistry.Register("http_proxy", httpProxyFactory)
	DefaultHandlerRegistry.Register("http_lb", httpProxyFactory)
	DefaultHandlerRegistry.Register("http_reverse_proxy", httpProxyFactory)
	DefaultHandlerRegistry.Register("http_strip_prefix", HTTPStripPrefixFactory{})
	DefaultHandlerRegistry.Register("http_add_prefix", HTTPAddPrefixFactory{})
	DefaultHandlerRegistry.Register("http_headers", HTTPHeadersFactory{})
	DefaultHandlerRegistry.Register("http_redirect", HTTPRedirectFactory{})
	DefaultHandlerRegistry.Register("http_basic_auth", HTTPBasicAuthFactory{})
	DefaultHandlerRegistry.Register("http_auth", HTTPAuthFactory{})
	DefaultHandlerRegistry.Register("http_rate_limit", HTTPRateLimitFactory{})
	DefaultHandlerRegistry.Register("http_ip_allow", HTTPIPAccessFactory{Mode: "allow"})
	DefaultHandlerRegistry.Register("http_ip_deny", HTTPIPAccessFactory{Mode: "deny"})

	// UDP Load Balancers & Middlewares
	udpProxyFactory := UDPProxyFactory{}
	DefaultHandlerRegistry.Register("udp_echo", UDPEchoFactory{})
	DefaultHandlerRegistry.Register("udp_proxy", udpProxyFactory)
	DefaultHandlerRegistry.Register("udp_lb", udpProxyFactory)
	DefaultHandlerRegistry.Register("udp_reverse_proxy", udpProxyFactory)
	DefaultHandlerRegistry.Register("udp_blackhole", UDPBlackholeFactory{})
}

// NewHandlerRegistry creates an empty HandlerRegistry.
func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{
		factories: make(map[string]HandlerFactory),
	}
}

// Register registers a new HandlerFactory for a given type name.
func (r *HandlerRegistry) Register(name string, factory HandlerFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
}

// Validate checks if the spec and any nested inner handler specs are supported and valid.
func (r *HandlerRegistry) Validate(protocol string, spec HandlerSpec) error {
	r.mu.RLock()
	factory, ok := r.factories[spec.Type]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("unsupported handler type %q", spec.Type)
	}

	if factory.Protocol() != protocol {
		return fmt.Errorf("handler type %q is for protocol %q, not %q", spec.Type, factory.Protocol(), protocol)
	}

	if err := factory.Validate(spec); err != nil {
		return err
	}

	if spec.Next != nil {
		return r.Validate(protocol, *spec.Next)
	}

	return nil
}

// Build validates and instantiates the concrete Go handler object, recursively building nested handlers via buildNext.
func (r *HandlerRegistry) Build(protocol string, spec HandlerSpec) (any, error) {
	if err := r.Validate(protocol, spec); err != nil {
		return nil, err
	}

	r.mu.RLock()
	factory := r.factories[spec.Type]
	r.mu.RUnlock()

	return factory.Build(spec, func(nextSpec HandlerSpec) (any, error) {
		return r.Build(protocol, nextSpec)
	})
}

// Helper to extract target addresses from config (supports "target": "str" or "targets": ["str1", "str2"])
func getTargetsFromConfig(config map[string]any) ([]string, error) {
	var targets []string
	if raw, ok := config["target"].(string); ok && strings.TrimSpace(raw) != "" {
		targets = append(targets, strings.TrimSpace(raw))
	}
	if rawList, ok := config["targets"].([]any); ok {
		for _, item := range rawList {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				targets = append(targets, strings.TrimSpace(s))
			}
		}
	} else if strList, ok := config["targets"].([]string); ok {
		targets = append(targets, strList...)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("either 'target' (string) or 'targets' ([]string) is required")
	}
	return targets, nil
}

// --- Concrete Handler Factories ---

type TCPEchoFactory struct{}
func (f TCPEchoFactory) Protocol() string { return "tcp" }
func (f TCPEchoFactory) Validate(spec HandlerSpec) error { return nil }
func (f TCPEchoFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	return handlers.NewTCPEchoServer(), nil
}

type TCPProxyFactory struct{}
func (f TCPProxyFactory) Protocol() string { return "tcp" }
func (f TCPProxyFactory) Validate(spec HandlerSpec) error {
	_, err := getTargetsFromConfig(spec.Config)
	return err
}
func (f TCPProxyFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	targets, err := getTargetsFromConfig(spec.Config)
	if err != nil {
		return nil, err
	}
	proxy := handlers.NewTCPLoadBalancer(targets...)
	if strat, ok := spec.Config["strategy"].(string); ok && strat != "" {
		proxy.Strategy = strat
	}
	return proxy, nil
}

type HTTPProxyFactory struct{}
func (f HTTPProxyFactory) Protocol() string { return "http" }
func (f HTTPProxyFactory) Validate(spec HandlerSpec) error {
	_, err := getTargetsFromConfig(spec.Config)
	return err
}
func (f HTTPProxyFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	targets, err := getTargetsFromConfig(spec.Config)
	if err != nil {
		return nil, err
	}
	proxy, err := handlers.NewHTTPLoadBalancer(targets...)
	if err != nil {
		return nil, err
	}
	if strat, ok := spec.Config["strategy"].(string); ok && strat != "" {
		proxy.Strategy = strat
	}
	if weightsRaw, ok := spec.Config["weights"].([]any); ok {
		for _, w := range weightsRaw {
			if wInt, ok := w.(float64); ok {
				proxy.Weights = append(proxy.Weights, int(wInt))
			}
		}
	}
	return proxy, nil
}

type HTTPStripPrefixFactory struct{}
func (f HTTPStripPrefixFactory) Protocol() string { return "http" }
func (f HTTPStripPrefixFactory) Validate(spec HandlerSpec) error {
	if spec.Next == nil {
		return fmt.Errorf("http_strip_prefix middleware requires an inner 'next' handler")
	}
	return nil
}
func (f HTTPStripPrefixFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	prefix, _ := spec.Config["prefix"].(string)
	nextObj, err := buildNext(*spec.Next)
	if err != nil {
		return nil, err
	}
	nextH, _ := nextObj.(http.Handler)
	return &handlers.HTTPStripPrefix{Prefix: prefix, Next: nextH}, nil
}

type HTTPAddPrefixFactory struct{}
func (f HTTPAddPrefixFactory) Protocol() string { return "http" }
func (f HTTPAddPrefixFactory) Validate(spec HandlerSpec) error {
	if spec.Next == nil {
		return fmt.Errorf("http_add_prefix middleware requires an inner 'next' handler")
	}
	return nil
}
func (f HTTPAddPrefixFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	prefix, _ := spec.Config["prefix"].(string)
	nextObj, err := buildNext(*spec.Next)
	if err != nil {
		return nil, err
	}
	nextH, _ := nextObj.(http.Handler)
	return &handlers.HTTPAddPrefix{Prefix: prefix, Next: nextH}, nil
}

type HTTPHeadersFactory struct{}
func (f HTTPHeadersFactory) Protocol() string { return "http" }
func (f HTTPHeadersFactory) Validate(spec HandlerSpec) error {
	if spec.Next == nil {
		return fmt.Errorf("http_headers middleware requires an inner 'next' handler")
	}
	return nil
}
func (f HTTPHeadersFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	nextObj, err := buildNext(*spec.Next)
	if err != nil {
		return nil, err
	}
	nextH, _ := nextObj.(http.Handler)

	reqHeaders := make(map[string]string)
	if reqMap, ok := spec.Config["add_request_headers"].(map[string]any); ok {
		for k, v := range reqMap {
			if s, ok := v.(string); ok {
				reqHeaders[k] = s
			}
		}
	}

	respHeaders := make(map[string]string)
	if respMap, ok := spec.Config["add_response_headers"].(map[string]any); ok {
		for k, v := range respMap {
			if s, ok := v.(string); ok {
				respHeaders[k] = s
			}
		}
	}

	var removeResp []string
	if remRaw, ok := spec.Config["remove_response_headers"].([]any); ok {
		for _, item := range remRaw {
			if s, ok := item.(string); ok {
				removeResp = append(removeResp, s)
			}
		}
	}

	return &handlers.HTTPHeaders{
		AddRequestHeaders:     reqHeaders,
		AddResponseHeaders:    respHeaders,
		RemoveResponseHeaders: removeResp,
		Next:                  nextH,
	}, nil
}

type HTTPRedirectFactory struct{}
func (f HTTPRedirectFactory) Protocol() string { return "http" }
func (f HTTPRedirectFactory) Validate(spec HandlerSpec) error {
	if urlStr, ok := spec.Config["url"].(string); !ok || strings.TrimSpace(urlStr) == "" {
		return fmt.Errorf("http_redirect requires 'url' string")
	}
	return nil
}
func (f HTTPRedirectFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	urlStr, _ := spec.Config["url"].(string)
	status := 301
	if s, ok := spec.Config["status"].(float64); ok {
		status = int(s)
	} else if s, ok := spec.Config["status"].(int); ok {
		status = s
	}

	forwardPath := true
	if fp, ok := spec.Config["forward_path"].(bool); ok {
		forwardPath = fp
	}

	stripPrefix, _ := spec.Config["strip_prefix"].(string)

	keepQuery := true
	if kq, ok := spec.Config["keep_query"].(bool); ok {
		keepQuery = kq
	}

	return &handlers.HTTPRedirect{
		URL:         urlStr,
		Status:      status,
		ForwardPath: forwardPath,
		StripPrefix: stripPrefix,
		KeepQuery:   keepQuery,
	}, nil
}

type HTTPBasicAuthFactory struct{}
func (f HTTPBasicAuthFactory) Protocol() string { return "http" }
func (f HTTPBasicAuthFactory) Validate(spec HandlerSpec) error {
	if spec.Next == nil {
		return fmt.Errorf("http_basic_auth middleware requires an inner 'next' handler")
	}
	return nil
}
func (f HTTPBasicAuthFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	u, _ := spec.Config["username"].(string)
	p, _ := spec.Config["password"].(string)
	nextObj, err := buildNext(*spec.Next)
	if err != nil {
		return nil, err
	}
	nextH, _ := nextObj.(http.Handler)
	return &handlers.HTTPBasicAuth{Username: u, Password: p, Next: nextH}, nil
}

type HTTPAuthFactory struct{}
func (f HTTPAuthFactory) Protocol() string { return "http" }
func (f HTTPAuthFactory) Validate(spec HandlerSpec) error {
	if spec.Next == nil {
		return fmt.Errorf("http_auth middleware requires an inner 'next' handler")
	}
	return nil
}
func (f HTTPAuthFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	authType, _ := spec.Config["auth_type"].(string)
	password, _ := spec.Config["password"].(string)
	pin, _ := spec.Config["pin"].(string)
	routeName, _ := spec.Config["route_name"].(string)
	secretStr, _ := spec.Config["cookie_secret"].(string)

	secretKey := []byte(secretStr)
	if len(secretKey) == 0 {
		secretKey = []byte("gateway-default-cookie-secret-key-32b")
	}

	nextObj, err := buildNext(*spec.Next)
	if err != nil {
		return nil, err
	}
	nextH, _ := nextObj.(http.Handler)

	return &handlers.HTTPAuth{
		AuthType:     authType,
		Password:     password,
		PIN:          pin,
		RouteName:    routeName,
		CookieSecret: secretKey,
		Next:         nextH,
	}, nil
}

type HTTPRateLimitFactory struct{}
func (f HTTPRateLimitFactory) Protocol() string { return "http" }
func (f HTTPRateLimitFactory) Validate(spec HandlerSpec) error {
	if spec.Next == nil {
		return fmt.Errorf("http_rate_limit middleware requires an inner 'next' handler")
	}
	return nil
}
func (f HTTPRateLimitFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	rate := 10.0
	if r, ok := spec.Config["rate"].(float64); ok && r > 0 {
		rate = r
	}
	burst := 20
	if b, ok := spec.Config["burst"].(float64); ok && b > 0 {
		burst = int(b)
	}
	nextObj, err := buildNext(*spec.Next)
	if err != nil {
		return nil, err
	}
	nextH, _ := nextObj.(http.Handler)
	return handlers.NewHTTPRateLimit(rate, burst, nextH), nil
}

type HTTPIPAccessFactory struct {
	Mode string
}
func (f HTTPIPAccessFactory) Protocol() string { return "http" }
func (f HTTPIPAccessFactory) Validate(spec HandlerSpec) error {
	if spec.Next == nil {
		return fmt.Errorf("http_ip_%s middleware requires an inner 'next' handler", f.Mode)
	}
	return nil
}
func (f HTTPIPAccessFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	var cidrs []string
	if raw, ok := spec.Config["cidrs"].([]any); ok {
		for _, item := range raw {
			if s, ok := item.(string); ok {
				cidrs = append(cidrs, s)
			}
		}
	}
	nextObj, err := buildNext(*spec.Next)
	if err != nil {
		return nil, err
	}
	nextH, _ := nextObj.(http.Handler)
	return handlers.NewHTTPIPAccess(f.Mode, cidrs, nextH)
}

type TCPIPAccessFactory struct {
	Mode string
}
func (f TCPIPAccessFactory) Protocol() string { return "tcp" }
func (f TCPIPAccessFactory) Validate(spec HandlerSpec) error {
	if spec.Next == nil {
		return fmt.Errorf("tcp_ip_%s middleware requires an inner 'next' handler", f.Mode)
	}
	return nil
}
func (f TCPIPAccessFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	var cidrs []string
	if raw, ok := spec.Config["cidrs"].([]any); ok {
		for _, item := range raw {
			if s, ok := item.(string); ok {
				cidrs = append(cidrs, s)
			}
		}
	}
	nextObj, err := buildNext(*spec.Next)
	if err != nil {
		return nil, err
	}
	nextH, _ := nextObj.(gateway.TCPHandler)
	return handlers.NewTCPIPAccess(f.Mode, cidrs, nextH)
}

type TCPBlackholeFactory struct{}
func (f TCPBlackholeFactory) Protocol() string { return "tcp" }
func (f TCPBlackholeFactory) Validate(spec HandlerSpec) error { return nil }
func (f TCPBlackholeFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	return &handlers.TCPBlackhole{}, nil
}

type UDPEchoFactory struct{}
func (f UDPEchoFactory) Protocol() string { return "udp" }
func (f UDPEchoFactory) Validate(spec HandlerSpec) error { return nil }
func (f UDPEchoFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	return handlers.NewUDPEchoServer(), nil
}

type UDPProxyFactory struct{}
func (f UDPProxyFactory) Protocol() string { return "udp" }
func (f UDPProxyFactory) Validate(spec HandlerSpec) error {
	_, err := getTargetsFromConfig(spec.Config)
	return err
}
func (f UDPProxyFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	targets, err := getTargetsFromConfig(spec.Config)
	if err != nil {
		return nil, err
	}
	proxy := handlers.NewUDPLoadBalancer(targets...)
	if strat, ok := spec.Config["strategy"].(string); ok && strat != "" {
		proxy.Strategy = strat
	}
	return proxy, nil
}

type UDPBlackholeFactory struct{}
func (f UDPBlackholeFactory) Protocol() string { return "udp" }
func (f UDPBlackholeFactory) Validate(spec HandlerSpec) error { return nil }
func (f UDPBlackholeFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	return &handlers.UDPBlackhole{}, nil
}
