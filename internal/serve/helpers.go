package serve

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/aidanhopper/gateway/internal/api"
)

// GatewayClient defines the REST operations required by serve.
type GatewayClient interface {
	ListRoutes(ctx context.Context) ([]api.RouteSpec, error)
	CreateRoute(ctx context.Context, spec api.RouteSpec) error
	DeleteRoute(ctx context.Context, name string) error
	ListListeners(ctx context.Context) ([]api.ListenerSpec, error)
	CreateListener(ctx context.Context, spec api.ListenerSpec) error
	DeleteListener(ctx context.Context, name string) error
	StreamLogs(ctx context.Context, routeFilter string, handler func(event api.LogEvent)) error
	ConfirmPublicSiteExposure(yesFlag bool, mountDesc string) bool
}

// ParseMount parses a positional serve target argument (e.g., "/path", "domain.com", "domain.com/path") into domain and path.
func ParseMount(arg string) (domain string, path string) {
	arg = strings.TrimSpace(arg)
	arg = strings.TrimPrefix(arg, "http://")
	arg = strings.TrimPrefix(arg, "https://")

	if strings.HasPrefix(arg, "/") {
		return "", arg
	}

	parts := strings.SplitN(arg, "/", 2)
	domain = parts[0]
	path = "/"
	if len(parts) == 2 && parts[1] != "" {
		path = "/" + parts[1]
	}
	return domain, path
}

// ExtractRuleDomainAndPath extracts host domain and path from a RuleSpec.
func ExtractRuleDomainAndPath(rule api.RuleSpec) (domain string, path string) {
	path = "/"
	rules := []api.RuleSpec{rule}
	if rule.Type == "and" {
		rules = rule.Rules
	}
	for _, r := range rules {
		if r.Type == "host" {
			domain = r.Value
		}
		if r.Type == "path" || r.Type == "path_prefix" {
			path = r.Value
		}
	}
	return domain, path
}

// ExtractHandlerTarget extracts the target string from a HandlerSpec.
func ExtractHandlerTarget(h api.HandlerSpec) string {
	if urlStr, ok := h.Config["url"].(string); ok {
		return urlStr
	}
	if targetStr, ok := h.Config["target"].(string); ok {
		return targetStr
	}
	if dirStr, ok := h.Config["dir"].(string); ok {
		return dirStr
	}
	if fileStr, ok := h.Config["file"].(string); ok {
		return fileStr
	}
	if h.Next != nil {
		return ExtractHandlerTarget(*h.Next)
	}
	return ""
}

// CalculateAutoPriority computes a priority score based on rule specificity unless an explicit priority (> 0) is specified.
func CalculateAutoPriority(rule api.RuleSpec, explicitPriority int) int {
	if explicitPriority > 0 {
		return explicitPriority
	}

	priority := 1
	domain, path := ExtractRuleDomainAndPath(rule)

	if domain != "" {
		priority += 100
	}

	if path != "" && path != "/" {
		priority += 100 + len(path)*10
	}

	if rule.Type == "path" {
		priority += 1000
	} else if rule.Type == "and" || rule.Type == "or" {
		for _, child := range rule.Rules {
			if child.Type == "path" {
				priority += 1000
				break
			}
		}
	}

	return priority
}

// HasMatchingRoute checks whether a route matching listener, domain, path, and target already exists.
// If a route exists for the exact same mount URL (listener, domain, path) but with a different target,
// the old route is deleted so it can be updated/replaced cleanly.
func HasMatchingRoute(ctx context.Context, client GatewayClient, listenerName, domain, path, target string) bool {
	routes, err := client.ListRoutes(ctx)
	if err != nil || len(routes) == 0 {
		return false
	}

	for _, r := range routes {
		if r.Listener != listenerName {
			continue
		}
		ruleDomain, rulePath := ExtractRuleDomainAndPath(r.Rule)
		if strings.EqualFold(ruleDomain, domain) && rulePath == path {
			if target != "" {
				handlerTarget := ExtractHandlerTarget(r.Handler)
				if strings.EqualFold(strings.TrimRight(handlerTarget, "/"), strings.TrimRight(target, "/")) {
					return true
				}
			} else {
				return true
			}
			// Route exists on the exact same mount URL with a different target -> remove old route to replace
			_ = client.DeleteRoute(ctx, r.Name)
		}
	}
	return false
}

// ValidateDNS checks if the domain's A/AAAA records resolve to this machine's public IP.
func ValidateDNS(domain string) (isMatch bool, resolvedIP string, serverIP string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || domain == "localhost" || strings.HasSuffix(domain, ".localhost") || strings.HasSuffix(domain, ".local") || net.ParseIP(domain) != nil {
		return false, "", ""
	}

	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return false, "", ""
	}

	resolvedIP = ips[0].String()

	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			serverIP = localAddr.IP.String()
		}
	}

	for _, ip := range ips {
		ipStr := ip.String()
		if ip.IsLoopback() || ipStr == "127.0.0.1" || ipStr == "::1" {
			continue
		}
		if ipStr == serverIP {
			return true, ipStr, serverIP
		}
	}

	return false, resolvedIP, serverIP
}

// HTTPStatusText returns the standard HTTP status text for status codes.
func HTTPStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	default:
		return ""
	}
}

// GetOutboundIP resolves local outbound IP.
func GetOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return localAddr.IP.String()
	}
	return ""
}

// IsNumericPort returns true if s consists entirely of digits.
func IsNumericPort(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// CleanupUnusedListeners removes serve- listeners that no longer have active routes.
func CleanupUnusedListeners(ctx context.Context, client GatewayClient) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		return
	}
	usedListeners := make(map[string]bool)
	for _, r := range routes {
		usedListeners[r.Listener] = true
	}

	listeners, err := client.ListListeners(ctx)
	if err != nil {
		return
	}

	for _, l := range listeners {
		if strings.HasPrefix(l.Name, "serve-") && !usedListeners[l.Name] {
			_ = client.DeleteListener(ctx, l.Name)
		}
	}
}

// EnsureListener finds or creates a listener matching name/address/protocol.
func EnsureListener(ctx context.Context, client GatewayClient, name, addr, proto string, tls *api.TLSConfigSpec) (string, error) {
	listeners, err := client.ListListeners(ctx)
	if err == nil {
		for _, l := range listeners {
			if l.Name == name || (l.Address == addr && l.Protocol == proto) {
				if tls != nil {
					needUpdate := false
					var newDomains []string
					if l.TLS != nil {
						newDomains = append([]string{}, l.TLS.Domains...)
					}
					domainMap := make(map[string]bool)
					for _, d := range newDomains {
						domainMap[d] = true
					}
					for _, d := range tls.Domains {
						if d != "" && !domainMap[d] {
							domainMap[d] = true
							newDomains = append(newDomains, d)
							needUpdate = true
						}
					}
					if l.TLS == nil || needUpdate {
						updatedTLS := *tls
						if len(newDomains) > 0 {
							updatedTLS.Domains = newDomains
						}
						spec := l
						spec.TLS = &updatedTLS
						_ = client.DeleteListener(ctx, l.Name)
						if createErr := client.CreateListener(ctx, spec); createErr != nil {
							_ = client.CreateListener(ctx, l)
							return "", fmt.Errorf("failed to update listener %s: %w", l.Name, createErr)
						}
					}
				}
				return l.Name, nil
			}
		}
	}

	spec := api.ListenerSpec{
		Name:     name,
		Address:  addr,
		Protocol: proto,
		TLS:      tls,
	}
	if err := client.CreateListener(ctx, spec); err != nil {
		return "", err
	}
	return name, nil
}
