package serve

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
)

// HTTP mounts a local HTTP service programmatically and returns created route names.
func HTTP(ctx context.Context, client GatewayClient, opts HTTPOptions) ([]string, error) {
	if !client.ConfirmPublicSiteExposure(opts.Yes, fmt.Sprintf("HTTP %s -> %s", opts.Mount, opts.Target)) {
		return nil, nil
	}

	target := opts.Target
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	domain, path := ParseMount(opts.Mount)
	lName := "serve-http-80"
	lAddr := ":80"

	actualListener, err := EnsureListener(ctx, client, lName, lAddr, "tcp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	routeName := fmt.Sprintf("serve-http-%d", time.Now().UnixNano())

	handlerSpec := api.HandlerSpec{
		Type:   "http_lb",
		Config: map[string]any{"target": target},
	}

	if path != "/" && path != "" {
		inner := handlerSpec
		handlerSpec = api.HandlerSpec{
			Type:   "http_strip_prefix",
			Config: map[string]any{"prefix": path},
			Next:   &inner,
		}
	}

	var rules []api.RuleSpec
	rules = append(rules, api.RuleSpec{Type: "not", Rule: &api.RuleSpec{Type: "secure"}})
	if domain != "" {
		rules = append(rules, api.RuleSpec{Type: "host", Value: domain})
	}
	if path != "/" && path != "" {
		rules = append(rules, api.RuleSpec{Type: "path_prefix", Value: path})
	}

	ruleSpec := rules[0]
	if len(rules) > 1 {
		ruleSpec = api.RuleSpec{Type: "and", Rules: rules}
	}

	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "http",
		Listener: actualListener,
		Priority: 1,
		TTL:      int(opts.TTL.Seconds()),
		Rule:     ruleSpec,
		Handler:  handlerSpec,
	}

	displayTarget := path
	if domain != "" {
		displayTarget = domain + path
	}

	if HasMatchingRoute(ctx, client, actualListener, domain, path, target) {
		fmt.Printf("[INFO] Serving HTTP %s -> %s (already active)\n", displayTarget, target)
		return nil, nil
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		return nil, fmt.Errorf("failed to create route: %w", err)
	}

	listenPort := strings.TrimPrefix(lAddr, ":")
	portSuffix := ""
	if listenPort != "80" {
		portSuffix = ":" + listenPort
	}

	fmt.Printf("[SUCCESS] Serving HTTP %s -> %s\n", displayTarget, target)
	fmt.Printf("  ├── Listener:    %s\n", lAddr)
	fmt.Printf("  ├── Mount:       %s\n", routeName)
	if opts.TTL > 0 {
		fmt.Printf("  ├── TTL:         %v (auto-expires)\n", opts.TTL)
	}
	if localIP := GetOutboundIP(); localIP != "" {
		fmt.Printf("  ├── Local URL:   http://localhost%s%s\n", portSuffix, path)
		fmt.Printf("  └── Network URL: http://%s%s%s\n", localIP, portSuffix, path)
	} else {
		fmt.Printf("  └── Local URL:   http://localhost%s%s\n", portSuffix, path)
	}

	return []string{routeName}, nil
}

// HTTPS mounts an HTTPS service programmatically and returns created route names.
func HTTPS(ctx context.Context, client GatewayClient, opts HTTPSOptions) ([]string, error) {
	if !client.ConfirmPublicSiteExposure(opts.Yes, fmt.Sprintf("HTTPS %s -> %s", opts.Mount, opts.Target)) {
		return nil, nil
	}

	parsedDomain, path := ParseMount(opts.Mount)
	target := opts.Target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") && !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	domainVal := parsedDomain

	lAddr := opts.ListenAddr
	if lAddr == "" {
		lAddr = ":443"
	}
	lName := fmt.Sprintf("serve-https-%s", strings.TrimPrefix(lAddr, ":"))

	useACME := opts.ACME
	if domainVal != "" && !useACME {
		dnsMatch, _, _ := ValidateDNS(domainVal)
		if dnsMatch {
			useACME = true
		}
	}

	var tlsSpec *api.TLSConfigSpec
	if useACME || domainVal != "" {
		tlsSpec = &api.TLSConfigSpec{
			Auto: useACME,
		}
		if domainVal != "" {
			tlsSpec.Domains = []string{domainVal}
		}
	}

	actualListener, err := EnsureListener(ctx, client, lName, lAddr, "tcp", tlsSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTPS listener: %w", err)
	}

	routeName := fmt.Sprintf("serve-https-route-%d", time.Now().UnixNano())

	var rules []api.RuleSpec
	rules = append(rules, api.RuleSpec{Type: "secure"})
	if domainVal != "" {
		rules = append(rules, api.RuleSpec{Type: "host", Value: domainVal})
	}
	if path != "/" && path != "" {
		rules = append(rules, api.RuleSpec{Type: "path_prefix", Value: path})
	}

	ruleSpec := rules[0]
	if len(rules) > 1 {
		ruleSpec = api.RuleSpec{Type: "and", Rules: rules}
	}

	innerHandler := api.HandlerSpec{
		Type:   "http_lb",
		Config: map[string]any{"target": target},
	}
	handlerSpec := innerHandler
	if path != "/" && path != "" {
		handlerSpec = api.HandlerSpec{
			Type:   "http_strip_prefix",
			Config: map[string]any{"prefix": path},
			Next:   &innerHandler,
		}
	}

	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "http",
		Listener: actualListener,
		Priority: 1,
		TTL:      int(opts.TTL.Seconds()),
		Rule:     ruleSpec,
		Handler:  handlerSpec,
	}

	displayTarget := path
	if domainVal != "" {
		displayTarget = domainVal + path
	}

	if HasMatchingRoute(ctx, client, actualListener, domainVal, path, target) {
		fmt.Printf("[INFO] Serving HTTPS %s -> %s (already active)\n", displayTarget, target)
		return nil, nil
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		return nil, fmt.Errorf("failed to create HTTPS route: %w", err)
	}

	fmt.Printf("[SUCCESS] Serving HTTPS %s -> %s\n", displayTarget, target)
	fmt.Printf("  ├── Listener:   %s\n", lAddr)
	if opts.TTL > 0 {
		fmt.Printf("  ├── Mount:      %s\n", routeName)
		fmt.Printf("  ├── TTL:        %v (auto-expires)\n", opts.TTL)
	} else if domainVal != "" {
		fmt.Printf("  ├── Mount:      %s\n", routeName)
	} else {
		fmt.Printf("  └── Mount:      %s\n", routeName)
	}
	if domainVal != "" {
		fmt.Printf("  └── Public URL: https://%s%s\n", domainVal, path)
	}

	createdRoutes := []string{routeName}

	if !opts.NoRedirect {
		httpListener, err := EnsureListener(ctx, client, "serve-http-80", ":80", "tcp", nil)
		if err == nil {
			redirectRouteName := fmt.Sprintf("serve-redirect-%s", routeName)
			var rRules []api.RuleSpec
			rRules = append(rRules, api.RuleSpec{Type: "not", Rule: &api.RuleSpec{Type: "secure"}})
			if domainVal != "" {
				rRules = append(rRules, api.RuleSpec{Type: "host", Value: domainVal})
			}
			if path != "/" && path != "" {
				rRules = append(rRules, api.RuleSpec{Type: "path_prefix", Value: path})
			}
			rRuleSpec := rRules[0]
			if len(rRules) > 1 {
				rRuleSpec = api.RuleSpec{Type: "and", Rules: rRules}
			}
			redirectTargetURL := "https://" + domainVal + path
			if domainVal == "" {
				redirectTargetURL = "https://" + path
			}
			redirectRouteSpec := api.RouteSpec{
				Name:     redirectRouteName,
				Protocol: "http",
				Listener: httpListener,
				Priority: 1,
				TTL:      int(opts.TTL.Seconds()),
				Rule:     rRuleSpec,
				Handler: api.HandlerSpec{
					Type:   "http_redirect",
					Config: map[string]any{"url": redirectTargetURL, "status": 301},
				},
			}
			if err := client.CreateRoute(ctx, redirectRouteSpec); err == nil {
				createdRoutes = append(createdRoutes, redirectRouteName)
				fmt.Printf("[INFO] Redirecting HTTP %s -> %s (Listener: :80)\n", displayTarget, redirectTargetURL)
			}
		}
	}

	return createdRoutes, nil
}

// TCP mounts a TCP stream serve mount programmatically and returns created route names.
func TCP(ctx context.Context, client GatewayClient, opts TCPOptions) ([]string, error) {
	if !client.ConfirmPublicSiteExposure(opts.Yes, fmt.Sprintf("TCP %s -> %s", opts.ListenPort, opts.Target)) {
		return nil, nil
	}

	listenPort := opts.ListenPort
	listenAddr := ":" + listenPort
	if strings.Contains(listenPort, ":") {
		listenAddr = listenPort
	}

	target := opts.Target
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	listenerName := fmt.Sprintf("serve-tcp-%s", strings.TrimPrefix(listenAddr, ":"))

	actualListener, err := EnsureListener(ctx, client, listenerName, listenAddr, "tcp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	routeName := fmt.Sprintf("serve-tcp-route-%d", time.Now().UnixNano())
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "tcp",
		Listener: actualListener,
		Priority: 1,
		TTL:      int(opts.TTL.Seconds()),
		Rule:     api.RuleSpec{Type: "any"},
		Handler: api.HandlerSpec{
			Type:   "tcp_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		return nil, fmt.Errorf("failed to create TCP route: %w", err)
	}

	fmt.Printf("[SUCCESS] Sharing TCP %s -> %s\n", listenAddr, target)
	fmt.Printf("  ├── Listener: %s\n", listenAddr)
	if opts.TTL > 0 {
		fmt.Printf("  ├── Mount:    %s\n", routeName)
		fmt.Printf("  └── TTL:      %v (auto-expires)\n", opts.TTL)
	} else {
		fmt.Printf("  └── Mount:    %s\n", routeName)
	}
	return []string{routeName}, nil
}

// UDP mounts a UDP stream serve mount programmatically and returns created route names.
func UDP(ctx context.Context, client GatewayClient, opts UDPOptions) ([]string, error) {
	if !client.ConfirmPublicSiteExposure(opts.Yes, fmt.Sprintf("UDP %s -> %s", opts.ListenPort, opts.Target)) {
		return nil, nil
	}

	listenPort := opts.ListenPort
	listenAddr := ":" + listenPort
	if strings.Contains(listenPort, ":") {
		listenAddr = listenPort
	}

	target := opts.Target
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	listenerName := fmt.Sprintf("serve-udp-%s", strings.TrimPrefix(listenAddr, ":"))

	actualListener, err := EnsureListener(ctx, client, listenerName, listenAddr, "udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP listener: %w", err)
	}

	routeName := fmt.Sprintf("serve-udp-route-%d", time.Now().UnixNano())
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "udp",
		Listener: actualListener,
		Priority: 1,
		TTL:      int(opts.TTL.Seconds()),
		Rule:     api.RuleSpec{Type: "any"},
		Handler: api.HandlerSpec{
			Type:   "udp_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		return nil, fmt.Errorf("failed to create UDP route: %w", err)
	}

	fmt.Printf("[SUCCESS] Sharing UDP %s -> %s\n", listenAddr, target)
	fmt.Printf("  ├── Listener: %s\n", listenAddr)
	if opts.TTL > 0 {
		fmt.Printf("  ├── Mount:    %s\n", routeName)
		fmt.Printf("  └── TTL:      %v (auto-expires)\n", opts.TTL)
	} else {
		fmt.Printf("  └── Mount:    %s\n", routeName)
	}
	return []string{routeName}, nil
}

// Minecraft mounts a Minecraft server serve mount programmatically and returns created route names.
func Minecraft(ctx context.Context, client GatewayClient, opts MinecraftOptions) ([]string, error) {
	arg0 := opts.HostOrPort
	arg1 := opts.Target

	if !client.ConfirmPublicSiteExposure(opts.Yes, fmt.Sprintf("Minecraft service %s", arg0)) {
		return nil, nil
	}

	parsedDomain, _ := ParseMount(arg0)
	listenAddr := ":25565"
	target := "127.0.0.1:25565"
	hostVal := ""

	if parsedDomain != "" || strings.Contains(arg0, ".") || (len(arg0) > 0 && !IsNumericPort(arg0) && !strings.HasPrefix(arg0, ":")) {
		hostVal = parsedDomain
		if hostVal == "" {
			hostVal = arg0
		}
		if arg1 != "" {
			target = arg1
		}
	} else {
		listenPort := arg0
		listenAddr = ":" + listenPort
		if strings.Contains(listenPort, ":") {
			listenAddr = listenPort
		}
		if arg1 != "" {
			target = arg1
		}
	}

	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	listenerName := fmt.Sprintf("serve-mc-%s", strings.TrimPrefix(listenAddr, ":"))

	actualListener, err := EnsureListener(ctx, client, listenerName, listenAddr, "tcp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Minecraft listener: %w", err)
	}

	var rules []api.RuleSpec
	rules = append(rules, api.RuleSpec{Type: "is_minecraft"})

	if hostVal != "" {
		rules = append(rules, api.RuleSpec{Type: "minecraft_host", Value: hostVal})
	}

	ruleSpec := api.RuleSpec{Type: "any"}
	if len(rules) == 1 {
		ruleSpec = rules[0]
	} else if len(rules) > 1 {
		ruleSpec = api.RuleSpec{Type: "and", Rules: rules}
	}

	routeName := fmt.Sprintf("serve-mc-route-%d", time.Now().UnixNano())
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "tcp",
		Listener: actualListener,
		Priority: 1,
		TTL:      int(opts.TTL.Seconds()),
		Rule:     ruleSpec,
		Handler: api.HandlerSpec{
			Type:   "tcp_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		return nil, fmt.Errorf("failed to create Minecraft route: %w", err)
	}

	displayHost := hostVal
	if displayHost == "" {
		displayHost = listenAddr
	}
	fmt.Printf("[SUCCESS] Sharing Minecraft %s -> %s\n", displayHost, target)
	fmt.Printf("  ├── Listener: %s\n", listenAddr)
	if opts.TTL > 0 {
		fmt.Printf("  ├── Mount:    %s\n", routeName)
		fmt.Printf("  └── TTL:      %v (auto-expires)\n", opts.TTL)
	} else {
		fmt.Printf("  └── Mount:    %s\n", routeName)
	}

	return []string{routeName}, nil
}



// Redirect mounts an HTTP/HTTPS redirect programmatically and returns created route names.
func Redirect(ctx context.Context, client GatewayClient, opts RedirectOptions) ([]string, error) {
	if !client.ConfirmPublicSiteExposure(opts.Yes, fmt.Sprintf("Redirect %s -> %s", opts.Mount, opts.TargetURL)) {
		return nil, nil
	}

	domain, path := ParseMount(opts.Mount)
	targetURL := opts.TargetURL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	status := opts.StatusCode
	if status != 301 && status != 302 {
		status = 301
	}

	displaySource := path
	if domain != "" {
		displaySource = domain + path
	}

	var createdRoutes []string

	tlsSpec := &api.TLSConfigSpec{
		Auto: true,
	}
	if domain != "" {
		tlsSpec.Domains = []string{domain}
	}

	httpsListener, err := EnsureListener(ctx, client, "serve-https-443", ":443", "tcp", tlsSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTPS listener on :443: %v\n", err)
	} else {
		if HasMatchingRoute(ctx, client, httpsListener, domain, path, targetURL) {
			fmt.Printf("[INFO] Redirecting HTTPS https://%s -> %s (Code: %d, already active)\n", displaySource, targetURL, status)
		} else {
			httpsRouteName := fmt.Sprintf("serve-redirect-https-%d", time.Now().UnixNano())
			var rules []api.RuleSpec
			rules = append(rules, api.RuleSpec{Type: "secure"})
			if domain != "" {
				rules = append(rules, api.RuleSpec{Type: "host", Value: domain})
			}
			if path != "/" && path != "" {
				rules = append(rules, api.RuleSpec{Type: "path_prefix", Value: path})
			}

			ruleSpec := rules[0]
			if len(rules) > 1 {
				ruleSpec = api.RuleSpec{Type: "and", Rules: rules}
			}

			httpsRoute := api.RouteSpec{
				Name:     httpsRouteName,
				Protocol: "http",
				Listener: httpsListener,
				Priority: 1,
				TTL:      int(opts.TTL.Seconds()),
				Rule:     ruleSpec,
				Handler: api.HandlerSpec{
					Type:   "http_redirect",
					Config: map[string]any{"url": targetURL, "status": float64(status)},
				},
			}

			if err := client.CreateRoute(ctx, httpsRoute); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTPS redirect route: %v\n", err)
			} else {
				createdRoutes = append(createdRoutes, httpsRouteName)
				fmt.Printf("[INFO] Redirecting HTTPS https://%s -> %s (Code: %d, Mount: %s)\n", displaySource, targetURL, status, httpsRouteName)
			}
		}
	}

	httpListener, err := EnsureListener(ctx, client, "serve-http-80", ":80", "tcp", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTP listener on :80: %v\n", err)
	} else {
		if HasMatchingRoute(ctx, client, httpListener, domain, path, targetURL) {
			fmt.Printf("[INFO] Redirecting HTTP  http://%s -> %s (Code: %d, already active)\n", displaySource, targetURL, status)
		} else {
			httpRouteName := fmt.Sprintf("serve-redirect-http-%d", time.Now().UnixNano())
			var rules []api.RuleSpec
			rules = append(rules, api.RuleSpec{Type: "not", Rule: &api.RuleSpec{Type: "secure"}})
			if domain != "" {
				rules = append(rules, api.RuleSpec{Type: "host", Value: domain})
			}
			if path != "/" && path != "" {
				rules = append(rules, api.RuleSpec{Type: "path_prefix", Value: path})
			}

			ruleSpec := rules[0]
			if len(rules) > 1 {
				ruleSpec = api.RuleSpec{Type: "and", Rules: rules}
			}

			httpRoute := api.RouteSpec{
				Name:     httpRouteName,
				Protocol: "http",
				Listener: httpListener,
				Priority: 1,
				TTL:      int(opts.TTL.Seconds()),
				Rule:     ruleSpec,
				Handler: api.HandlerSpec{
					Type:   "http_redirect",
					Config: map[string]any{"url": targetURL, "status": float64(status)},
				},
			}

			if err := client.CreateRoute(ctx, httpRoute); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTP redirect route: %v\n", err)
			} else {
				createdRoutes = append(createdRoutes, httpRouteName)
				fmt.Printf("[INFO] Redirecting HTTP  http://%s -> %s (Code: %d, Mount: %s)\n", displaySource, targetURL, status, httpRouteName)
			}
		}
	}

	if opts.TTL > 0 {
		fmt.Printf("[INFO] TTL: %v (auto-expires)\n", opts.TTL)
	}

	return createdRoutes, nil
}

// Status returns active serve mounts.
func Status(ctx context.Context, client GatewayClient) ([]api.RouteSpec, error) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve serve status: %w", err)
	}

	var serveRoutes []api.RouteSpec
	for _, r := range routes {
		if strings.HasPrefix(r.Name, "serve-") {
			serveRoutes = append(serveRoutes, r)
		}
	}

	return serveRoutes, nil
}

// Off removes an active serve mount by name or port.
func Off(ctx context.Context, client GatewayClient, nameOrPort string) (int, error) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve routes: %w", err)
	}

	deletedCount := 0
	for _, r := range routes {
		if r.Name == nameOrPort || strings.Contains(r.Name, nameOrPort) || strings.HasSuffix(r.Listener, "-"+nameOrPort) {
			if err := client.DeleteRoute(ctx, r.Name); err == nil {
				deletedCount++
			}
		}
	}

	if deletedCount == 0 {
		if err := client.DeleteRoute(ctx, nameOrPort); err == nil {
			deletedCount++
		}
	}

	if deletedCount > 0 {
		CleanupUnusedListeners(ctx, client)
	}

	return deletedCount, nil
}

// Reset clears all serve mounts.
func Reset(ctx context.Context, client GatewayClient) (int, error) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve routes: %w", err)
	}

	var serveRoutes []string
	for _, r := range routes {
		if strings.HasPrefix(r.Name, "serve-") {
			serveRoutes = append(serveRoutes, r.Name)
		}
	}

	deletedCount := 0
	for _, name := range serveRoutes {
		if err := client.DeleteRoute(ctx, name); err == nil {
			deletedCount++
		}
	}
	CleanupUnusedListeners(ctx, client)
	return deletedCount, nil
}
