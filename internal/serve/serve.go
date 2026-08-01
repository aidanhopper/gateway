package serve

import (
	"context"
	"fmt"
	"os"
	"strings"

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

	routeName := GenerateMountName("http", opts.Mount, target)

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
		Priority: CalculateAutoPriority(ruleSpec, opts.Priority),
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
	lAddr := ":443"
	lName := "serve-https-443"

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

	routeName := GenerateMountName("https", opts.Mount, target)

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
		Priority: CalculateAutoPriority(ruleSpec, opts.Priority),
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
			redirectRouteName := routeName + "-redir"
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
				Priority: CalculateAutoPriority(rRuleSpec, opts.Priority),
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

	routeName := GenerateMountName("tcp", opts.ListenPort, target)
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "tcp",
		Listener: actualListener,
		Priority: CalculateAutoPriority(api.RuleSpec{Type: "any"}, opts.Priority),
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

	routeName := GenerateMountName("udp", opts.ListenPort, target)
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "udp",
		Listener: actualListener,
		Priority: CalculateAutoPriority(api.RuleSpec{Type: "any"}, opts.Priority),
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
	arg0 := opts.Domain
	if arg0 == "" {
		arg0 = opts.HostOrPort
	}
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
		if arg1 != "" {
			target = arg1
		}
	}

	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	listenerName := "serve-mc-25565"

	actualListener, err := EnsureListener(ctx, client, listenerName, listenAddr, "tcp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Minecraft listener: %w", err)
	}

	var rules []api.RuleSpec
	rules = append(rules, api.RuleSpec{Type: "is_minecraft"})

	if hostVal != "" {
		rules = append(rules, api.RuleSpec{Type: "minecraft_host", Value: hostVal})
	}
	if len(opts.AllowPlayers) > 0 {
		rules = append(rules, api.RuleSpec{Type: "minecraft_player", Values: opts.AllowPlayers})
	}
	if len(opts.DenyPlayers) > 0 {
		rules = append(rules, api.RuleSpec{Type: "minecraft_player_not", Values: opts.DenyPlayers})
	}

	ruleSpec := api.RuleSpec{Type: "any"}
	if len(rules) == 1 {
		ruleSpec = rules[0]
	} else if len(rules) > 1 {
		ruleSpec = api.RuleSpec{Type: "and", Rules: rules}
	}

	routeName := GenerateMountName("minecraft", arg0, target)
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "tcp",
		Listener: actualListener,
		Priority: CalculateAutoPriority(ruleSpec, opts.Priority),
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
	if len(opts.AllowPlayers) > 0 {
		fmt.Printf("  ├── Whitelist: %s\n", strings.Join(opts.AllowPlayers, ", "))
	}
	if len(opts.DenyPlayers) > 0 {
		fmt.Printf("  ├── Blacklist: %s\n", strings.Join(opts.DenyPlayers, ", "))
	}
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
	if status != 301 && status != 302 && status != 307 && status != 308 {
		status = 301
	}

	displaySource := path
	if domain != "" {
		displaySource = domain + path
	}

	var createdRoutes []string

	tlsSpec := &api.TLSConfigSpec{
		Auto: opts.ACME,
	}
	if domain != "" {
		tlsSpec.Domains = []string{domain}
	}

	pathRuleType := "path_prefix"
	if opts.Exact {
		pathRuleType = "path"
	}

	handlerConfig := map[string]any{
		"url":          targetURL,
		"status":       float64(status),
		"forward_path": !opts.NoForwardPath,
		"strip_prefix": path,
		"keep_query":   !opts.NoQuery,
	}

	routeName := GenerateMountName("redirect", opts.Mount, targetURL)

	httpsListener, err := EnsureListener(ctx, client, "serve-https-443", ":443", "tcp", tlsSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTPS listener on :443: %v\n", err)
	} else {
		if HasMatchingRoute(ctx, client, httpsListener, domain, path, targetURL) {
			fmt.Printf("[INFO] Redirecting HTTPS https://%s -> %s (Code: %d, already active)\n", displaySource, targetURL, status)
			createdRoutes = append(createdRoutes, routeName)
		} else {
			var rules []api.RuleSpec
			rules = append(rules, api.RuleSpec{Type: "secure"})
			if domain != "" {
				rules = append(rules, api.RuleSpec{Type: "host", Value: domain})
			}
			if path != "/" && path != "" {
				rules = append(rules, api.RuleSpec{Type: pathRuleType, Value: path})
			}

			ruleSpec := rules[0]
			if len(rules) > 1 {
				ruleSpec = api.RuleSpec{Type: "and", Rules: rules}
			}

			httpsRoute := api.RouteSpec{
				Name:     routeName,
				Protocol: "http",
				Listener: httpsListener,
				Priority: CalculateAutoPriority(ruleSpec, opts.Priority),
				TTL:      int(opts.TTL.Seconds()),
				Rule:     ruleSpec,
				Handler: api.HandlerSpec{
					Type:   "http_redirect",
					Config: handlerConfig,
				},
			}

			if err := client.CreateRoute(ctx, httpsRoute); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTPS redirect route: %v\n", err)
			} else {
				createdRoutes = append(createdRoutes, routeName)
				fmt.Printf("[INFO] Redirecting HTTPS https://%s -> %s (Code: %d, Mount: %s)\n", displaySource, targetURL, status, routeName)
			}
		}
	}

	httpListener, err := EnsureListener(ctx, client, "serve-http-80", ":80", "tcp", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTP listener on :80: %v\n", err)
	} else {
		redirectRouteName := routeName + "-redir"
		if HasMatchingRoute(ctx, client, httpListener, domain, path, targetURL) {
			fmt.Printf("[INFO] Redirecting HTTP  http://%s -> %s (Code: %d, already active)\n", displaySource, targetURL, status)
		} else {
			var rRules []api.RuleSpec
			rRules = append(rRules, api.RuleSpec{Type: "not", Rule: &api.RuleSpec{Type: "secure"}})
			if domain != "" {
				rRules = append(rRules, api.RuleSpec{Type: "host", Value: domain})
			}
			if path != "/" && path != "" {
				rRules = append(rRules, api.RuleSpec{Type: pathRuleType, Value: path})
			}

			ruleSpec := rRules[0]
			if len(rRules) > 1 {
				ruleSpec = api.RuleSpec{Type: "and", Rules: rRules}
			}

			httpRoute := api.RouteSpec{
				Name:     redirectRouteName,
				Protocol: "http",
				Listener: httpListener,
				Priority: CalculateAutoPriority(ruleSpec, opts.Priority),
				TTL:      int(opts.TTL.Seconds()),
				Rule:     ruleSpec,
				Handler: api.HandlerSpec{
					Type:   "http_redirect",
					Config: handlerConfig,
				},
			}

			if err := client.CreateRoute(ctx, httpRoute); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTP redirect route: %v\n", err)
			} else {
				createdRoutes = append(createdRoutes, redirectRouteName)
				fmt.Printf("[INFO] Redirecting HTTP  http://%s -> %s (Code: %d, Mount: %s)\n", displaySource, targetURL, status, redirectRouteName)
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

	listeners, _ := client.ListListeners(ctx)
	listenerAddrMap := make(map[string]string)
	for _, l := range listeners {
		listenerAddrMap[l.Name] = l.Address
	}

	mountsMap := make(map[string]api.RouteSpec)
	mountListeners := make(map[string][]string)
	var primaryMountNames []string

	for _, r := range routes {
		if !IsServeRoute(r.Name) {
			continue
		}

		baseName := r.Name
		isHelper := false
		if strings.HasSuffix(r.Name, "-redir") {
			baseName = strings.TrimSuffix(r.Name, "-redir")
			isHelper = true
		} else if strings.HasSuffix(r.Name, "-http") {
			baseName = strings.TrimSuffix(r.Name, "-http")
			isHelper = true
		}

		addr := listenerAddrMap[r.Listener]
		if addr == "" {
			if strings.HasSuffix(r.Listener, "-443") {
				addr = ":443"
			} else if strings.HasSuffix(r.Listener, "-80") {
				addr = ":80"
			} else if strings.HasPrefix(r.Listener, "serve-") {
				parts := strings.Split(r.Listener, "-")
				addr = ":" + parts[len(parts)-1]
			} else {
				addr = r.Listener
			}
		}

		if !isHelper {
			if _, exists := mountsMap[baseName]; !exists {
				primaryMountNames = append(primaryMountNames, baseName)
			}
			mountsMap[baseName] = r
		}

		addrs := mountListeners[baseName]
		found := false
		for _, a := range addrs {
			if a == addr {
				found = true
				break
			}
		}
		if !found {
			mountListeners[baseName] = append(addrs, addr)
		}
	}

	var result []api.RouteSpec
	for _, name := range primaryMountNames {
		rSpec := mountsMap[name]
		addrs := mountListeners[name]
		if len(addrs) > 0 {
			rSpec.Listener = strings.Join(addrs, ", ")
		}

		if rSpec.Handler.Type == "http_redirect" {
			targetURL, _ := rSpec.Handler.Config["url"].(string)
			statusVal := 301
			if st, ok := rSpec.Handler.Config["status"].(float64); ok {
				statusVal = int(st)
			} else if st, ok := rSpec.Handler.Config["status"].(int); ok {
				statusVal = st
			}
			if targetURL != "" {
				rSpec.Handler.Config = map[string]any{
					"target": fmt.Sprintf("%d -> %s", statusVal, targetURL),
					"url":    targetURL,
				}
			}
		}

		result = append(result, rSpec)
	}

	return result, nil
}

// IsServeRoute returns true if route name belongs to a serve mount.
func IsServeRoute(name string) bool {
	return strings.HasPrefix(name, "http://") ||
		strings.HasPrefix(name, "https://") ||
		strings.HasPrefix(name, "mc://") ||
		strings.HasPrefix(name, "tcp://") ||
		strings.HasPrefix(name, "udp://") ||
		strings.HasPrefix(name, "serve-")
}

// Off removes an active serve mount by name or port.
func Off(ctx context.Context, client GatewayClient, nameOrPort string) (int, error) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve routes: %w", err)
	}

	targetName := strings.TrimSpace(nameOrPort)
	deletedCount := 0

	for _, r := range routes {
		if !IsServeRoute(r.Name) {
			continue
		}
		if r.Name == targetName ||
			r.Name == targetName+"-redir" ||
			r.Name == targetName+"-http" ||
			strings.HasPrefix(r.Name, targetName+"-") ||
			strings.Contains(r.Name, targetName) ||
			strings.HasSuffix(r.Listener, "-"+targetName) {
			if err := client.DeleteRoute(ctx, r.Name); err == nil {
				deletedCount++
			}
		}
	}

	if deletedCount == 0 {
		if err := client.DeleteRoute(ctx, targetName); err == nil {
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
		if IsServeRoute(r.Name) {
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
