package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
)

// WatchAndCleanup blocks, streams logs for the given routes, and deletes the routes on Ctrl+C (SIGINT/SIGTERM).
func WatchAndCleanup(client *Client, routeNames ...string) {
	if len(routeNames) == 0 {
		return
	}
	mainRoute := routeNames[0]

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Println("\nLogs streaming... Press Ctrl+C to stop sharing.")
	fmt.Println("-----------------------------------------------------------------------------------------")

	go func() {
		err := client.StreamLogs(ctx, mainRoute, func(event api.LogEvent) {
			timeStr := event.Timestamp.Format("15:04:05")

			if event.MinecraftInfo != nil {
				mcDetails := ""
				if event.MinecraftInfo.Username != "" {
					mcDetails = fmt.Sprintf(" [Player: %s]", event.MinecraftInfo.Username)
				} else if event.MinecraftInfo.ProtocolState == 1 {
					mcDetails = " [Ping/Status]"
				} else if event.MinecraftInfo.ProtocolState == 2 {
					mcDetails = " [Login]"
				}
				if event.MinecraftInfo.RequestedHost != "" {
					mcDetails += fmt.Sprintf(" host: %s", event.MinecraftInfo.RequestedHost)
				}

				durationStr := ""
				if event.DurationMs > 0 {
					durationStr = fmt.Sprintf(" (%dms)", event.DurationMs)
				}

				fmt.Printf("[%s] minecraft%s%s - %s\n",
					timeStr, mcDetails, durationStr, event.RemoteIP)
				return
			}

			statusStr := ""
			if event.Status > 0 {
				statusStr = fmt.Sprintf("%d %s ", event.Status, httpStatusText(event.Status))
			}
			pathStr := event.Path
			if pathStr == "" {
				pathStr = event.Protocol
			}
			methodStr := event.Method
			if methodStr != "" {
				methodStr += " "
			}

			fmt.Printf("[%s] %s%s %s(%dms) - %s\n",
				timeStr, methodStr, pathStr, statusStr, event.DurationMs, event.RemoteIP)
		})
		if err != nil && ctx.Err() == nil {
			log.Printf("stream error: %v\n", err)
		}
	}()

	<-ctx.Done()
	fmt.Println("\nReceived interrupt. Stopping share...")

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cleanupCancel()

	for _, rName := range routeNames {
		if err := client.DeleteRoute(cleanupCtx, rName); err != nil {
			log.Printf("failed to delete route %s on exit: %v\n", rName, err)
		} else {
			fmt.Printf("Route %q deleted.\n", rName)
		}
	}
	fmt.Println("Sharing stopped.")
	cleanupUnusedServeListeners(cleanupCtx, client)
}

// extractBoolFlag pre-scans args for boolean flag names (e.g. "w", "watch") that may appear
// anywhere in the argument list, including after positional args. Returns the cleaned arg list
// and whether the flag was found. This works around the Go flag package stopping at the first
// non-flag argument.
func extractBoolFlag(args []string, names ...string) ([]string, bool) {
	allowed := make(map[string]bool, len(names)*2)
	for _, n := range names {
		allowed["-"+n] = true
		allowed["--"+n] = true
	}
	var out []string
	found := false
	for _, a := range args {
		if allowed[a] {
			found = true
		} else {
			out = append(out, a)
		}
	}
	return out, found
}

// extractWatchAndBGFlags scans args for background mode (-bg, --bg, -d) or foreground watch mode (-w, --watch).
// Returns cleaned args and whether watchMode should be active (defaults to true unless background mode is requested).
func extractWatchAndBGFlags(args []string) ([]string, bool) {
	args, bgMode := extractBoolFlag(args, "bg", "d")
	args, explicitWatch := extractBoolFlag(args, "w", "watch")
	if bgMode && !explicitWatch {
		return args, false
	}
	return args, true
}

// hasHelpFlag checks whether -h or --help appears anywhere in args, including after positional args.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "-help" {
			return true
		}
	}
	return false
}

// parseServeMount parses a positional serve target argument (e.g., "/path", "domain.com", "domain.com/path", "https://domain.com/path")
// into its domain and path components.
func parseServeMount(arg string) (domain string, path string) {
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

	// Get outbound local/public IP
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

func httpStatusText(code int) string {
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

// PrintServeUsage prints usage for 'gateway serve' subcommands.
func PrintServeUsage() {
	fmt.Println("Usage: gateway serve <protocol|command> [args] [flags]")
	fmt.Println("\nProtocols:")
	fmt.Println("  dir [https] <domain/path> <folder|file> Expose local folder/file (e.g. gateway serve dir app.domain.com/ ./dist)")
	fmt.Println("  file [https] <domain/path> <file>      Expose single static file (e.g. gateway serve file what.domain.com/install.sh ./install.sh)")
	fmt.Println("  spa [https] <domain/path> <folder>      Expose Single Page App with index.html fallback")
	fmt.Println("  http <path> <target>        Expose local HTTP service (e.g. gateway serve http / 3000)")
	fmt.Println("  https <path> <target>       Expose local service over HTTPS (e.g. gateway serve https / 3000 --acme)")
	fmt.Println("  tcp <port> <target>         Expose TCP stream (e.g. gateway serve tcp 2222 127.0.0.1:22)")
	fmt.Println("  udp <port> <target>         Expose UDP stream (e.g. gateway serve udp 5353 127.0.0.1:53)")
	fmt.Println("  minecraft <port> <target>   Expose Minecraft server with player/host filters")
	fmt.Println("\nCommon Flags:")
	fmt.Println("  --watch, -w                 Stream live logs; delete route on Ctrl+C (default)")
	fmt.Println("  --bg, -d                    Run in background mode")
	fmt.Println("  --ttl <duration>            Auto-expire the route (e.g. 30s, 15m, 2h, 1d)")
	fmt.Println("\nManagement:")
	fmt.Println("  status                      List active serve mounts and TTL countdowns")
	fmt.Println("  off <name_or_port>          Remove an active serve mount")
	fmt.Println("  reset                       Clear all serve mounts")
}

// RunServe handles 'gateway serve' subcommands.
func RunServe(args []string) {
	if len(args) < 1 {
		PrintServeUsage()
		os.Exit(0)
	}

	subcmd := args[0]
	if subcmd == "--help" || subcmd == "-h" || subcmd == "help" {
		PrintServeUsage()
		os.Exit(0)
	}

	client := NewClient("", "", "")
	ctx := context.Background()

	switch subcmd {
	case "dir", "static", "spa", "file":
		runServeDir(ctx, client, args[1:], subcmd == "spa")
	case "http":
		runServeHTTP(ctx, client, args[1:])
	case "https":
		runServeHTTPS(ctx, client, args[1:])
	case "tcp":
		runServeTCP(ctx, client, args[1:])
	case "udp":
		runServeUDP(ctx, client, args[1:])
	case "minecraft":
		runServeMinecraft(ctx, client, args[1:])
	case "status":
		runServeStatus(ctx, client)
	case "off":
		if len(args) < 2 {
			fmt.Println("Usage: gateway serve off <name_or_port>")
			os.Exit(0)
		}
		runServeOff(ctx, client, args[1])
	case "reset":
		runServeReset(ctx, client)
	default:
		PrintServeUsage()
		os.Exit(0)
	}
}

func cleanupUnusedServeListeners(ctx context.Context, client *Client) {
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

func ensureListener(ctx context.Context, client *Client, name, addr, proto string, tls *api.TLSConfigSpec) (string, error) {
	listeners, err := client.ListListeners(ctx)
	if err == nil {
		for _, l := range listeners {
			if l.Name == name || l.Address == addr {
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

func runServeHTTP(ctx context.Context, client *Client, args []string) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve http", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration (e.g. 30s, 15m, 2h, 1d)")
	listenerName := fs.String("listener", "serve-http-80", "Listener name")
	listenAddr := fs.String("listen", ":80", "Listen address")
	stripPrefix := fs.String("strip-prefix", "", "Strip path prefix before forwarding")
	noStripPrefix := fs.Bool("no-strip-prefix", false, "Do not automatically strip path prefix when forwarding")
	basicAuth := fs.String("basic-auth", "", "Enforce HTTP basic auth (user:pass)")
	rateLimit := fs.String("rate-limit", "", "Rate limit (rate/burst, e.g. 100/20)")
	_ = fs.Bool("bg", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("d", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("watch", false, "Stream live logs in foreground and remove route on Ctrl+C (default)")
	_ = fs.Bool("w", false, "Stream live logs in foreground and remove route on Ctrl+C (default)")

	if hasHelpFlag(args) {
		fmt.Println("Usage: gateway serve http <path> <target> [flags]")
		fs.PrintDefaults()
		os.Exit(0)
	}

	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		fmt.Println("Usage: gateway serve http <path> <target> [flags]")
		os.Exit(0)
	}

	mountArg := fs.Arg(0)
	target := fs.Arg(1)

	domain, path := parseServeMount(mountArg)

	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	lName := *listenerName
	if lName == "serve-http-80" && *listenAddr != ":80" {
		lName = fmt.Sprintf("serve-http-%s", strings.TrimPrefix(*listenAddr, ":"))
	}

	actualListener, err := ensureListener(ctx, client, lName, *listenAddr, "tcp", nil)
	if err != nil {
		log.Fatalf("failed to create listener: %v", err)
	}

	routeName := fmt.Sprintf("serve-http-%d", time.Now().UnixNano()%10000)

	// Handler chain: Optional BasicAuth / RateLimit / StripPrefix -> http_lb
	handlerSpec := api.HandlerSpec{
		Type:   "http_lb",
		Config: map[string]any{"target": target},
	}

	prefixToStrip := *stripPrefix
	if prefixToStrip == "" && !*noStripPrefix && path != "/" && path != "" {
		prefixToStrip = path
	}

	if prefixToStrip != "" {
		inner := handlerSpec
		handlerSpec = api.HandlerSpec{
			Type:   "http_strip_prefix",
			Config: map[string]any{"prefix": prefixToStrip},
			Next:   &inner,
		}
	}

	if *basicAuth != "" {
		parts := strings.SplitN(*basicAuth, ":", 2)
		if len(parts) == 2 {
			inner := handlerSpec
			handlerSpec = api.HandlerSpec{
				Type:   "http_basic_auth",
				Config: map[string]any{"username": parts[0], "password": parts[1]},
				Next:   &inner,
			}
		}
	}

	if *rateLimit != "" {
		parts := strings.SplitN(*rateLimit, "/", 2)
		rateVal := 100.0
		burstVal := 20.0
		if len(parts) >= 1 {
			if r, e := strconv.ParseFloat(parts[0], 64); e == nil {
				rateVal = r
			}
		}
		if len(parts) == 2 {
			if b, e := strconv.ParseFloat(parts[1], 64); e == nil {
				burstVal = b
			}
		}
		inner := handlerSpec
		handlerSpec = api.HandlerSpec{
			Type:   "http_rate_limit",
			Config: map[string]any{"rate": rateVal, "burst": burstVal},
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
		TTL:      int(ttlDuration.Seconds()),
		Rule:     ruleSpec,
		Handler:  handlerSpec,
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		log.Fatalf("failed to create route: %v", err)
	}

	displayTarget := path
	if domain != "" {
		displayTarget = domain + path
	}
	fmt.Printf("Sharing HTTP %s -> %s (Listener: %s)\n", displayTarget, target, *listenAddr)
	if ttlDuration > 0 {
		fmt.Printf("TTL: %v (auto-expires)\n", ttlDuration)
	}

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func runServeHTTPS(ctx context.Context, client *Client, args []string) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve https", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration (e.g. 30s, 15m, 2h, 1d)")
	listenerName := fs.String("listener", "serve-https-443", "Listener name")
	listenAddr := fs.String("listen", ":443", "Listen address")
	domain := fs.String("domain", "", "TLS Domain name")
	acme := fs.Bool("acme", false, "Enable automatic Let's Encrypt TLS cert")
	certFile := fs.String("cert", "", "Path to PEM certificate")
	keyFile := fs.String("key", "", "Path to PEM private key")
	stripPrefix := fs.String("strip-prefix", "", "Strip path prefix before forwarding")
	noStripPrefix := fs.Bool("no-strip-prefix", false, "Do not automatically strip path prefix when forwarding")
	noRedirect := fs.Bool("no-redirect", false, "Do not automatically create HTTP to HTTPS redirect route on port 80")
	_ = fs.Bool("bg", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("d", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("watch", false, "Stream live logs in foreground and remove route on Ctrl+C (default)")
	_ = fs.Bool("w", false, "Stream live logs in foreground and remove route on Ctrl+C (default)")

	if hasHelpFlag(args) {
		fmt.Println("Usage: gateway serve https <path> <target> [flags]")
		fs.PrintDefaults()
		os.Exit(0)
	}

	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		fmt.Println("Usage: gateway serve https <path> <target> [flags]")
		os.Exit(0)
	}

	mountArg := fs.Arg(0)
	target := fs.Arg(1)

	parsedDomain, path := parseServeMount(mountArg)
	domainVal := *domain
	if domainVal == "" {
		domainVal = parsedDomain
	}

	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	useACME := *acme
	if domainVal != "" && !useACME && *certFile == "" {
		dnsMatch, resolvedIP, serverIP := ValidateDNS(domainVal)
		if dnsMatch {
			fmt.Printf("[INFO] DNS for %s resolves to this server (%s). Enabling ACME Let's Encrypt auto-cert.\n", domainVal, resolvedIP)
			useACME = true
		} else if resolvedIP != "" {
			fmt.Printf("[INFO] DNS for %s points to %s (server IP: %s). Using local TLS until DNS propagates.\n", domainVal, resolvedIP, serverIP)
		}
	}

	var tlsSpec *api.TLSConfigSpec
	if useACME || domainVal != "" || *certFile != "" {
		tlsSpec = &api.TLSConfigSpec{
			Auto: useACME,
		}
		if domainVal != "" {
			tlsSpec.Domains = []string{domainVal}
		}
		if *certFile != "" {
			if data, e := os.ReadFile(*certFile); e == nil {
				tlsSpec.Cert = string(data)
			}
		}
		if *keyFile != "" {
			if data, e := os.ReadFile(*keyFile); e == nil {
				tlsSpec.Key = string(data)
			}
		}
	}

	lName := *listenerName
	if lName == "serve-https-443" && *listenAddr != ":443" {
		lName = fmt.Sprintf("serve-https-%s", strings.TrimPrefix(*listenAddr, ":"))
	}

	actualListener, err := ensureListener(ctx, client, lName, *listenAddr, "tcp", tlsSpec)
	if err != nil {
		log.Fatalf("failed to create HTTPS listener: %v", err)
	}

	routeName := fmt.Sprintf("serve-https-%d", time.Now().UnixNano()%10000)
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

	handlerSpec := api.HandlerSpec{
		Type:   "http_lb",
		Config: map[string]any{"target": target},
	}

	prefixToStrip := *stripPrefix
	if prefixToStrip == "" && !*noStripPrefix && path != "/" && path != "" {
		prefixToStrip = path
	}

	if prefixToStrip != "" {
		inner := handlerSpec
		handlerSpec = api.HandlerSpec{
			Type:   "http_strip_prefix",
			Config: map[string]any{"prefix": prefixToStrip},
			Next:   &inner,
		}
	}

	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "http",
		Listener: actualListener,
		Priority: 1,
		TTL:      int(ttlDuration.Seconds()),
		Rule:     ruleSpec,
		Handler:  handlerSpec,
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		log.Fatalf("failed to create HTTPS route: %v", err)
	}

	displayTarget := path
	if domainVal != "" {
		displayTarget = domainVal + path
	}
	fmt.Printf("Sharing HTTPS %s -> %s (Listener: %s)\n", displayTarget, target, *listenAddr)

	routesToCleanup := []string{routeName}

	if !*noRedirect {
		httpListener, err := ensureListener(ctx, client, "serve-http-80", ":80", "tcp", nil)
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
				TTL:      int(ttlDuration.Seconds()),
				Rule:     rRuleSpec,
				Handler: api.HandlerSpec{
					Type:   "http_redirect",
					Config: map[string]any{"url": redirectTargetURL, "status": 301},
				},
			}

			if err := client.CreateRoute(ctx, redirectRouteSpec); err == nil {
				routesToCleanup = append(routesToCleanup, redirectRouteName)
				fmt.Printf("Redirecting HTTP %s -> %s (Listener: :80)\n", displayTarget, redirectTargetURL)
			}
		}
	}

	if watchMode {
		WatchAndCleanup(client, routesToCleanup...)
	}
}

func runServeTCP(ctx context.Context, client *Client, args []string) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve tcp", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	_ = fs.Bool("bg", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("d", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("watch", false, "Stream live logs and remove route on Ctrl+C (default)")
	_ = fs.Bool("w", false, "Stream live logs and remove route on Ctrl+C (default)")

	if hasHelpFlag(args) {
		fmt.Println("Usage: gateway serve tcp <listen-port> <target> [flags]")
		fs.PrintDefaults()
		os.Exit(0)
	}

	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		fmt.Println("Usage: gateway serve tcp <listen-port> <target> [flags]")
		os.Exit(0)
	}

	listenPort := fs.Arg(0)
	target := fs.Arg(1)

	listenAddr := ":" + listenPort
	if strings.Contains(listenPort, ":") {
		listenAddr = listenPort
	}
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}
	listenerName := fmt.Sprintf("serve-tcp-%s", strings.TrimPrefix(listenAddr, ":"))

	actualListener, err := ensureListener(ctx, client, listenerName, listenAddr, "tcp", nil)
	if err != nil {
		log.Fatalf("failed to create listener: %v", err)
	}

	routeName := fmt.Sprintf("serve-tcp-route-%d", time.Now().UnixNano()%10000)
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "tcp",
		Listener: actualListener,
		Priority: 1,
		TTL:      int(ttlDuration.Seconds()),
		Rule:     api.RuleSpec{Type: "any"},
		Handler: api.HandlerSpec{
			Type:   "tcp_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		log.Fatalf("failed to create TCP route: %v", err)
	}

	fmt.Printf("Sharing TCP %s -> %s\n", listenAddr, target)

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func runServeUDP(ctx context.Context, client *Client, args []string) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve udp", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	_ = fs.Bool("bg", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("d", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("watch", false, "Stream live logs and remove route on Ctrl+C (default)")
	_ = fs.Bool("w", false, "Stream live logs and remove route on Ctrl+C (default)")

	if hasHelpFlag(args) {
		fmt.Println("Usage: gateway serve udp <listen-port> <target> [flags]")
		fs.PrintDefaults()
		os.Exit(0)
	}

	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		fmt.Println("Usage: gateway serve udp <listen-port> <target> [flags]")
		os.Exit(0)
	}

	listenPort := fs.Arg(0)
	target := fs.Arg(1)

	listenAddr := ":" + listenPort
	if strings.Contains(listenPort, ":") {
		listenAddr = listenPort
	}
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}
	listenerName := fmt.Sprintf("serve-udp-%s", strings.TrimPrefix(listenAddr, ":"))

	actualListener, err := ensureListener(ctx, client, listenerName, listenAddr, "udp", nil)
	if err != nil {
		log.Fatalf("failed to create UDP listener: %v", err)
	}

	routeName := fmt.Sprintf("serve-udp-route-%d", time.Now().UnixNano()%10000)
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "udp",
		Listener: actualListener,
		Priority: 1,
		TTL:      int(ttlDuration.Seconds()),
		Rule:     api.RuleSpec{Type: "any"},
		Handler: api.HandlerSpec{
			Type:   "udp_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		log.Fatalf("failed to create UDP route: %v", err)
	}

	fmt.Printf("Sharing UDP %s -> %s\n", listenAddr, target)

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func isNumericPort(s string) bool {
	s = strings.TrimPrefix(s, ":")
	_, err := strconv.Atoi(s)
	return err == nil
}

func runServeMinecraft(ctx context.Context, client *Client, args []string) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve minecraft", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	mcHost := fs.String("host", "", "Minecraft virtual host domain (e.g. mc.example.com)")
	players := fs.String("player", "", "Whitelisted Minecraft player usernames (comma-separated)")
	denyPlayers := fs.String("deny-player", "", "Blacklisted Minecraft player usernames (comma-separated)")
	_ = fs.Bool("bg", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("d", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("watch", false, "Stream live logs and remove route on Ctrl+C (default)")
	_ = fs.Bool("w", false, "Stream live logs and remove route on Ctrl+C (default)")

	if hasHelpFlag(args) {
		fmt.Println("Usage: gateway serve minecraft <host-or-port> [target] [flags]")
		fs.PrintDefaults()
		os.Exit(0)
	}

	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Println("Usage: gateway serve minecraft <host-or-port> [target] [flags]")
		os.Exit(0)
	}

	arg0 := fs.Arg(0)
	arg1 := ""
	if fs.NArg() >= 2 {
		arg1 = fs.Arg(1)
	}

	parsedDomain, _ := parseServeMount(arg0)
	listenAddr := ":25565"
	target := "127.0.0.1:25565"
	hostVal := *mcHost

	if parsedDomain != "" || strings.Contains(arg0, ".") || (len(arg0) > 0 && !isNumericPort(arg0) && !strings.HasPrefix(arg0, ":")) {
		// Domain positional arg (e.g. abc.localhost or mc.example.com)
		if hostVal == "" {
			hostVal = parsedDomain
			if hostVal == "" {
				hostVal = arg0
			}
		}
		if arg1 != "" {
			target = arg1
		}
	} else {
		// Port positional arg (e.g. 25565 or :25565)
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

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}
	listenerName := fmt.Sprintf("serve-mc-%s", strings.TrimPrefix(listenAddr, ":"))

	actualListener, err := ensureListener(ctx, client, listenerName, listenAddr, "tcp", nil)
	if err != nil {
		log.Fatalf("failed to create Minecraft listener: %v", err)
	}

	var rules []api.RuleSpec
	rules = append(rules, api.RuleSpec{Type: "is_minecraft"})

	if hostVal != "" {
		rules = append(rules, api.RuleSpec{Type: "minecraft_host", Value: hostVal})
	}
	if *players != "" {
		playerList := strings.Split(*players, ",")
		rules = append(rules, api.RuleSpec{Type: "minecraft_player", Values: playerList})
	}
	if *denyPlayers != "" {
		denyList := strings.Split(*denyPlayers, ",")
		rules = append(rules, api.RuleSpec{Type: "minecraft_not_player", Values: denyList})
	}

	ruleSpec := api.RuleSpec{Type: "any"}
	if len(rules) == 1 {
		ruleSpec = rules[0]
	} else if len(rules) > 1 {
		ruleSpec = api.RuleSpec{Type: "and", Rules: rules}
	}

	routeName := fmt.Sprintf("serve-mc-route-%d", time.Now().UnixNano()%10000)
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "tcp",
		Listener: actualListener,
		Priority: 1,
		TTL:      int(ttlDuration.Seconds()),
		Rule:     ruleSpec,
		Handler: api.HandlerSpec{
			Type:   "tcp_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		log.Fatalf("failed to create Minecraft route: %v", err)
	}

	displayHost := hostVal
	if displayHost == "" {
		displayHost = listenAddr
	}
	fmt.Printf("Sharing Minecraft %s -> %s (Listener: %s)\n", displayHost, target, listenAddr)

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func runServeStatus(ctx context.Context, client *Client) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		log.Fatalf("failed to retrieve serve status: %v", err)
	}

	var serveRoutes []api.RouteSpec
	for _, r := range routes {
		if strings.HasPrefix(r.Name, "serve-") {
			serveRoutes = append(serveRoutes, r)
		}
	}

	fmt.Printf("ACTIVE SERVE MOUNTS (%d)\n", len(serveRoutes))
	if len(serveRoutes) == 0 {
		fmt.Println("No active serve mounts.")
		return
	}

	fmt.Printf("%-22s %-12s %-8s %-25s %-20s %-12s\n", "NAME", "LISTENER", "PROTO", "MATCH", "TARGET", "EXPIRES IN")
	fmt.Println("---------------------------------------------------------------------------------------------------")
	for _, r := range serveRoutes {
		fmt.Printf("%-22s %-12s %-8s %-25s %-20s %-12s\n",
			r.Name, r.Listener, r.Protocol, FormatRuleSummary(r.Rule), FormatTargetsSummary(r.Handler), FormatTTLRemaining(time.Now(), r.TTL))
	}
}

func runServeOff(ctx context.Context, client *Client, nameOrPort string) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		log.Fatalf("failed to retrieve routes: %v", err)
	}

	deletedCount := 0
	for _, r := range routes {
		if r.Name == nameOrPort || strings.Contains(r.Name, nameOrPort) || strings.HasSuffix(r.Listener, "-"+nameOrPort) {
			if err := client.DeleteRoute(ctx, r.Name); err == nil {
				fmt.Printf("Removed serve mount %q\n", r.Name)
				deletedCount++
			}
		}
	}

	if deletedCount == 0 {
		// Try direct delete by name
		if err := client.DeleteRoute(ctx, nameOrPort); err == nil {
			fmt.Printf("Removed serve mount %q\n", nameOrPort)
			deletedCount++
		} else {
			fmt.Printf("No active serve mount found matching %q\n", nameOrPort)
		}
	}

	if deletedCount > 0 {
		cleanupUnusedServeListeners(ctx, client)
	}
}

func runServeReset(ctx context.Context, client *Client) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		log.Fatalf("failed to retrieve routes: %v", err)
	}

	deletedCount := 0
	for _, r := range routes {
		if strings.HasPrefix(r.Name, "serve-") {
			if err := client.DeleteRoute(ctx, r.Name); err == nil {
				deletedCount++
			}
		}
	}
	cleanupUnusedServeListeners(ctx, client)
	fmt.Printf("Reset complete. Removed %d serve mounts.\n", deletedCount)
}

func runServeDir(ctx context.Context, client *Client, args []string, defaultSPA bool) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve dir", flag.ExitOnError)
	spa := fs.Bool("spa", defaultSPA, "Enable SPA (Single Page App) routing fallback to index.html")
	index := fs.String("index", "index.html", "Default index file name")
	browse := fs.Bool("browse", false, "Enable directory browsing")
	httpFlag := fs.Bool("http", false, "Serve static directory over unencrypted HTTP instead of HTTPS")
	_ = fs.Bool("https", true, "Serve static directory over HTTPS (default)")
	ttlStr := fs.String("ttl", "", "Time to live duration")
	listenerName := fs.String("listener", "", "Listener name")
	listenAddr := fs.String("listen", "", "Listen address")
	domain := fs.String("domain", "", "TLS Domain name")
	acme := fs.Bool("acme", false, "Enable automatic Let's Encrypt TLS cert")
	certFile := fs.String("cert", "", "Path to PEM certificate")
	keyFile := fs.String("key", "", "Path to PEM private key")
	stripPrefix := fs.String("strip-prefix", "", "Strip path prefix before serving files")
	noStripPrefix := fs.Bool("no-strip-prefix", false, "Do not automatically strip path prefix when serving files")
	noRedirect := fs.Bool("no-redirect", false, "Do not automatically create HTTP to HTTPS redirect route on port 80")
	_ = fs.Bool("bg", false, "Run in background mode")
	_ = fs.Bool("d", false, "Run in background mode")
	_ = fs.Bool("watch", false, "Stream live logs in foreground and remove route on Ctrl+C (default)")
	_ = fs.Bool("w", false, "Stream live logs in foreground and remove route on Ctrl+C (default)")

	if hasHelpFlag(args) {
		fmt.Println("Usage: gateway serve dir <domain/path> <local-dir> [flags]")
		fs.PrintDefaults()
		os.Exit(0)
	}

	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Println("Usage: gateway serve dir <domain/path> <local-dir> [flags]")
		os.Exit(0)
	}

	mountArg := fs.Arg(0)
	dirPath := "."
	if fs.NArg() >= 2 {
		dirPath = fs.Arg(1)
	}

	isHTTPS := true
	if *httpFlag {
		isHTTPS = false
	}

	parsedDomain, path := parseServeMount(mountArg)
	domainVal := *domain
	if domainVal == "" {
		domainVal = parsedDomain
	}

	absDir, err := filepath.Abs(dirPath)
	if err != nil {
		log.Fatalf("invalid directory path %q: %v", dirPath, err)
	}

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	isFile := false
	if fi, err := os.Stat(absDir); err == nil && !fi.IsDir() {
		isFile = true
	}

	handlerSpec := api.HandlerSpec{
		Type: "http_static",
		Config: map[string]any{
			"dir":    absDir,
			"spa":    *spa,
			"index":  *index,
			"browse": *browse,
		},
	}

	prefixToStrip := *stripPrefix
	if prefixToStrip == "" && !*noStripPrefix && path != "/" && path != "" && !isFile {
		prefixToStrip = path
	}

	if prefixToStrip != "" {
		inner := handlerSpec
		handlerSpec = api.HandlerSpec{
			Type:   "http_strip_prefix",
			Config: map[string]any{"prefix": prefixToStrip},
			Next:   &inner,
		}
	}

	if isHTTPS {
		// Serve static directory/file over HTTPS
		lAddr := *listenAddr
		if lAddr == "" {
			lAddr = ":443"
		}
		lName := *listenerName
		if lName == "" {
			lName = fmt.Sprintf("serve-https-%s", strings.TrimPrefix(lAddr, ":"))
		}

		useACME := *acme
		if domainVal != "" && !useACME && *certFile == "" {
			dnsMatch, resolvedIP, serverIP := ValidateDNS(domainVal)
			if dnsMatch {
				fmt.Printf("[INFO] DNS for %s resolves to this server (%s). Enabling ACME Let's Encrypt auto-cert.\n", domainVal, resolvedIP)
				useACME = true
			} else if resolvedIP != "" {
				fmt.Printf("[INFO] DNS for %s points to %s (server IP: %s). Using local TLS until DNS propagates.\n", domainVal, resolvedIP, serverIP)
			}
		}

		var tlsSpec *api.TLSConfigSpec
		if useACME || domainVal != "" || *certFile != "" {
			tlsSpec = &api.TLSConfigSpec{Auto: useACME}
			if domainVal != "" {
				tlsSpec.Domains = []string{domainVal}
			}
			if *certFile != "" {
				if data, e := os.ReadFile(*certFile); e == nil {
					tlsSpec.Cert = string(data)
				}
			}
			if *keyFile != "" {
				if data, e := os.ReadFile(*keyFile); e == nil {
					tlsSpec.Key = string(data)
				}
			}
		}

		actualListener, err := ensureListener(ctx, client, lName, lAddr, "tcp", tlsSpec)
		if err != nil {
			log.Fatalf("failed to create HTTPS listener: %v", err)
		}

		routeName := fmt.Sprintf("serve-dir-https-%d", time.Now().UnixNano()%10000)
		var rules []api.RuleSpec
		rules = append(rules, api.RuleSpec{Type: "secure"})
		if domainVal != "" {
			rules = append(rules, api.RuleSpec{Type: "host", Value: domainVal})
		}
		if path != "/" && path != "" {
			if isFile {
				rules = append(rules, api.RuleSpec{Type: "path", Value: path})
			} else {
				rules = append(rules, api.RuleSpec{Type: "path_prefix", Value: path})
			}
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
			TTL:      int(ttlDuration.Seconds()),
			Rule:     ruleSpec,
			Handler:  handlerSpec,
		}

		if err := client.CreateRoute(ctx, routeSpec); err != nil {
			log.Fatalf("failed to create HTTPS static route: %v", err)
		}

		displayTarget := path
		if domainVal != "" {
			displayTarget = domainVal + path
		}
		modeStr := "Static"
		if isFile {
			modeStr = "File"
		} else if *spa {
			modeStr = "SPA"
		}
		fmt.Printf("Sharing %s HTTPS %s -> %s (Listener: %s)\n", modeStr, displayTarget, absDir, lAddr)

		routesToCleanup := []string{routeName}

		if !*noRedirect {
			httpListener, err := ensureListener(ctx, client, "serve-http-80", ":80", "tcp", nil)
			if err == nil {
				redirectRouteName := fmt.Sprintf("serve-redirect-%s", routeName)
				var rRules []api.RuleSpec
				rRules = append(rRules, api.RuleSpec{Type: "not", Rule: &api.RuleSpec{Type: "secure"}})
				if domainVal != "" {
					rRules = append(rRules, api.RuleSpec{Type: "host", Value: domainVal})
				}
				if path != "/" && path != "" {
					if isFile {
						rRules = append(rRules, api.RuleSpec{Type: "path", Value: path})
					} else {
						rRules = append(rRules, api.RuleSpec{Type: "path_prefix", Value: path})
					}
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
					TTL:      int(ttlDuration.Seconds()),
					Rule:     rRuleSpec,
					Handler: api.HandlerSpec{
						Type:   "http_redirect",
						Config: map[string]any{"url": redirectTargetURL, "status": 301},
					},
				}
				if err := client.CreateRoute(ctx, redirectRouteSpec); err == nil {
					routesToCleanup = append(routesToCleanup, redirectRouteName)
					fmt.Printf("Redirecting HTTP %s -> %s (Listener: :80)\n", displayTarget, redirectTargetURL)
				}
			}
		}

		if watchMode {
			WatchAndCleanup(client, routesToCleanup...)
		}
	} else {
		// Serve static directory/file over plain HTTP
		lAddr := *listenAddr
		if lAddr == "" {
			lAddr = ":80"
		}
		lName := *listenerName
		if lName == "" {
			lName = fmt.Sprintf("serve-http-%s", strings.TrimPrefix(lAddr, ":"))
		}

		actualListener, err := ensureListener(ctx, client, lName, lAddr, "tcp", nil)
		if err != nil {
			log.Fatalf("failed to create HTTP listener: %v", err)
		}

		routeName := fmt.Sprintf("serve-dir-http-%d", time.Now().UnixNano()%10000)
		var rules []api.RuleSpec
		rules = append(rules, api.RuleSpec{Type: "not", Rule: &api.RuleSpec{Type: "secure"}})
		if domainVal != "" {
			rules = append(rules, api.RuleSpec{Type: "host", Value: domainVal})
		}
		if path != "/" && path != "" {
			if isFile {
				rules = append(rules, api.RuleSpec{Type: "path", Value: path})
			} else {
				rules = append(rules, api.RuleSpec{Type: "path_prefix", Value: path})
			}
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
			TTL:      int(ttlDuration.Seconds()),
			Rule:     ruleSpec,
			Handler:  handlerSpec,
		}

		if err := client.CreateRoute(ctx, routeSpec); err != nil {
			log.Fatalf("failed to create HTTP static route: %v", err)
		}

		displayTarget := path
		if domainVal != "" {
			displayTarget = domainVal + path
		}
		modeStr := "Static"
		if isFile {
			modeStr = "File"
		} else if *spa {
			modeStr = "SPA"
		}
		fmt.Printf("Sharing %s HTTP %s -> %s (Listener: %s)\n", modeStr, displayTarget, absDir, lAddr)

		if watchMode {
			WatchAndCleanup(client, routeName)
		}
	}
}
