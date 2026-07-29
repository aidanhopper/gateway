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

func extractRuleDomainAndPath(rule api.RuleSpec) (domain string, path string) {
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

func extractHandlerTarget(h api.HandlerSpec) string {
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
		return extractHandlerTarget(*h.Next)
	}
	return ""
}

func hasMatchingServeRoute(ctx context.Context, client *Client, listenerName, domain, path, target string) bool {
	routes, err := client.ListRoutes(ctx)
	if err != nil || len(routes) == 0 {
		return false
	}

	for _, r := range routes {
		if r.Listener != listenerName {
			continue
		}
		ruleDomain, rulePath := extractRuleDomainAndPath(r.Rule)
		if strings.EqualFold(ruleDomain, domain) && rulePath == path {
			if target != "" {
				handlerTarget := extractHandlerTarget(r.Handler)
				if strings.EqualFold(strings.TrimRight(handlerTarget, "/"), strings.TrimRight(target, "/")) {
					return true
				}
			} else {
				return true
			}
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
	fmt.Println("Usage: gateway serve <protocol|subcommand> [args] [flags]")
	fmt.Println("\nProtocols:")
	fmt.Println("  dir (static) <domain/path> <folder|file>   Expose local folder/file")
	fmt.Println("  file <domain/path> <file>                  Expose single static file")
	fmt.Println("  spa <domain/path> <folder>                 Expose Single Page App with index.html fallback")
	fmt.Println("  redirect (redir) <domain/path> <target-url> Redirect HTTP/HTTPS traffic to external URL")
	fmt.Println("  http <path> <target>                       Expose local HTTP service (e.g. gateway serve http / 3000)")
	fmt.Println("  https <path> <target>                      Expose local service over HTTPS (e.g. gateway serve https / 3000 --acme)")
	fmt.Println("  tcp <port> <target>                        Expose TCP stream (e.g. gateway serve tcp 2222 127.0.0.1:22)")
	fmt.Println("  udp <port> <target>                        Expose UDP stream (e.g. gateway serve udp 5353 127.0.0.1:53)")
	fmt.Println("  minecraft (mc) <port> <target>             Expose Minecraft server")
	fmt.Println("\nCommon Flags:")
	fmt.Println("  --bg, -d                                   Run in background mode")
	fmt.Println("  --ttl <duration>                           Auto-expire duration (e.g. 30s, 15m, 2h, 1d)")
	fmt.Println("  --1h, --30m, --1d                          Duration flag aliases")
	fmt.Println("  --yes, -y                                  Bypass public site exposure confirmation")
	fmt.Println("\nManagement:")
	fmt.Println("  status                                     List active serve mounts and TTL countdowns")
	fmt.Println("  logs [route_name]                          Stream live logs for background routes")
	fmt.Println("  off [name_or_port]                         Remove active serve mount (interactive if no arg)")
	fmt.Println("  reset                                      Clear all serve mounts")
}

func extractDurationFlags(args []string) ([]string, string) {
	durations := map[string]string{
		"-15m": "15m", "--15m": "15m",
		"-30m": "30m", "--30m": "30m",
		"-1h": "1h", "--1h": "1h",
		"-2h": "2h", "--2h": "2h",
		"-6h": "6h", "--6h": "6h",
		"-12h": "12h", "--12h": "12h",
		"-1d": "1d", "--1d": "1d",
		"-7d": "7d", "--7d": "7d",
	}
	var out []string
	var found string
	for _, a := range args {
		if d, ok := durations[a]; ok {
			found = d
		} else {
			out = append(out, a)
		}
	}
	return out, found
}

func checkBackendDial(target string) {
	dialTarget := target
	if !strings.Contains(dialTarget, ":") {
		dialTarget = "127.0.0.1:" + dialTarget
	}
	conn, err := net.DialTimeout("tcp", dialTarget, 500*time.Millisecond)
	if err != nil {
		fmt.Printf("[WARNING] Nothing appears to be listening on %s (connection refused).\n", dialTarget)
		fmt.Println("[INFO] Proxy route created anyway. Make sure your local application is started.")
	} else {
		conn.Close()
	}
}

func getOutboundIP() string {
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

// RunServe handles 'gateway serve' subcommands.
func RunServe(args []string) {
	if len(args) < 1 {
		PrintServeUsage()
		os.Exit(0)
	}

	siteName, args := extractSiteFlag(args)
	args, yesMode := extractBoolFlag(args, "y", "yes")
	var durationPreset string
	args, durationPreset = extractDurationFlags(args)

	subcmd := args[0]
	if subcmd == "--help" || subcmd == "-h" || subcmd == "help" {
		PrintServeUsage()
		os.Exit(0)
	}

	client := NewClient(siteName)
	ctx := context.Background()

	if subcmd == "off" {
		targetArg := ""
		if len(args) >= 2 {
			targetArg = args[1]
		}
		runServeOff(ctx, client, targetArg)
		return
	}

	if subcmd == "logs" || subcmd == "log" {
		targetRoute := ""
		if len(args) >= 2 {
			targetRoute = args[1]
		}
		logArgs := []string{}
		if targetRoute != "" {
			logArgs = append(logArgs, targetRoute)
		}
		if siteName != "" {
			logArgs = append(logArgs, "--site", siteName)
		}
		RunLogs(logArgs)
		return
	}

	switch subcmd {
	case "dir", "static", "spa", "file":
		runArgs := args[1:]
		if durationPreset != "" {
			runArgs = append(runArgs, "--ttl", durationPreset)
		}
		runServeDir(ctx, client, runArgs, subcmd == "spa", yesMode)
	case "redirect", "redir":
		runArgs := args[1:]
		if durationPreset != "" {
			runArgs = append(runArgs, "--ttl", durationPreset)
		}
		runServeRedirect(ctx, client, runArgs, yesMode)
	case "http":
		runArgs := args[1:]
		if durationPreset != "" {
			runArgs = append(runArgs, "--ttl", durationPreset)
		}
		runServeHTTP(ctx, client, runArgs, yesMode)
	case "https":
		runArgs := args[1:]
		if durationPreset != "" {
			runArgs = append(runArgs, "--ttl", durationPreset)
		}
		runServeHTTPS(ctx, client, runArgs, yesMode)
	case "tcp":
		runArgs := args[1:]
		if durationPreset != "" {
			runArgs = append(runArgs, "--ttl", durationPreset)
		}
		runServeTCP(ctx, client, runArgs, yesMode)
	case "udp":
		runArgs := args[1:]
		if durationPreset != "" {
			runArgs = append(runArgs, "--ttl", durationPreset)
		}
		runServeUDP(ctx, client, runArgs, yesMode)
	case "minecraft", "mc":
		runArgs := args[1:]
		if durationPreset != "" {
			runArgs = append(runArgs, "--ttl", durationPreset)
		}
		runServeMinecraft(ctx, client, runArgs, yesMode)
	case "status":
		runServeStatus(ctx, client)
	case "reset":
		runServeReset(ctx, client, yesMode)
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] Unknown serve protocol or subcommand %q\n\n", subcmd)
		PrintServeUsage()
		os.Exit(2)
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
						_ = client.CreateListener(ctx, spec)
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

func runServeHTTP(ctx context.Context, client *Client, args []string, yesMode bool) {
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

	if !ConfirmPublicSiteExposure(client, yesMode, fmt.Sprintf("HTTP %s -> %s", mountArg, target)) {
		return
	}

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

	displayTarget := path
	if domain != "" {
		displayTarget = domain + path
	}

	if hasMatchingServeRoute(ctx, client, actualListener, domain, path, target) {
		fmt.Printf("[INFO] Serving HTTP %s -> %s (already active)\n", displayTarget, target)
		return
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		log.Fatalf("failed to create route: %v", err)
	}

	checkBackendDial(target)

	fmt.Printf("[INFO] Serving HTTP %s -> %s (Listener: %s, Mount: %s)\n", displayTarget, target, *listenAddr, routeName)
	if ttlDuration > 0 {
		fmt.Printf("[INFO] TTL: %v (auto-expires)\n", ttlDuration)
	}

	listenPort := strings.TrimPrefix(*listenAddr, ":")
	portSuffix := ""
	if listenPort != "80" {
		portSuffix = ":" + listenPort
	}
	fmt.Printf("[INFO] Local URL:   http://localhost%s%s\n", portSuffix, path)
	if localIP := getOutboundIP(); localIP != "" {
		fmt.Printf("[INFO] Network URL: http://%s%s%s\n", localIP, portSuffix, path)
	}

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func runServeHTTPS(ctx context.Context, client *Client, args []string, yesMode bool) {
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

	if !ConfirmPublicSiteExposure(client, yesMode, fmt.Sprintf("HTTPS %s -> %s", mountArg, target)) {
		return
	}

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

	displayTarget := path
	if domainVal != "" {
		displayTarget = domainVal + path
	}

	if hasMatchingServeRoute(ctx, client, actualListener, domainVal, path, target) {
		fmt.Printf("[INFO] Serving HTTPS %s -> %s (already active)\n", displayTarget, target)
		return
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		log.Fatalf("failed to create HTTPS route: %v", err)
	}

	checkBackendDial(target)

	fmt.Printf("[INFO] Serving HTTPS %s -> %s (Listener: %s, Mount: %s)\n", displayTarget, target, *listenAddr, routeName)
	if ttlDuration > 0 {
		fmt.Printf("[INFO] TTL: %v (auto-expires)\n", ttlDuration)
	}
	if domainVal != "" {
		fmt.Printf("[INFO] Public URL:  https://%s%s\n", domainVal, path)
	}

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

func runServeTCP(ctx context.Context, client *Client, args []string, yesMode bool) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve tcp", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	_ = fs.Bool("bg", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("d", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")

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

	if !ConfirmPublicSiteExposure(client, yesMode, fmt.Sprintf("TCP %s -> %s", listenPort, target)) {
		return
	}

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

	fmt.Printf("Sharing TCP %s -> %s (Listener: %s, Mount: %s)\n", listenAddr, target, listenAddr, routeName)

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func runServeUDP(ctx context.Context, client *Client, args []string, yesMode bool) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve udp", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	_ = fs.Bool("bg", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("d", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")

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

	if !ConfirmPublicSiteExposure(client, yesMode, fmt.Sprintf("UDP %s -> %s", listenPort, target)) {
		return
	}

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

	fmt.Printf("Sharing UDP %s -> %s (Listener: %s, Mount: %s)\n", listenAddr, target, listenAddr, routeName)

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func isNumericPort(s string) bool {
	s = strings.TrimPrefix(s, ":")
	_, err := strconv.Atoi(s)
	return err == nil
}

func runServeMinecraft(ctx context.Context, client *Client, args []string, yesMode bool) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve minecraft", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	mcHost := fs.String("host", "", "Minecraft virtual host domain (e.g. mc.example.com)")
	players := fs.String("player", "", "Whitelisted Minecraft player usernames (comma-separated)")
	denyPlayers := fs.String("deny-player", "", "Blacklisted Minecraft player usernames (comma-separated)")
	_ = fs.Bool("bg", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("d", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")

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

	if !ConfirmPublicSiteExposure(client, yesMode, fmt.Sprintf("Minecraft service %s", arg0)) {
		return
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
	fmt.Printf("Sharing Minecraft %s -> %s (Listener: %s, Mount: %s)\n", displayHost, target, listenAddr, routeName)

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func runServeStatus(ctx context.Context, client *Client) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to retrieve serve status: %v\n", err)
		os.Exit(1)
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

	tbl := NewTable("NAME", "LISTENER", "PROTO", "MATCH", "TARGET", "EXPIRES IN")
	for _, r := range serveRoutes {
		tbl.AddRow(r.Name, r.Listener, r.Protocol, FormatRuleSummary(r.Rule), FormatTargetsSummary(r.Handler), FormatTTLRemaining(time.Now(), r.TTL))
	}
	fmt.Print(tbl.String())
}

func runServeOff(ctx context.Context, client *Client, nameOrPort string) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		log.Fatalf("failed to retrieve routes: %v", err)
	}

	if nameOrPort == "" {
		var serveRoutes []api.RouteSpec
		for _, r := range routes {
			if strings.HasPrefix(r.Name, "serve-") {
				serveRoutes = append(serveRoutes, r)
			}
		}
		if len(serveRoutes) == 0 {
			fmt.Println("[INFO] No active serve mounts found.")
			return
		}
		fmt.Println("\nSelect an active serve mount to turn off:")
		for i, r := range serveRoutes {
			fmt.Printf("  %d) %-22s (%s -> %s)\n", i+1, r.Name, r.Protocol, FormatTargetsSummary(r.Handler))
		}
		input := PromptInput("\nEnter number (or 0 to cancel): ")
		var choice int
		if _, err := fmt.Sscanf(input, "%d", &choice); err == nil && choice > 0 && choice <= len(serveRoutes) {
			nameOrPort = serveRoutes[choice-1].Name
		} else {
			fmt.Println("[INFO] Operation cancelled.")
			return
		}
	}

	deletedCount := 0
	for _, r := range routes {
		if r.Name == nameOrPort || strings.Contains(r.Name, nameOrPort) || strings.HasSuffix(r.Listener, "-"+nameOrPort) {
			if err := client.DeleteRoute(ctx, r.Name); err == nil {
				fmt.Printf("[SUCCESS] Removed serve mount %q\n", r.Name)
				deletedCount++
			}
		}
	}

	if deletedCount == 0 {
		// Try direct delete by name
		if err := client.DeleteRoute(ctx, nameOrPort); err == nil {
			fmt.Printf("[SUCCESS] Removed serve mount %q\n", nameOrPort)
			deletedCount++
		} else {
			fmt.Printf("[INFO] No active serve mount found matching %q\n", nameOrPort)
		}
	}

	if deletedCount > 0 {
		cleanupUnusedServeListeners(ctx, client)
	}
}

func runServeReset(ctx context.Context, client *Client, yesMode bool) {
	routes, err := client.ListRoutes(ctx)
	if err != nil {
		log.Fatalf("failed to retrieve routes: %v", err)
	}

	var serveRoutes []string
	for _, r := range routes {
		if strings.HasPrefix(r.Name, "serve-") {
			serveRoutes = append(serveRoutes, r.Name)
		}
	}

	if len(serveRoutes) == 0 {
		fmt.Println("No active serve mounts to remove.")
		return
	}

	if !yesMode {
		fmt.Printf("This will remove %d serve mount(s). Continue? [y/N]: ", len(serveRoutes))
		input := strings.ToLower(PromptInput(""))
		if input != "y" && input != "yes" {
			fmt.Println("[INFO] Operation cancelled.")
			return
		}
	}

	deletedCount := 0
	for _, name := range serveRoutes {
		if err := client.DeleteRoute(ctx, name); err == nil {
			deletedCount++
		}
	}
	cleanupUnusedServeListeners(ctx, client)
	fmt.Printf("Reset complete. Removed %d serve mount(s).\n", deletedCount)
}

func runServeDir(ctx context.Context, client *Client, args []string, defaultSPA bool, yesMode bool) {
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

	if !ConfirmPublicSiteExposure(client, yesMode, fmt.Sprintf("Static Directory %s -> %s", mountArg, dirPath)) {
		return
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
		fmt.Printf("Sharing %s HTTPS %s -> %s (Listener: %s, Mount: %s)\n", modeStr, displayTarget, absDir, lAddr, routeName)

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
		fmt.Printf("Sharing %s HTTP %s -> %s (Listener: %s, Mount: %s)\n", modeStr, displayTarget, absDir, lAddr, routeName)

		if watchMode {
			WatchAndCleanup(client, routeName)
		}
	}
}

func runServeRedirect(ctx context.Context, client *Client, args []string, yesMode bool) {
	var watchMode bool
	args, watchMode = extractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve redirect", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	statusCode := fs.Int("code", 301, "HTTP status code for redirect (301 or 302)")
	_ = fs.Bool("bg", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")
	_ = fs.Bool("d", false, "Run in background and keep route active after CLI exits (default is foreground watch mode)")

	if hasHelpFlag(args) {
		fmt.Println("Usage: gateway serve redirect <domain/path> <target-url> [flags]")
		fs.PrintDefaults()
		os.Exit(0)
	}

	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		fmt.Println("Usage: gateway serve redirect <domain/path> <target-url> [flags]")
		os.Exit(2)
	}

	mountArg := fs.Arg(0)
	targetURL := fs.Arg(1)

	if !ConfirmPublicSiteExposure(client, yesMode, fmt.Sprintf("Redirect %s -> %s", mountArg, targetURL)) {
		return
	}

	domain, path := parseServeMount(mountArg)
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	status := *statusCode
	if status != 301 && status != 302 {
		status = 301
	}

	displaySource := path
	if domain != "" {
		displaySource = domain + path
	}

	var routesToCleanup []string

	// 1. HTTPS listener & route (port 443)
	tlsSpec := &api.TLSConfigSpec{
		Auto: true,
	}
	if domain != "" {
		tlsSpec.Domains = []string{domain}
	}

	httpsListener, err := ensureListener(ctx, client, "serve-https-443", ":443", "tcp", tlsSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTPS listener on :443: %v\n", err)
	} else {
		if hasMatchingServeRoute(ctx, client, httpsListener, domain, path, targetURL) {
			fmt.Printf("[INFO] Redirecting HTTPS https://%s -> %s (Code: %d, already active)\n", displaySource, targetURL, status)
		} else {
			httpsRouteName := fmt.Sprintf("serve-redirect-https-%d", time.Now().UnixNano()%10000)
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
				TTL:      int(ttlDuration.Seconds()),
				Rule:     ruleSpec,
				Handler: api.HandlerSpec{
					Type:   "http_redirect",
					Config: map[string]any{"url": targetURL, "status": float64(status)},
				},
			}

			if err := client.CreateRoute(ctx, httpsRoute); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTPS redirect route: %v\n", err)
			} else {
				routesToCleanup = append(routesToCleanup, httpsRouteName)
				fmt.Printf("[INFO] Redirecting HTTPS https://%s -> %s (Code: %d, Mount: %s)\n", displaySource, targetURL, status, httpsRouteName)
			}
		}
	}

	// 2. HTTP listener & route (port 80)
	httpListener, err := ensureListener(ctx, client, "serve-http-80", ":80", "tcp", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTP listener on :80: %v\n", err)
	} else {
		if hasMatchingServeRoute(ctx, client, httpListener, domain, path, targetURL) {
			fmt.Printf("[INFO] Redirecting HTTP  http://%s -> %s (Code: %d, already active)\n", displaySource, targetURL, status)
		} else {
			httpRouteName := fmt.Sprintf("serve-redirect-http-%d", time.Now().UnixNano()%10000)
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
				TTL:      int(ttlDuration.Seconds()),
				Rule:     ruleSpec,
				Handler: api.HandlerSpec{
					Type:   "http_redirect",
					Config: map[string]any{"url": targetURL, "status": float64(status)},
				},
			}

			if err := client.CreateRoute(ctx, httpRoute); err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Could not create HTTP redirect route: %v\n", err)
			} else {
				routesToCleanup = append(routesToCleanup, httpRouteName)
				fmt.Printf("[INFO] Redirecting HTTP  http://%s -> %s (Code: %d, Mount: %s)\n", displaySource, targetURL, status, httpRouteName)
			}
		}
	}

	if ttlDuration > 0 {
		fmt.Printf("[INFO] TTL: %v (auto-expires)\n", ttlDuration)
	}

	if watchMode && len(routesToCleanup) > 0 {
		WatchAndCleanup(client, routesToCleanup...)
	}
}
