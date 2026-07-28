package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
	"github.com/aidanhopper/gateway/internal/gateway"
)

// WatchAndCleanup blocks, streams logs for the given route, and deletes the route on Ctrl+C (SIGINT/SIGTERM).
func WatchAndCleanup(client *Client, routeName string) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Println("\nLogs streaming... Press Ctrl+C to stop sharing.")
	fmt.Println("-----------------------------------------------------------------------------------------")

	go func() {
		err := client.StreamLogs(ctx, routeName, func(event gateway.LogEvent) {
			timeStr := event.Timestamp.Format("15:04:05")
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

	if err := client.DeleteRoute(cleanupCtx, routeName); err != nil {
		log.Printf("failed to delete route %s on exit: %v\n", routeName, err)
	} else {
		fmt.Printf("Sharing stopped. Route %q deleted.\n", routeName)
	}
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

// hasHelpFlag checks whether -h or --help appears anywhere in args, including after positional args.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "-help" {
			return true
		}
	}
	return false
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
	fmt.Println("  http <path> <target>       Expose local HTTP service (e.g. gateway serve http / 3000)")
	fmt.Println("  https <path> <target>      Expose local service over HTTPS (e.g. gateway serve https / 3000 --acme)")
	fmt.Println("  tcp <port> <target>        Expose TCP stream (e.g. gateway serve tcp 2222 127.0.0.1:22)")
	fmt.Println("  udp <port> <target>        Expose UDP stream (e.g. gateway serve udp 5353 127.0.0.1:53)")
	fmt.Println("  minecraft <port> <target>  Expose Minecraft server with player/host filters")
	fmt.Println("\nCommon Flags:")
	fmt.Println("  --watch, -w                Stream live logs; delete route on Ctrl+C")
	fmt.Println("  --ttl <duration>           Auto-expire the route (e.g. 30s, 15m, 2h, 1d)")
	fmt.Println("\nManagement:")
	fmt.Println("  status                     List active serve mounts and TTL countdowns")
	fmt.Println("  off <name_or_port>         Remove an active serve mount")
	fmt.Println("  reset                      Clear all serve mounts")
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

func ensureListener(ctx context.Context, client *Client, name, addr, proto string, tls *api.TLSConfigSpec) error {
	listeners, err := client.ListListeners(ctx)
	if err == nil {
		for _, l := range listeners {
			if l.Name == name || l.Address == addr {
				return nil // already exists
			}
		}
	}

	spec := api.ListenerSpec{
		Name:     name,
		Address:  addr,
		Protocol: proto,
		TLS:      tls,
	}
	return client.CreateListener(ctx, spec)
}

func runServeHTTP(ctx context.Context, client *Client, args []string) {
	var watchMode bool
	args, watchMode = extractBoolFlag(args, "w", "watch")

	fs := flag.NewFlagSet("serve http", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration (e.g. 30s, 15m, 2h, 1d)")
	listenerName := fs.String("listener", "serve-http-80", "Listener name")
	listenAddr := fs.String("listen", ":80", "Listen address")
	stripPrefix := fs.String("strip-prefix", "", "Strip path prefix before forwarding")
	basicAuth := fs.String("basic-auth", "", "Enforce HTTP basic auth (user:pass)")
	rateLimit := fs.String("rate-limit", "", "Rate limit (rate/burst, e.g. 100/20)")
	_ = fs.Bool("watch", false, "Stream live logs in foreground and remove route on Ctrl+C")
	_ = fs.Bool("w", false, "Stream live logs in foreground and remove route on Ctrl+C")

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

	path := fs.Arg(0)
	target := fs.Arg(1)

	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	if err := ensureListener(ctx, client, *listenerName, *listenAddr, "tcp", nil); err != nil {
		log.Fatalf("failed to create listener: %v", err)
	}

	routeName := fmt.Sprintf("serve-http-%d", time.Now().UnixNano()%10000)

	// Handler chain: Optional BasicAuth / RateLimit / StripPrefix -> http_lb
	handlerSpec := api.HandlerSpec{
		Type:   "http_lb",
		Config: map[string]any{"target": target},
	}

	if *stripPrefix != "" {
		handlerSpec = api.HandlerSpec{
			Type:   "http_strip_prefix",
			Config: map[string]any{"prefix": *stripPrefix},
			Next:   &handlerSpec,
		}
	}

	if *basicAuth != "" {
		parts := strings.SplitN(*basicAuth, ":", 2)
		if len(parts) == 2 {
			handlerSpec = api.HandlerSpec{
				Type:   "http_basic_auth",
				Config: map[string]any{"username": parts[0], "password": parts[1]},
				Next:   &handlerSpec,
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
		handlerSpec = api.HandlerSpec{
			Type:   "http_rate_limit",
			Config: map[string]any{"rate": rateVal, "burst": burstVal},
			Next:   &handlerSpec,
		}
	}

	ruleSpec := api.RuleSpec{Type: "any"}
	if path != "/" && path != "" {
		ruleSpec = api.RuleSpec{Type: "path_prefix", Value: path}
	}

	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "http",
		Listener: *listenerName,
		Priority: 1,
		TTL:      int(ttlDuration.Seconds()),
		Rule:     ruleSpec,
		Handler:  handlerSpec,
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		log.Fatalf("failed to create route: %v", err)
	}

	fmt.Printf("Sharing HTTP %s -> %s (Listener: %s)\n", path, target, *listenAddr)
	if ttlDuration > 0 {
		fmt.Printf("TTL: %v (auto-expires)\n", ttlDuration)
	}

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func runServeHTTPS(ctx context.Context, client *Client, args []string) {
	var watchMode bool
	args, watchMode = extractBoolFlag(args, "w", "watch")

	fs := flag.NewFlagSet("serve https", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration (e.g. 30s, 15m, 2h, 1d)")
	listenerName := fs.String("listener", "serve-https-443", "Listener name")
	listenAddr := fs.String("listen", ":443", "Listen address")
	domain := fs.String("domain", "", "TLS Domain name")
	acme := fs.Bool("acme", false, "Enable automatic Let's Encrypt TLS cert")
	certFile := fs.String("cert", "", "Path to PEM certificate")
	keyFile := fs.String("key", "", "Path to PEM private key")
	_ = fs.Bool("watch", false, "Stream live logs in foreground and remove route on Ctrl+C")
	_ = fs.Bool("w", false, "Stream live logs in foreground and remove route on Ctrl+C")

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

	path := fs.Arg(0)
	target := fs.Arg(1)

	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	var tlsSpec *api.TLSConfigSpec
	if *acme || *domain != "" || *certFile != "" {
		tlsSpec = &api.TLSConfigSpec{
			Auto: *acme,
		}
		if *domain != "" {
			tlsSpec.Domains = []string{*domain}
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

	if err := ensureListener(ctx, client, *listenerName, *listenAddr, "tcp", tlsSpec); err != nil {
		log.Fatalf("failed to create HTTPS listener: %v", err)
	}

	routeName := fmt.Sprintf("serve-https-%d", time.Now().UnixNano()%10000)
	ruleSpec := api.RuleSpec{Type: "any"}
	if *domain != "" && path != "/" && path != "" {
		ruleSpec = api.RuleSpec{
			Type: "and",
			Rules: []api.RuleSpec{
				{Type: "host", Value: *domain},
				{Type: "path_prefix", Value: path},
			},
		}
	} else if *domain != "" {
		ruleSpec = api.RuleSpec{Type: "host", Value: *domain}
	} else if path != "/" && path != "" {
		ruleSpec = api.RuleSpec{Type: "path_prefix", Value: path}
	}

	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "http",
		Listener: *listenerName,
		Priority: 1,
		TTL:      int(ttlDuration.Seconds()),
		Rule:     ruleSpec,
		Handler: api.HandlerSpec{
			Type:   "http_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		log.Fatalf("failed to create HTTPS route: %v", err)
	}

	fmt.Printf("Sharing HTTPS %s -> %s (Listener: %s)\n", path, target, *listenAddr)

	if watchMode {
		WatchAndCleanup(client, routeName)
	}
}

func runServeTCP(ctx context.Context, client *Client, args []string) {
	var watchMode bool
	args, watchMode = extractBoolFlag(args, "w", "watch")

	fs := flag.NewFlagSet("serve tcp", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	_ = fs.Bool("watch", false, "Stream live logs and remove route on Ctrl+C")
	_ = fs.Bool("w", false, "Stream live logs and remove route on Ctrl+C")

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

	ttlDuration, _ := ParseTTL(*ttlStr)
	listenerName := fmt.Sprintf("serve-tcp-%s", strings.TrimPrefix(listenAddr, ":"))

	if err := ensureListener(ctx, client, listenerName, listenAddr, "tcp", nil); err != nil {
		log.Fatalf("failed to create listener: %v", err)
	}

	routeName := fmt.Sprintf("serve-tcp-route-%d", time.Now().UnixNano()%10000)
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "tcp",
		Listener: listenerName,
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
	args, watchMode = extractBoolFlag(args, "w", "watch")

	fs := flag.NewFlagSet("serve udp", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	_ = fs.Bool("watch", false, "Stream live logs and remove route on Ctrl+C")
	_ = fs.Bool("w", false, "Stream live logs and remove route on Ctrl+C")

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

	ttlDuration, _ := ParseTTL(*ttlStr)
	listenerName := fmt.Sprintf("serve-udp-%s", strings.TrimPrefix(listenAddr, ":"))

	if err := ensureListener(ctx, client, listenerName, listenAddr, "udp", nil); err != nil {
		log.Fatalf("failed to create UDP listener: %v", err)
	}

	routeName := fmt.Sprintf("serve-udp-route-%d", time.Now().UnixNano()%10000)
	routeSpec := api.RouteSpec{
		Name:     routeName,
		Protocol: "udp",
		Listener: listenerName,
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

func runServeMinecraft(ctx context.Context, client *Client, args []string) {
	var watchMode bool
	args, watchMode = extractBoolFlag(args, "w", "watch")

	fs := flag.NewFlagSet("serve minecraft", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	_ = fs.Bool("watch", false, "Stream live logs and remove route on Ctrl+C")
	_ = fs.Bool("w", false, "Stream live logs and remove route on Ctrl+C")
	mcHost := fs.String("host", "", "Minecraft virtual host domain (e.g. mc.example.com)")
	players := fs.String("player", "", "Whitelisted Minecraft player usernames (comma-separated)")
	denyPlayers := fs.String("deny-player", "", "Blacklisted Minecraft player usernames (comma-separated)")

	if hasHelpFlag(args) {
		fmt.Println("Usage: gateway serve minecraft <listen-port> <target> [flags]")
		fs.PrintDefaults()
		os.Exit(0)
	}

	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		fmt.Println("Usage: gateway serve minecraft <listen-port> <target> [flags]")
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

	ttlDuration, _ := ParseTTL(*ttlStr)
	listenerName := fmt.Sprintf("serve-mc-%s", strings.TrimPrefix(listenAddr, ":"))

	if err := ensureListener(ctx, client, listenerName, listenAddr, "tcp", nil); err != nil {
		log.Fatalf("failed to create Minecraft listener: %v", err)
	}

	var rules []api.RuleSpec
	rules = append(rules, api.RuleSpec{Type: "is_minecraft"})

	if *mcHost != "" {
		rules = append(rules, api.RuleSpec{Type: "minecraft_host", Value: *mcHost})
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
		Listener: listenerName,
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

	fmt.Printf("Sharing Minecraft %s -> %s\n", listenAddr, target)

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
		if r.Name == nameOrPort || strings.Contains(r.Name, nameOrPort) || r.Listener == "serve-http-"+nameOrPort || r.Listener == "serve-tcp-"+nameOrPort {
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
		} else {
			fmt.Printf("No active serve mount found matching %q\n", nameOrPort)
		}
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
	fmt.Printf("Reset complete. Removed %d serve mounts.\n", deletedCount)
}
