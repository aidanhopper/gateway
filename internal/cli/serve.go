package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
	"github.com/aidanhopper/gateway/internal/serve"
)

// PrintServeUsage prints usage for 'gateway serve' subcommands.
func PrintServeUsage() {
	fmt.Println("Usage: gateway serve <protocol|subcommand> [args] [flags]")
	fmt.Println("\nProtocols:")
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
				statusStr = fmt.Sprintf("%d %s ", event.Status, serve.HTTPStatusText(event.Status))
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
	fmt.Println("[INFO] Received interrupt. Stopping share...")

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cleanupCancel()

	for _, rName := range routeNames {
		if err := client.DeleteRoute(cleanupCtx, rName); err != nil {
			fmt.Printf("[ERROR] Failed to delete route %s on exit: %v\n", rName, err)
		} else {
			fmt.Printf("[SUCCESS] Route %q deleted.\n", rName)
		}
	}
	fmt.Println("[INFO] Sharing stopped.")
	serve.CleanupUnusedListeners(cleanupCtx, client)
}

// CheckBackendDial attempts a quick test connection to the target to warn if offline.
func CheckBackendDial(target string) {
	addr := target
	if !strings.Contains(addr, ":") {
		addr = "127.0.0.1:" + addr
	}
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		fmt.Printf("[WARNING] Target backend at %s is not reachable (%v)\n", target, err)
		fmt.Println("[INFO] Proxy route created anyway. Make sure your local application is started.")
	} else {
		conn.Close()
	}
}

// ExtractWatchAndBGFlags scans args for background mode (-bg, --bg, -d) or foreground watch mode (-w, --watch).
func ExtractWatchAndBGFlags(args []string) ([]string, bool) {
	args, bgMode := extractBoolFlag(args, "bg", "d")
	args, explicitWatch := extractBoolFlag(args, "w", "watch")
	if bgMode && !explicitWatch {
		return args, false
	}
	return args, true
}

// RunServe handles 'gateway serve' CLI commands.
func RunServe(args []string) {
	if len(args) < 1 {
		PrintServeUsage()
		os.Exit(0)
	}

	siteName, args := ExtractSiteFlag(args)
	args, yesMode := extractBoolFlag(args, "y", "yes")
	var durationPreset string
	args, durationPreset = ExtractDurationFlags(args)

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

	if subcmd == "status" {
		runServeStatus(ctx, client)
		return
	}

	if subcmd == "reset" {
		runServeReset(ctx, client, yesMode)
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
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] Unknown serve protocol or subcommand %q\n\n", subcmd)
		PrintServeUsage()
		os.Exit(2)
	}
}

func runServeStatus(ctx context.Context, client *Client) {
	routes, err := serve.Status(ctx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to retrieve serve status: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("ACTIVE SERVE MOUNTS (%d)\n", len(routes))
	if len(routes) == 0 {
		fmt.Println("No active serve mounts.")
		return
	}

	tbl := NewTable("NAME", "LISTENER", "PROTO", "MATCH", "TARGET", "EXPIRES IN")
	for _, r := range routes {
		tbl.AddRow(r.Name, r.Listener, r.Protocol, FormatRuleSummary(r.Rule), FormatTargetsSummary(r.Handler), FormatTTLRemaining(time.Now(), r.TTL))
	}
	fmt.Print(tbl.String())
}

func runServeOff(ctx context.Context, client *Client, nameOrPort string) {
	if nameOrPort == "" {
		routes, err := serve.Status(ctx, client)
		if err != nil || len(routes) == 0 {
			fmt.Println("[INFO] No active serve mounts found.")
			return
		}
		fmt.Println("Select an active serve mount to turn off:")
		for i, r := range routes {
			fmt.Printf("  %d) %-22s (%s -> %s)\n", i+1, r.Name, r.Protocol, FormatTargetsSummary(r.Handler))
		}
		input := PromptInput("Enter number (or 0 to cancel): ")
		var choice int
		if _, err := fmt.Sscanf(input, "%d", &choice); err == nil && choice > 0 && choice <= len(routes) {
			nameOrPort = routes[choice-1].Name
		} else {
			fmt.Println("[INFO] Operation cancelled.")
			return
		}
	}

	deleted, err := serve.Off(ctx, client, nameOrPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}

	if deleted > 0 {
		fmt.Printf("[SUCCESS] Removed serve mount %q\n", nameOrPort)
	} else {
		fmt.Printf("[INFO] No active serve mount found matching %q\n", nameOrPort)
	}
}

func runServeReset(ctx context.Context, client *Client, yesMode bool) {
	routes, err := serve.Status(ctx, client)
	if err != nil || len(routes) == 0 {
		fmt.Println("No active serve mounts to remove.")
		return
	}

	if !yesMode {
		fmt.Printf("This will remove %d serve mount(s). Continue? [y/N]: ", len(routes))
		input := strings.ToLower(PromptInput(""))
		if input != "y" && input != "yes" {
			fmt.Println("[INFO] Operation cancelled.")
			return
		}
	}

	deleted, err := serve.Reset(ctx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Reset complete. Removed %d serve mount(s).\n", deleted)
}

func runServeHTTP(ctx context.Context, client *Client, args []string, yesMode bool) {
	args, watchMode := ExtractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve http", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	priority := fs.Int("priority", 0, "Route priority (0 for auto)")
	fs.IntVar(priority, "p", 0, "Route priority (shorthand)")
	_ = fs.Bool("bg", false, "Run in background mode")
	_ = fs.Bool("d", false, "Run in background mode")

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

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	target := fs.Arg(1)
	routes, err := serve.HTTP(ctx, client, serve.HTTPOptions{
		Mount:      fs.Arg(0),
		Target:     target,
		Priority:   *priority,
		TTL:        ttlDuration,
		Background: !watchMode,
		Yes:        yesMode,
	})
	if err != nil {
		log.Fatalf("failed to serve http: %v", err)
	}

	CheckBackendDial(target)

	if watchMode && len(routes) > 0 {
		WatchAndCleanup(client, routes...)
	}
}

func runServeHTTPS(ctx context.Context, client *Client, args []string, yesMode bool) {
	args, watchMode := ExtractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve https", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	listenAddr := fs.String("listen", ":443", "Listen address")
	acme := fs.Bool("acme", true, "Enable automatic Let's Encrypt / ACME TLS cert")
	noRedirect := fs.Bool("no-redirect", false, "Do not automatically create HTTP to HTTPS redirect route on port 80")
	priority := fs.Int("priority", 0, "Route priority (0 for auto)")
	fs.IntVar(priority, "p", 0, "Route priority (shorthand)")
	_ = fs.Bool("bg", false, "Run in background mode")
	_ = fs.Bool("d", false, "Run in background mode")

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

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	target := fs.Arg(1)
	routes, err := serve.HTTPS(ctx, client, serve.HTTPSOptions{
		Mount:      fs.Arg(0),
		Target:     target,
		ListenAddr: *listenAddr,
		Priority:   *priority,
		ACME:       *acme,
		NoRedirect: *noRedirect,
		TTL:        ttlDuration,
		Background: !watchMode,
		Yes:        yesMode,
	})
	if err != nil {
		log.Fatalf("failed to serve https: %v", err)
	}

	CheckBackendDial(target)

	if watchMode && len(routes) > 0 {
		WatchAndCleanup(client, routes...)
	}
}

func runServeTCP(ctx context.Context, client *Client, args []string, yesMode bool) {
	args, watchMode := ExtractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve tcp", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	priority := fs.Int("priority", 0, "Route priority (0 for auto)")
	fs.IntVar(priority, "p", 0, "Route priority (shorthand)")
	_ = fs.Bool("bg", false, "Run in background mode")
	_ = fs.Bool("d", false, "Run in background mode")

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

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	routes, err := serve.TCP(ctx, client, serve.TCPOptions{
		ListenPort: fs.Arg(0),
		Target:     fs.Arg(1),
		Priority:   *priority,
		TTL:        ttlDuration,
		Background: !watchMode,
		Yes:        yesMode,
	})
	if err != nil {
		log.Fatalf("failed to serve tcp: %v", err)
	}

	if watchMode && len(routes) > 0 {
		WatchAndCleanup(client, routes...)
	}
}

func runServeUDP(ctx context.Context, client *Client, args []string, yesMode bool) {
	args, watchMode := ExtractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve udp", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	priority := fs.Int("priority", 0, "Route priority (0 for auto)")
	fs.IntVar(priority, "p", 0, "Route priority (shorthand)")
	_ = fs.Bool("bg", false, "Run in background mode")
	_ = fs.Bool("d", false, "Run in background mode")

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

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	routes, err := serve.UDP(ctx, client, serve.UDPOptions{
		ListenPort: fs.Arg(0),
		Target:     fs.Arg(1),
		Priority:   *priority,
		TTL:        ttlDuration,
		Background: !watchMode,
		Yes:        yesMode,
	})
	if err != nil {
		log.Fatalf("failed to serve udp: %v", err)
	}

	if watchMode && len(routes) > 0 {
		WatchAndCleanup(client, routes...)
	}
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	for _, p := range strings.Split(val, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

func runServeMinecraft(ctx context.Context, client *Client, args []string, yesMode bool) {
	args, watchMode := ExtractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve minecraft", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	priority := fs.Int("priority", 0, "Route priority (0 for auto)")
	fs.IntVar(priority, "p", 0, "Route priority (shorthand)")
	_ = fs.Bool("bg", false, "Run in background mode")
	_ = fs.Bool("d", false, "Run in background mode")

	var allowPlayers stringSliceFlag
	fs.Var(&allowPlayers, "allow", "Allowed player username(s) (whitelist)")
	fs.Var(&allowPlayers, "allow-players", "Allowed player username(s) (whitelist)")
	fs.Var(&allowPlayers, "whitelist", "Allowed player username(s) (whitelist)")

	var denyPlayers stringSliceFlag
	fs.Var(&denyPlayers, "deny", "Denied player username(s) (blacklist)")
	fs.Var(&denyPlayers, "deny-players", "Denied player username(s) (blacklist)")
	fs.Var(&denyPlayers, "blacklist", "Denied player username(s) (blacklist)")

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

	arg1 := ""
	if fs.NArg() >= 2 {
		arg1 = fs.Arg(1)
	}

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	routes, err := serve.Minecraft(ctx, client, serve.MinecraftOptions{
		HostOrPort:   fs.Arg(0),
		Target:       arg1,
		AllowPlayers: allowPlayers,
		DenyPlayers:  denyPlayers,
		Priority:     *priority,
		TTL:          ttlDuration,
		Background:   !watchMode,
		Yes:          yesMode,
	})
	if err != nil {
		log.Fatalf("failed to serve minecraft: %v", err)
	}

	if watchMode && len(routes) > 0 {
		WatchAndCleanup(client, routes...)
	}
}

func runServeRedirect(ctx context.Context, client *Client, args []string, yesMode bool) {
	args, watchMode := ExtractWatchAndBGFlags(args)

	fs := flag.NewFlagSet("serve redirect", flag.ExitOnError)
	ttlStr := fs.String("ttl", "", "Time to live duration")
	statusCode := fs.Int("code", 301, "HTTP status code for redirect (301, 302, 307, 308)")
	exact := fs.Bool("exact", false, "Strict exact path matching (does not match subpaths)")
	fs.BoolVar(exact, "e", false, "Strict exact path matching (shorthand)")
	forwardPath := fs.Bool("forward-path", true, "Forward relative subpaths to target URL")
	fs.BoolVar(forwardPath, "f", true, "Forward relative subpaths (shorthand)")
	noForwardPath := fs.Bool("no-forward-path", false, "Do not append subpaths to target URL")
	noQuery := fs.Bool("no-query", false, "Do not forward query parameters to target URL")
	priority := fs.Int("priority", 0, "Route priority (0 for auto)")
	fs.IntVar(priority, "p", 0, "Route priority (shorthand)")
	_ = fs.Bool("bg", false, "Run in background mode")
	_ = fs.Bool("d", false, "Run in background mode")

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

	ttlDuration, err := ParseTTL(*ttlStr)
	if err != nil {
		log.Fatalf("invalid ttl: %v", err)
	}

	routes, err := serve.Redirect(ctx, client, serve.RedirectOptions{
		Mount:         fs.Arg(0),
		TargetURL:     fs.Arg(1),
		StatusCode:    *statusCode,
		Exact:         *exact,
		NoForwardPath: *noForwardPath || !*forwardPath,
		NoQuery:       *noQuery,
		Priority:      *priority,
		TTL:           ttlDuration,
		Background:    !watchMode,
		Yes:           yesMode,
	})
	if err != nil {
		log.Fatalf("failed to serve redirect: %v", err)
	}

	if watchMode && len(routes) > 0 {
		WatchAndCleanup(client, routes...)
	}
}
