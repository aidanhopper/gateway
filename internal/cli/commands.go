package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
	"github.com/aidanhopper/gateway/internal/config"
	"github.com/aidanhopper/gateway/internal/firewall"
	"github.com/aidanhopper/gateway/internal/gateway"
)

// PromptInput prints a prompt string and reads line input from stdin.
// If Ctrl+C (SIGINT/SIGTERM) is pressed while waiting for input, it prints
// "[INFO] Operation cancelled." and exits code 0 cleanly.
func PromptInput(prompt string) string {
	if prompt != "" {
		fmt.Print(prompt)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	type result struct {
		line string
	}
	resChan := make(chan result, 1)

	go func() {
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		resChan <- result{line: strings.TrimSpace(line)}
	}()

	select {
	case <-sigChan:
		signal.Stop(sigChan)
		fmt.Println("[INFO] Operation cancelled.")
		os.Exit(0)
		return ""
	case res := <-resChan:
		signal.Stop(sigChan)
		return res.line
	}
}

// loadServerDefaults loads the server config file + env vars and returns
// resolved defaults for use as flag default values in RunDaemon.
func loadServerDefaults(customPath string) *config.ServerConfig {
	cfg, err := config.LoadServerConfigFromPath(customPath)
	if err != nil {
		log.Printf("[WARNING] Could not load server config: %v", err)
		cfg = &config.ServerConfig{}
	}
	// Apply built-in fallbacks for unset fields
	if cfg.Addr == "" {
		cfg.Addr = "0.0.0.0:9090"
	}
	if cfg.DB == "" {
		cfg.DB = config.DBPath()
	}
	if cfg.Firewall == "" {
		cfg.Firewall = "auto"
	}
	if len(cfg.ProtectedPorts) == 0 {
		cfg.ProtectedPorts = config.StringOrList{"22/tcp"}
	}
	return cfg
}

// PrintUsage prints high-level CLI usage options.
func PrintUsage() {
	fmt.Println("Usage: gateway <command> [subcommand] [flags]")
	fmt.Printf("\n%s\n", ColorBold("Daemon & Overview:"))
	fmt.Println("  daemon                    Start the gateway proxy server and REST API daemon")
	fmt.Println("  status (stat)             DisplayTailscale-style status overview of daemon, listeners, and routes")
	fmt.Println("  logs (log)                Stream live logs for active proxy routes")
	fmt.Printf("\n%s\n", ColorBold("Service Exposure:"))
	fmt.Println("  serve (s)                 Expose local services (http, https, tcp, udp, mc, redirect)")
	fmt.Println("                            Example: gateway serve app.domain.com 3000 --1h")
	fmt.Printf("\n%s\n", ColorBold("Site Management:"))
	fmt.Println("  site (sites)              Manage target Gateway sites (list, use, ping)")
	fmt.Println("                            Config: ~/.config/gateway/config.yaml")
	fmt.Printf("\n%s\n", ColorBold("Management Commands:"))
	fmt.Println("  token (tokens)            Manage local daemon API auth tokens (create, list, revoke)")
	fmt.Println("  listener (listeners)      Inspect and force-delete listeners (list, delete)")
	fmt.Println("  route (routes)            Inspect and force-delete routes (list, delete)")
	fmt.Printf("\n%s\n", ColorBold("Global Flags:"))
	fmt.Println("  --site <name>             Target a specific Gateway site for any command")
	fmt.Println("  --yes, -y                 Bypass interactive confirmation prompts")
	fmt.Printf("\n%s\n", ColorBold("EXAMPLES:"))
	fmt.Println("  $ gateway serve http / 8080               Expose local port 8080 on HTTP")
	fmt.Println("  $ gateway serve app.domain.com 3000       Expose app.domain.com on HTTPS with auto-cert")
	fmt.Println("  $ gateway logs                            Stream live logs for background routes")
	fmt.Println("  $ gateway status                          Display active listeners and proxy routes")
}

// ConfirmPublicSiteExposure prompts for interactive confirmation if the target
// Gateway daemon reports itself as publicly exposed. Visibility is server-authoritative:
// set public: true in ~/.config/gateway/server.yaml or GATEWAY_PUBLIC=true on the daemon.
// If the daemon is unreachable the prompt is skipped (routes would fail anyway).
func ConfirmPublicSiteExposure(client *Client, yesFlag bool, targetDesc string) bool {
	if yesFlag {
		return true
	}
	health, err := client.Health(context.Background())
	if err != nil {
		return true
	}
	isPublic, _ := health["public"].(bool)
	if !isPublic {
		return true
	}

	siteDisplayName := client.SiteName
	if siteDisplayName == "" {
		siteDisplayName = "default"
	}
	fmt.Printf("[WARNING] Target site %q is PUBLICLY exposed to the open Internet (%s).\n", siteDisplayName, client.BaseURL)
	if targetDesc != "" {
		fmt.Printf("[INFO] %s will be publicly accessible.\n", targetDesc)
	}

	if fileInfo, err := os.Stdin.Stat(); err == nil && (fileInfo.Mode()&os.ModeCharDevice) == 0 {
		fmt.Fprintf(os.Stderr, "[ERROR] Target site %q is public. Exposing to open Internet requires -y / --yes flag in non-interactive shell.\n", siteDisplayName)
		os.Exit(2)
	}

	input := strings.ToLower(PromptInput("Are you sure you want to proceed? [y/N]: "))
	if input == "y" || input == "yes" {
		return true
	}
	fmt.Println("[INFO] Operation cancelled.")
	return false
}

func (c *Client) ConfirmPublicSiteExposure(yesFlag bool, targetDesc string) bool {
	return ConfirmPublicSiteExposure(c, yesFlag, targetDesc)
}

// RunDaemon starts the Gateway network proxy engine and REST API server.
func RunDaemon(args []string) {
	// Pre-scan args for optional custom config file flag
	customConfigPath := ""
	for i, arg := range args {
		if (arg == "--config" || arg == "-config" || arg == "-c" || arg == "--c") && i+1 < len(args) {
			customConfigPath = args[i+1]
			break
		} else if strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			customConfigPath = strings.SplitN(arg, "=", 2)[1]
			break
		} else if strings.HasPrefix(arg, "-c=") || strings.HasPrefix(arg, "--c=") {
			customConfigPath = strings.SplitN(arg, "=", 2)[1]
			break
		}
	}

	// Load server config file + env vars first; CLI flags override.
	defaults := loadServerDefaults(customConfigPath)

	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	configPath := fs.String("config", customConfigPath, "Path to server configuration file")
	fs.StringVar(configPath, "c", customConfigPath, "Path to server configuration file (shorthand)")
	dbPath := fs.String("db", defaults.DB, "Path to SQLite database file")
	addr := fs.String("addr", defaults.Addr, "REST API listen address")
	fwDriver := fs.String("firewall", defaults.Firewall, "Firewall driver (auto, dry, none, ufw, firewalld, nftables, iptables)")
	protectedPorts := fs.String("protected-ports", defaults.ProtectedPorts.String(), "Protected ports that can never be closed (e.g. 22/tcp or 22/tcp,2222/tcp)")
	_ = fs.Parse(args)

	// Resolve final public value: server config/env set the baseline;
	// there is no --public flag by design.
	isPublic := defaults.Public

	// Disable standard log flags so third-party or stdlib log calls don't prepend timestamps on top of formatted logs.
	log.SetFlags(0)
	gateway.SystemLogger = api.LogSystem
	firewall.Logger = func(level, format string, args ...any) {
		api.LogSystem(level, "FIREWALL", format, args...)
	}

	db, err := api.OpenDB(*dbPath)
	if err != nil {
		log.Fatalf("failed to open database at %s: %v", *dbPath, err)
	}
	defer db.Close()

	fwManager := firewall.Detect(*fwDriver, *protectedPorts)

	gw := gateway.New()
	apiServer, err := api.New(gw, db, fwManager, isPublic)
	if err != nil {
		log.Fatalf("failed to initialize api server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	handler := api.NewHandler(apiServer)
	httpServer := &http.Server{
		Addr:    *addr,
		Handler: handler,
	}

	go func() {
		publicStr := "private"
		if isPublic {
			publicStr = "public"
		}
		api.LogInfo("DAEMON", "REST API server listening on %s (db: %s, firewall: %s, visibility: %s)", *addr, *dbPath, *fwDriver, publicStr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			api.LogError("DAEMON", "REST API server error: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		api.LogInfo("DAEMON", "Gateway network proxy engine started")
		if err := gw.Listen(ctx); err != nil && ctx.Err() == nil {
			api.LogWarn("DAEMON", "Gateway listen error: %v", err)
		}
	}()

	<-ctx.Done()
	api.LogInfo("DAEMON", "Signal SIGINT/SIGTERM received; starting graceful shutdown...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)

	api.LogInfo("DAEMON", "Shutdown complete.")
}

// RunToken manages local daemon API authentication tokens directly in SQLite.
func RunToken(subcmd string, args []string) {
	ctx := context.Background()
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	siteName, args := ExtractSiteFlag(args)
	args, yesMode := extractBoolFlag(args, "y", "yes")

	switch subcmd {
	case "create", "add", "new":
		name := fs.String("name", "", "Human-readable label for the token")
		_ = fs.Parse(args)
		tokenName := *name
		if tokenName == "" && fs.NArg() > 0 {
			tokenName = fs.Arg(0)
		}

		client := NewClient(siteName)
		if !ConfirmPublicSiteExposure(client, yesMode, "API token creation") {
			return
		}

		id, token, err := client.CreateToken(ctx, tokenName)
		if err != nil {
			if strings.Contains(err.Error(), "readonly database") || strings.Contains(err.Error(), "permission denied") {
				fmt.Fprintf(os.Stderr, "[ERROR] Permission denied writing to database at %s.\n", client.DBPath)
				fmt.Fprintf(os.Stderr, "[INFO] Please run with sudo: sudo gateway token create %s\n", tokenName)
				os.Exit(1)
			}
			log.Fatalf("failed to create token: %v", err)
		}
		fmt.Printf("[SUCCESS] Created token %q (ID: %s) in local daemon DB (%s)\nToken: %s\n", tokenName, id, client.DBPath, token)
		fmt.Printf("  Export token:  export GATEWAY_API_TOKEN=%q\n", token)
		fmt.Println("  List tokens:   gateway tokens list")

	case "list", "ls":
		_ = fs.Parse(args)
		client := NewClient(siteName)

		tokens, err := client.ListTokens(ctx)
		if err != nil {
			log.Fatalf("failed to list tokens: %v", err)
		}

		if len(tokens) == 0 {
			fmt.Printf("No tokens found in local daemon DB (%s).\n", client.DBPath)
			return
		}

		tbl := NewTable("ID", "NAME", "CREATED AT")
		for _, t := range tokens {
			name := t.Name
			if name == "" {
				name = "<unnamed>"
			}
			tbl.AddRow(t.ID, name, t.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
		}
		fmt.Print(tbl.String())

	case "revoke", "delete", "rm", "del":
		_ = fs.Parse(args)
		if fs.NArg() < 1 {
			fmt.Println("Usage: gateway token revoke <id>")
			os.Exit(2)
		}
		targetID := fs.Arg(0)

		client := NewClient(siteName)
		if err := client.RevokeToken(ctx, targetID); err != nil {
			log.Fatalf("failed to revoke token: %v", err)
		}
		fmt.Printf("Revoked token %s in local daemon DB (%s)\n", targetID, client.DBPath)

	default:
		fmt.Println("Usage: gateway token <create|list|revoke> [flags]")
		fmt.Println("Note: Token commands access the local daemon SQLite database directly, not remote sites.")
		os.Exit(2)
	}
}

// RunListener manages network listeners.
func RunListener(subcmd string, args []string) {
	ctx := context.Background()
	fs := flag.NewFlagSet("listener", flag.ExitOnError)
	siteName, args := ExtractSiteFlag(args)

	switch subcmd {
	case "list", "ls":
		_ = fs.Parse(args)
		client := NewClient(siteName)

		listeners, err := client.ListListeners(ctx)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if len(listeners) == 0 {
			fmt.Println("No listeners found.")
			return
		}

		tbl := NewTable("NAME", "ADDRESS", "PROTOCOL")
		for _, spec := range listeners {
			tbl.AddRow(spec.Name, spec.Address, spec.Protocol)
		}
		fmt.Print(tbl.String())

	case "delete", "rm", "del":
		_ = fs.Parse(args)
		if fs.NArg() < 1 {
			fmt.Println("Usage: gateway listener delete <name>")
			os.Exit(2)
		}
		name := fs.Arg(0)

		client := NewClient(siteName)
		if err := client.DeleteListener(ctx, name); err != nil {
			log.Fatalf("%v", err)
		}
		fmt.Printf("Deleted listener %q\n", name)

	default:
		fmt.Println("Usage: gateway listener <list|delete> [flags]")
		os.Exit(2)
	}
}

// RunRoute manages proxy routes.
func RunRoute(subcmd string, args []string) {
	ctx := context.Background()
	fs := flag.NewFlagSet("route", flag.ExitOnError)
	siteName, args := ExtractSiteFlag(args)

	switch subcmd {
	case "list", "ls":
		_ = fs.Parse(args)
		client := NewClient(siteName)

		routes, err := client.ListRoutes(ctx)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if len(routes) == 0 {
			fmt.Println("No routes found.")
			return
		}

		tbl := NewTable("NAME", "LISTENER", "PROTOCOL", "PRIORITY")
		for _, spec := range routes {
			tbl.AddRow(spec.Name, spec.Listener, spec.Protocol, fmt.Sprintf("%d", spec.Priority))
		}
		fmt.Print(tbl.String())

	case "delete", "rm", "del":
		_ = fs.Parse(args)
		if fs.NArg() < 1 {
			fmt.Println("Usage: gateway route delete <name>")
			os.Exit(2)
		}
		name := fs.Arg(0)

		client := NewClient(siteName)
		if err := client.DeleteRoute(ctx, name); err != nil {
			log.Fatalf("%v", err)
		}
		fmt.Printf("Deleted route %q\n", name)

	default:
		fmt.Println("Usage: gateway route <list|delete> [flags]")
		os.Exit(2)
	}
}

func printJSONOrTable(data []byte) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(data))
	}
}

// RunLogs streams live logs for a route or all background routes.
func RunLogs(args []string) {
	siteName, args := ExtractSiteFlag(args)
	args, yesMode := extractBoolFlag(args, "y", "yes")
	if hasHelpFlag(args) {
		fmt.Println("Usage: gateway logs [route_name] [flags]")
		fmt.Println("\nFlags:")
		fmt.Println("  --site <name>             Target a specific Gateway site")
		fmt.Println("  --yes, -y                 Bypass interactive route picker and stream all routes")
		fmt.Println("\nEXAMPLES:")
		fmt.Println("  $ gateway logs                            Stream logs for active routes")
		fmt.Println("  $ gateway logs -y                         Stream logs for all routes without prompt")
		fmt.Println("  $ gateway logs serve-http-8080            Stream logs for specific route")
		return
	}

	routeFilter := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		routeFilter = args[0]
	}

	client := NewClient(siteName)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if routeFilter == "" && !yesMode {
		routes, err := client.ListRoutes(ctx)
		if err == nil && len(routes) > 0 {
			if len(routes) == 1 {
				routeFilter = routes[0].Name
			} else {
				if fileInfo, err := os.Stdin.Stat(); err == nil && (fileInfo.Mode()&os.ModeCharDevice) != 0 {
					fmt.Println("\nSelect route to view logs for:")
					for i, r := range routes {
						fmt.Printf("  %d) %-22s (%s -> %s)\n", i+1, r.Name, r.Protocol, FormatTargetsSummary(r.Handler))
					}
					fmt.Printf("  %d) All routes (stream everything)\n", len(routes)+1)
					input := PromptInput("\nEnter choice [default: all]: ")
					var choice int
					if _, err := fmt.Sscanf(input, "%d", &choice); err == nil && choice > 0 && choice <= len(routes) {
						routeFilter = routes[choice-1].Name
					}
				}
			}
		}
	}

	displayTarget := routeFilter
	if displayTarget == "" {
		displayTarget = "all routes"
	}

	fmt.Printf("[INFO] Streaming logs for %s... Press Ctrl+C to stop.\n", displayTarget)
	fmt.Println("-----------------------------------------------------------------------------------------")

	err := client.StreamLogs(ctx, routeFilter, func(event api.LogEvent) {
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
		log.Fatalf("failed to stream logs: %v", err)
	}
}
