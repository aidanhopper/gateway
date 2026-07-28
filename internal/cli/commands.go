package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
	"github.com/aidanhopper/gateway/internal/firewall"
	"github.com/aidanhopper/gateway/internal/gateway"
)

func getDefaultDBPath() string {
	if envDB := os.Getenv("GATEWAY_DB"); envDB != "" {
		return envDB
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./gateway.db"
	}
	return filepath.Join(home, ".gateway", "gateway.db")
}

func getDefaultAddr() string {
	if envAddr := os.Getenv("GATEWAY_ADDR"); envAddr != "" {
		return envAddr
	}
	return "0.0.0.0:9090"
}

func getDefaultFirewall() string {
	if envFW := os.Getenv("GATEWAY_FIREWALL"); envFW != "" {
		return envFW
	}
	return "auto"
}

func getDefaultProtectedPorts() string {
	if envProt := os.Getenv("GATEWAY_PROTECTED_PORTS"); envProt != "" {
		return envProt
	}
	return "22/tcp"
}

// PrintUsage prints high-level CLI usage options.
func PrintUsage() {
	fmt.Println("Usage: gateway <command> [subcommand] [flags]")
	fmt.Println("\nDaemon & Overview:")
	fmt.Println("  daemon           Start the gateway proxy server and REST API daemon")
	fmt.Println("  status           Display status overview of daemon, listeners, and routes")
	fmt.Println("\nService Exposure:")
	fmt.Println("  serve            Expose local services (http, https, tcp, udp, minecraft)")
	fmt.Println("                   Use --watch / -w to stream logs live and delete route on Ctrl+C")
	fmt.Println("\nManagement Commands:")
	fmt.Println("  token            Manage API authentication tokens (create, list, revoke)")
	fmt.Println("  listener         Manage listeners (list, create, delete)")
	fmt.Println("  route            Manage routes (list, create, delete)")
}

// RunDaemon starts the Gateway network proxy engine and REST API server.
func RunDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	dbPath := fs.String("db", getDefaultDBPath(), "Path to SQLite database file")
	addr := fs.String("addr", getDefaultAddr(), "REST API listen address")
	fwDriver := fs.String("firewall", getDefaultFirewall(), "Firewall driver (auto, dry, none, ufw, firewalld, nftables, iptables)")
	protectedPorts := fs.String("protected-ports", getDefaultProtectedPorts(), "Protected ports that can never be closed (e.g. 22/tcp)")
	_ = fs.Parse(args)

	db, err := api.OpenDB(*dbPath)
	if err != nil {
		log.Fatalf("failed to open database at %s: %v", *dbPath, err)
	}
	defer db.Close()

	fwManager := firewall.Detect(*fwDriver, *protectedPorts)

	gw := gateway.New()
	apiServer, err := api.New(gw, db, fwManager)
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
		log.Printf("REST API server listening on %s (DB: %s, Firewall: %s, Protected: %s)\n", *addr, *dbPath, *fwDriver, *protectedPorts)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("REST API server error: %v\n", err)
		}
	}()

	go func() {
		log.Println("Gateway network proxy engine started")
		if err := gw.Listen(ctx); err != nil && ctx.Err() == nil {
			log.Printf("Gateway listen error: %v\n", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down gateway and API server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)

	log.Println("Shutdown complete.")
}

// RunToken manages API authentication tokens.
func RunToken(subcmd string, args []string) {
	ctx := context.Background()
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	dbPath := fs.String("db", getDefaultDBPath(), "Path to SQLite database file")

	client := NewClient("", "", *dbPath)

	switch subcmd {
	case "create":
		name := fs.String("name", "", "Human-readable label for the token")
		_ = fs.Parse(args)

		client.DBPath = *dbPath
		id, token, err := client.CreateToken(ctx, *name)
		if err != nil {
			log.Fatalf("failed to create token: %v", err)
		}
		fmt.Printf("Created token %q (ID: %s)\nToken: %s\n", *name, id, token)

	case "list":
		_ = fs.Parse(args)

		client.DBPath = *dbPath
		tokens, err := client.ListTokens(ctx)
		if err != nil {
			log.Fatalf("failed to list tokens: %v", err)
		}

		if len(tokens) == 0 {
			fmt.Println("No tokens found.")
			return
		}

		fmt.Printf("%-38s %-20s %-25s\n", "ID", "NAME", "CREATED AT")
		fmt.Println("-------------------------------------------------------------------------------------")
		for _, t := range tokens {
			name := t.Name
			if name == "" {
				name = "<unnamed>"
			}
			fmt.Printf("%-38s %-20s %-25s\n", t.ID, name, t.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
		}

	case "revoke":
		_ = fs.Parse(args)
		if fs.NArg() < 1 {
			fmt.Println("Usage: gateway token revoke [--db <path>] <id>")
			os.Exit(0)
		}
		targetID := fs.Arg(0)

		client.DBPath = *dbPath
		if err := client.RevokeToken(ctx, targetID); err != nil {
			log.Fatalf("failed to revoke token: %v", err)
		}
		fmt.Printf("Revoked token %s\n", targetID)

	default:
		fmt.Println("Usage: gateway token <create|list|revoke> [flags]")
		os.Exit(0)
	}
}

// RunListener manages network listeners.
func RunListener(subcmd string, args []string) {
	ctx := context.Background()
	fs := flag.NewFlagSet("listener", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to SQLite database file")
	apiAddr := fs.String("api-addr", "", "REST API address")
	token := fs.String("token", "", "Bearer token for authentication")

	switch subcmd {
	case "list":
		_ = fs.Parse(args)
		client := NewClient(*apiAddr, *token, *dbPath)

		listeners, err := client.ListListeners(ctx)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if len(listeners) == 0 {
			fmt.Println("No listeners found.")
			return
		}

		fmt.Printf("%-20s %-20s %-10s\n", "NAME", "ADDRESS", "PROTOCOL")
		fmt.Println("--------------------------------------------------")
		for _, spec := range listeners {
			fmt.Printf("%-20s %-20s %-10s\n", spec.Name, spec.Address, spec.Protocol)
		}

	case "create":
		name := fs.String("name", "", "Listener name")
		addr := fs.String("address", "", "Listen address (e.g. :8080)")
		proto := fs.String("protocol", "tcp", "Protocol (tcp|udp)")
		_ = fs.Parse(args)

		if *name == "" || *addr == "" {
			fmt.Println("Usage: gateway listener create --name <name> --address <addr> [--protocol tcp|udp] [--token <token>]")
			os.Exit(0)
		}

		client := NewClient(*apiAddr, *token, *dbPath)
		spec := api.ListenerSpec{
			Name:     *name,
			Address:  *addr,
			Protocol: *proto,
		}
		if err := client.CreateListener(ctx, spec); err != nil {
			log.Fatalf("%v", err)
		}
		fmt.Printf("Created listener %q (%s/%s)\n", spec.Name, spec.Address, spec.Protocol)

	case "delete":
		_ = fs.Parse(args)
		if fs.NArg() < 1 {
			fmt.Println("Usage: gateway listener delete [--token <token>] <name>")
			os.Exit(0)
		}
		name := fs.Arg(0)

		client := NewClient(*apiAddr, *token, *dbPath)
		if err := client.DeleteListener(ctx, name); err != nil {
			log.Fatalf("%v", err)
		}
		fmt.Printf("Deleted listener %q\n", name)

	default:
		fmt.Println("Usage: gateway listener <list|create|delete> [flags]")
		os.Exit(0)
	}
}

// RunRoute manages proxy routes.
func RunRoute(subcmd string, args []string) {
	ctx := context.Background()
	fs := flag.NewFlagSet("route", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to SQLite database file")
	apiAddr := fs.String("api-addr", "", "REST API address")
	token := fs.String("token", "", "Bearer token for authentication")

	switch subcmd {
	case "list":
		_ = fs.Parse(args)
		client := NewClient(*apiAddr, *token, *dbPath)

		routes, err := client.ListRoutes(ctx)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if len(routes) == 0 {
			fmt.Println("No routes found.")
			return
		}

		fmt.Printf("%-20s %-15s %-15s %-10s\n", "NAME", "LISTENER", "PROTOCOL", "PRIORITY")
		fmt.Println("------------------------------------------------------------------")
		for _, spec := range routes {
			fmt.Printf("%-20s %-15s %-15s %-10d\n", spec.Name, spec.Listener, spec.Protocol, spec.Priority)
		}

	case "create":
		name := fs.String("name", "", "Route name")
		listener := fs.String("listener", "", "Listener name")
		proto := fs.String("protocol", "http", "Protocol (http|tcp|udp)")
		target := fs.String("target", "", "Target backend address")
		ttlStr := fs.String("ttl", "", "Time to live duration (e.g. 30s, 15m, 2h, 1d)")
		_ = fs.Parse(args)

		if *name == "" || *listener == "" || *target == "" {
			fmt.Println("Usage: gateway route create --name <name> --listener <ln> --target <addr> [--protocol http|tcp|udp] [--ttl <duration>]")
			os.Exit(0)
		}

		ttlDuration, err := ParseTTL(*ttlStr)
		if err != nil {
			log.Fatalf("invalid ttl: %v", err)
		}

		client := NewClient(*apiAddr, *token, *dbPath)
		handlerType := fmt.Sprintf("%s_lb", *proto)
		spec := api.RouteSpec{
			Name:     *name,
			Listener: *listener,
			Protocol: *proto,
			Priority: 1,
			TTL:      int(ttlDuration.Seconds()),
			Rule:     api.RuleSpec{Type: "any"},
			Handler: api.HandlerSpec{
				Type:   handlerType,
				Config: map[string]any{"target": *target},
			},
		}
		if err := client.CreateRoute(ctx, spec); err != nil {
			log.Fatalf("%v", err)
		}
		if ttlDuration > 0 {
			fmt.Printf("Created route %q (%s -> %s) [TTL: %v]\n", spec.Name, spec.Protocol, *target, ttlDuration)
		} else {
			fmt.Printf("Created route %q (%s -> %s)\n", spec.Name, spec.Protocol, *target)
		}

	case "delete":
		_ = fs.Parse(args)
		if fs.NArg() < 1 {
			fmt.Println("Usage: gateway route delete [--token <token>] <name>")
			os.Exit(0)
		}
		name := fs.Arg(0)

		client := NewClient(*apiAddr, *token, *dbPath)
		if err := client.DeleteRoute(ctx, name); err != nil {
			log.Fatalf("%v", err)
		}
		fmt.Printf("Deleted route %q\n", name)

	default:
		fmt.Println("Usage: gateway route <list|create|delete> [flags]")
		os.Exit(0)
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
