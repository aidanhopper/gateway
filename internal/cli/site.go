package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
	"github.com/aidanhopper/gateway/internal/config"
)

// ExtractSiteFlag scans args for --site <name> or -site <name> and returns
// the site name and the remaining args with the flag removed.
func ExtractSiteFlag(args []string) (siteName string, rest []string) {
	for i := 0; i < len(args); i++ {
		if (args[i] == "--site" || args[i] == "-site") && i+1 < len(args) {
			siteName = args[i+1]
			rest = append(append([]string{}, args[:i]...), args[i+2:]...)
			return siteName, rest
		}
		if strings.HasPrefix(args[i], "--site=") {
			siteName = strings.TrimPrefix(args[i], "--site=")
			rest = append(append([]string{}, args[:i]...), args[i+1:]...)
			return siteName, rest
		}
	}
	return "", args
}

// RunSite handles 'gateway site' subcommands.
func RunSite(subcmd string, args []string) {
	switch subcmd {
	case "list", "ls":
		runSiteList()
	case "use":
		name := ""
		if len(args) > 0 {
			name = args[0]
		}
		runSiteUse(name)
	case "ping":
		name := ""
		if len(args) > 0 {
			name = args[0]
		}
		runSitePing(name)
	case "logs", "log":
		name := ""
		if len(args) > 0 {
			name = args[0]
		}
		runSiteLogs(name)
	default:
		fmt.Println("Usage: gateway site <list|use|ping|logs> [args]")
		os.Exit(2)
	}
}

func runSiteList() {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Loading config: %v\n", err)
		os.Exit(2)
	}

	activeSite, _ := config.ReadActiveSite()

	fmt.Printf("CONFIGURED SITES (%d)\n", len(cfg.Sites))
	if len(cfg.Sites) == 0 {
		fmt.Println("No sites configured.")
		fmt.Printf("Add sites to %s/config.yaml\n", config.ConfigDir())
		return
	}

	tbl := NewTable("", "NAME", "TARGET URL", "VISIBILITY", "STATUS")
	for name, profile := range cfg.Sites {
		marker := " "
		if name == activeSite {
			marker = ColorGreen("*")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		client := NewClientDirect(profile.URL, profile.Token, "")
		siteHealth, err := client.Health(ctx)
		cancel()

		statusBadge := BadgeSuccess("[ACTIVE]")
		if err != nil {
			statusBadge = BadgeError("[OFFLINE]")
			siteHealth = map[string]any{}
		}

		visStr := "private"
		if pub, _ := siteHealth["public"].(bool); pub {
			visStr = BadgeWarning("PUBLIC")
		}

		tbl.AddRow(marker, name, profile.URL, visStr, statusBadge)
	}
	fmt.Print(tbl.String())
}

func runSiteUse(name string) {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Loading config: %v\n", err)
		os.Exit(2)
	}

	if name == "" {
		if len(cfg.Sites) == 0 {
			fmt.Printf("[INFO] No sites configured in %s/config.yaml\n", config.ConfigDir())
			return
		}
		siteNames := make([]string, 0, len(cfg.Sites))
		for n := range cfg.Sites {
			siteNames = append(siteNames, n)
		}
		fmt.Println("Select Gateway site to use:")
		for i, n := range siteNames {
			p := cfg.Sites[n]
			fmt.Printf("  %d) %-15s (%s)\n", i+1, n, p.URL)
		}
		input := PromptInput("Enter number (or 0 to cancel): ")
		var choice int
		if _, err := fmt.Sscanf(input, "%d", &choice); err == nil && choice > 0 && choice <= len(siteNames) {
			name = siteNames[choice-1]
		} else {
			fmt.Println("[INFO] Operation cancelled.")
			return
		}
	}

	if _, ok := cfg.Sites[name]; !ok {
		fmt.Fprintf(os.Stderr, "[ERROR] Site %q not found in %s/config.yaml\n", name, config.ConfigDir())
		os.Exit(2)
	}

	if err := config.WriteActiveSite(name); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to set active site: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("[SUCCESS] Active site set to %q\n", name)
}

func runSitePing(nameOverride string) {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	profile, err := config.ResolveSite(cfg, nameOverride)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving site: %v\n", err)
		os.Exit(1)
	}

	displayName := nameOverride
	if displayName == "" {
		activeSite, _ := config.ReadActiveSite()
		if activeSite != "" {
			displayName = activeSite
		} else {
			displayName = "local (default)"
		}
	}

	fmt.Printf("Pinging site %q (%s)...\n", displayName, profile.URL)

	httpClient := &http.Client{Timeout: 5 * time.Second}
	req, err := newHealthRequest(profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	resp, err := httpClient.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("  FAIL  %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("  OK    %dms\n", elapsed.Milliseconds())
	} else if resp.StatusCode == http.StatusUnauthorized {
		fmt.Printf("  UNAUTH  Reachable but token is invalid or missing (%dms)\n", elapsed.Milliseconds())
		os.Exit(1)
	} else {
		fmt.Printf("  WARN  HTTP %d (%dms)\n", resp.StatusCode, elapsed.Milliseconds())
	}
}

func newHealthRequest(profile config.SiteProfile) (*http.Request, error) {
	url := strings.TrimRight(profile.URL, "/") + "/api/v1/health"
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if profile.Token != "" {
		req.Header.Set("Authorization", "Bearer "+profile.Token)
	}
	return req, nil
}

func runSiteLogs(nameOverride string) {
	client := NewClient(nameOverride)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Println("[INFO] Streaming daemon system logs... Press Ctrl+C to stop.")
	fmt.Println("-----------------------------------------------------------------------------------------")

	err := client.StreamSystemLogs(ctx, func(event api.SystemLogEvent) {
		timeStr := event.Timestamp.Format("15:04:05")
		lvlPadded := fmt.Sprintf("%-5s", event.Level)
		compPadded := fmt.Sprintf("%-8s", event.Component)
		fmt.Printf("[%s] [%s] [%s] %s\n", timeStr, lvlPadded, compPadded, event.Message)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}
}
