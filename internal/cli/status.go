package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
)

// FormatTTLRemaining returns a human-readable countdown string for a given route creation time and TTL seconds.
func FormatTTLRemaining(createdAt time.Time, ttlSeconds int) string {
	if ttlSeconds <= 0 {
		return "Permanent"
	}
	expireTime := createdAt.Add(time.Duration(ttlSeconds) * time.Second)
	remaining := time.Until(expireTime)
	if remaining <= 0 {
		return "[Expired]"
	}

	totalSec := int(remaining.Seconds())
	hours := totalSec / 3600
	mins := (totalSec % 3600) / 60
	secs := totalSec % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

// FormatRuleSummary produces a clean, human-readable summary string for a route rule.
func FormatRuleSummary(rule api.RuleSpec) string {
	switch rule.Type {
	case "any":
		return "Any"
	case "host":
		return fmt.Sprintf("Host(%q)", rule.Value)
	case "path":
		return fmt.Sprintf("Path(%q)", rule.Value)
	case "path_prefix":
		return fmt.Sprintf("PathPrefix(%q)", rule.Value)
	case "method":
		return fmt.Sprintf("Method(%s)", strings.Join(rule.Values, ","))
	case "remote_ip":
		return fmt.Sprintf("RemoteIP(%q)", rule.Value)
	case "sni":
		return fmt.Sprintf("SNI(%q)", rule.Value)
	case "minecraft_host":
		return fmt.Sprintf("MinecraftHost(%q)", rule.Value)
	case "minecraft_player":
		return fmt.Sprintf("MinecraftPlayer(%s)", strings.Join(rule.Values, ","))
	case "minecraft_player_not":
		return fmt.Sprintf("MinecraftNotPlayer(%s)", strings.Join(rule.Values, ","))
	default:
		if rule.Value != "" {
			return fmt.Sprintf("%s(%q)", rule.Type, rule.Value)
		}
		return rule.Type
	}
}

// FormatTargetsSummary extracts backend target addresses from a handler spec.
func FormatTargetsSummary(handler api.HandlerSpec) string {
	if handler.Config == nil {
		return "-"
	}
	if target, ok := handler.Config["target"].(string); ok && target != "" {
		return target
	}
	if rawList, ok := handler.Config["targets"].([]any); ok {
		var targets []string
		for _, item := range rawList {
			if s, ok := item.(string); ok {
				targets = append(targets, s)
			}
		}
		if len(targets) > 0 {
			return strings.Join(targets, ",")
		}
	}
	if strList, ok := handler.Config["targets"].([]string); ok && len(strList) > 0 {
		return strings.Join(strList, ",")
	}
	return "-"
}

// FormatStrategy extracts load balancer strategy.
func FormatStrategy(handler api.HandlerSpec) string {
	if handler.Config != nil {
		if strat, ok := handler.Config["strategy"].(string); ok && strat != "" {
			return strat
		}
	}
	return "round_robin"
}

// RunStatus displays a Tailscale-style status dashboard of daemon health, listeners, and routes.
func RunStatus(args []string) {
	siteName, _ := ExtractSiteFlag(args)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client := NewClient(siteName)

	healthData, healthErr := client.Health(ctx)
	daemonStatus := BadgeSuccess("[RUNNING]")
	if healthErr != nil {
		daemonStatus = BadgeError("[OFFLINE]")
		healthData = map[string]any{}
	}

	fwDriver := os.Getenv("GATEWAY_FIREWALL")
	if fwDriver == "" {
		fwDriver = "auto"
	}

	visibilityStr := "private"
	if pub, _ := healthData["public"].(bool); pub {
		visibilityStr = BadgeWarning("PUBLIC (Open Internet)")
	}

	siteNameStr := client.SiteName
	if siteNameStr == "" {
		siteNameStr = "default"
	}

	divLine := "========================================================================================="
	fmt.Println(divLine)
	fmt.Printf("Gateway Daemon Status: %s\n", daemonStatus)
	fmt.Printf("Target Site:           %s (%s)\n", siteNameStr, visibilityStr)
	fmt.Printf("API Address:           %s\n", client.BaseURL)
	fmt.Printf("Database Path:         %s\n", client.DBPath)
	fmt.Printf("Firewall Driver:       %s\n", fwDriver)
	fmt.Println(divLine)

	// Listeners
	listeners, err := client.ListListeners(ctx)
	if err != nil && healthErr != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to retrieve status: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nLISTENERS (%d)\n", len(listeners))
	if len(listeners) == 0 {
		fmt.Println("No listeners registered.")
	} else {
		lnTable := NewTable("NAME", "ADDRESS", "PROTOCOL", "STATUS")
		for _, ln := range listeners {
			statusBadge := BadgeSuccess("[ACTIVE]")
			if healthErr != nil {
				statusBadge = BadgeError("[OFFLINE]")
			}
			lnTable.AddRow(ln.Name, ln.Address, ln.Protocol, statusBadge)
		}
		fmt.Print(lnTable.String())
	}

	// Routes
	routes, err := client.ListRoutes(ctx)
	if err != nil && healthErr != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to retrieve routes: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nROUTES (%d)\n", len(routes))
	if len(routes) == 0 {
		fmt.Println("No routes registered.")
	} else {
		routeTable := NewTable("NAME", "LISTENER", "PROTO", "RULE / MATCH", "TARGETS", "STRATEGY", "EXPIRES IN")
		for _, r := range routes {
			ruleSummary := FormatRuleSummary(r.Rule)
			targetsSummary := FormatTargetsSummary(r.Handler)
			strategy := FormatStrategy(r.Handler)
			ttlRemaining := FormatTTLRemaining(time.Now(), r.TTL)

			routeTable.AddRow(r.Name, r.Listener, r.Protocol, ruleSummary, targetsSummary, strategy, ttlRemaining)
		}
		fmt.Print(routeTable.String())
	}
}
