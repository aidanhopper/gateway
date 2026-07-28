package cli

import (
	"context"
	"fmt"
	"log"
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
func RunStatus(apiAddr, token, dbPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client := NewClient(apiAddr, token, dbPath)

	_, healthErr := client.Health(ctx)
	daemonStatus := "Running"
	if healthErr != nil {
		daemonStatus = "Offline / Unreachable"
	}

	fwDriver := os.Getenv("GATEWAY_FIREWALL")
	if fwDriver == "" {
		fwDriver = "auto"
	}

	fmt.Println("=========================================================================================")
	fmt.Printf("Gateway Daemon Status: %s\n", daemonStatus)
	fmt.Printf("API Address:           %s\n", client.BaseURL)
	fmt.Printf("Database Path:         %s\n", client.DBPath)
	fmt.Printf("Firewall Driver:       %s\n", fwDriver)
	fmt.Println("=========================================================================================")

	// Listeners
	listeners, err := client.ListListeners(ctx)
	if err != nil && healthErr != nil {
		log.Fatalf("failed to retrieve status: %v", err)
	}

	fmt.Printf("\nLISTENERS (%d)\n", len(listeners))
	if len(listeners) == 0 {
		fmt.Println("No listeners registered.")
	} else {
		fmt.Printf("%-20s %-20s %-10s %-10s\n", "NAME", "ADDRESS", "PROTOCOL", "STATUS")
		fmt.Println("-----------------------------------------------------------------------------------------")
		for _, ln := range listeners {
			status := "ACTIVE"
			if healthErr != nil {
				status = "OFFLINE"
			}
			fmt.Printf("%-20s %-20s %-10s %-10s\n", ln.Name, ln.Address, ln.Protocol, status)
		}
	}

	// Routes
	routes, err := client.ListRoutes(ctx)
	if err != nil && healthErr != nil {
		log.Fatalf("failed to retrieve routes: %v", err)
	}

	fmt.Printf("\nROUTES (%d)\n", len(routes))
	if len(routes) == 0 {
		fmt.Println("No routes registered.")
	} else {
		fmt.Printf("%-18s %-12s %-8s %-25s %-20s %-12s %-12s\n", "NAME", "LISTENER", "PROTO", "RULE / MATCH", "TARGETS", "STRATEGY", "EXPIRES IN")
		fmt.Println("---------------------------------------------------------------------------------------------------")
		for _, r := range routes {
			ruleSummary := FormatRuleSummary(r.Rule)
			targetsSummary := FormatTargetsSummary(r.Handler)
			strategy := FormatStrategy(r.Handler)
			ttlRemaining := FormatTTLRemaining(time.Now(), r.TTL) // fallback display

			fmt.Printf("%-18s %-12s %-8s %-25s %-20s %-12s %-12s\n",
				r.Name, r.Listener, r.Protocol, ruleSummary, targetsSummary, strategy, ttlRemaining)
		}
	}
	fmt.Println()
}
