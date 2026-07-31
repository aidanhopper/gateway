package firewall

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Manager defines the interface for managing OS firewall port rules.
type Manager interface {
	OpenPort(protocol string, port int) error
	ClosePort(protocol string, port int) error
}

// ParsePort extracts the port number from a listener address string (e.g. ":8080", "127.0.0.1:25565", "8080").
func ParsePort(address string) (int, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return 0, fmt.Errorf("empty address string")
	}

	// Case 1: Plain port number like "8080"
	if p, err := strconv.Atoi(address); err == nil && p > 0 && p <= 65535 {
		return p, nil
	}

	// Case 2: Host:Port like "127.0.0.1:8080" or ":8080"
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return 0, fmt.Errorf("invalid address format %q: %w", address, err)
	}

	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("invalid port number %q in address %q", portStr, address)
	}

	return p, nil
}

type protectedKey struct {
	protocol string
	port     int
}

// ParseProtectedPorts parses a comma-separated string of protected ports (e.g. "22/tcp,53/udp").
// Defaults to "22/tcp" if empty.
func ParseProtectedPorts(raw string) map[protectedKey]bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = os.Getenv("GATEWAY_PROTECTED_PORTS")
	}
	if strings.TrimSpace(raw) == "" {
		raw = "22/tcp"
	}

	protected := make(map[protectedKey]bool)
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		sub := strings.Split(part, "/")
		portStr := sub[0]
		proto := "tcp"
		if len(sub) > 1 {
			proto = strings.ToLower(strings.TrimSpace(sub[1]))
		}

		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			protected[protectedKey{protocol: proto, port: p}] = true
		}
	}
	return protected
}

// ProtectedManager wraps a Manager to prevent closing protected ports (e.g. SSH 22/tcp).
type ProtectedManager struct {
	target    Manager
	protected map[protectedKey]bool
}

// NewProtectedManager wraps target Manager with protected port enforcement.
func NewProtectedManager(target Manager, protectedStr string) *ProtectedManager {
	if target == nil {
		target = NewDryManager()
	}
	return &ProtectedManager{
		target:    target,
		protected: ParseProtectedPorts(protectedStr),
	}
}

// Logger is an optional callback to route firewall log events to system loggers.
var Logger func(level, format string, args ...any)

func logFirewall(level, format string, args ...any) {
	if Logger != nil {
		Logger(level, format, args...)
		return
	}
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	cleanLvl := strings.ToUpper(strings.TrimSpace(level))
	lvlPadded := fmt.Sprintf("%-5s", cleanLvl)
	compPadded := fmt.Sprintf("%-8s", "FIREWALL")
	msg := fmt.Sprintf(format, args...)
	out := os.Stdout
	if cleanLvl == "ERROR" {
		out = os.Stderr
	}
	fmt.Fprintf(out, "[%s] [%s] [%s] %s\n", timeStr, lvlPadded, compPadded, msg)
}

func (pm *ProtectedManager) OpenPort(protocol string, port int) error {
	return pm.target.OpenPort(protocol, port)
}

func (pm *ProtectedManager) ClosePort(protocol string, port int) error {
	protocol = strings.ToLower(protocol)
	if pm.protected[protectedKey{protocol: protocol, port: port}] {
		logFirewall("WARN", "refusing to close protected port %s/%d (protected by GATEWAY_PROTECTED_PORTS)", protocol, port)
		return fmt.Errorf("refusing to close protected port %s/%d (protected by GATEWAY_PROTECTED_PORTS)", protocol, port)
	}
	return pm.target.ClosePort(protocol, port)
}

// DryManager simulates firewall port opening/closing by logging without modifying the OS.
type DryManager struct {
	Logger *log.Logger
}

// NewDryManager creates a new DryManager instance.
func NewDryManager() *DryManager {
	return &DryManager{}
}

func (m *DryManager) OpenPort(protocol string, port int) error {
	msg := fmt.Sprintf("[FIREWALL DRY] Would open %s port %d", strings.ToLower(protocol), port)
	if m.Logger != nil {
		m.Logger.Println(msg)
	} else {
		logFirewall("INFO", "dry run: would open %s port %d", strings.ToLower(protocol), port)
	}
	return nil
}

func (m *DryManager) ClosePort(protocol string, port int) error {
	msg := fmt.Sprintf("[FIREWALL DRY] Would close %s port %d", strings.ToLower(protocol), port)
	if m.Logger != nil {
		m.Logger.Println(msg)
	} else {
		logFirewall("INFO", "dry run: would close %s port %d", strings.ToLower(protocol), port)
	}
	return nil
}

// NoopManager silently does nothing for firewall operations (useful in tests).
type NoopManager struct{}

// NewNoopManager creates a new NoopManager instance.
func NewNoopManager() *NoopManager {
	return &NoopManager{}
}

func (m *NoopManager) OpenPort(protocol string, port int) error  { return nil }
func (m *NoopManager) ClosePort(protocol string, port int) error { return nil }

// Detect resolves a FirewallManager based on driver name or OS environment, wrapped in ProtectedManager.
func Detect(driver string, protectedPorts string) Manager {
	var base Manager
	drvName := strings.ToLower(strings.TrimSpace(driver))
	if drvName == "" {
		drvName = "auto"
	}

	switch drvName {
	case "dry":
		base = NewDryManager()
	case "none", "noop":
		base = NewNoopManager()
	case "ufw":
		base = NewUFWManager()
	case "firewalld":
		base = NewFirewalldManager()
	case "iptables":
		base = NewIPTablesManager()
	case "nftables":
		base = NewNFTablesManager()
	case "auto":
		base = NewDryManager()
	default:
		base = NewDryManager()
	}

	logFirewall("INFO", "detected host firewall driver: %s", drvName)
	return NewProtectedManager(base, protectedPorts)
}
