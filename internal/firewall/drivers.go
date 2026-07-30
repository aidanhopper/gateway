package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// CommandExecutor abstracts command execution for testability.
type CommandExecutor func(name string, args ...string) ([]byte, error)

func defaultExec(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

// OSCommandManager implements Manager using OS system commands.
type OSCommandManager struct {
	Name     string
	OpenCmd  func(protocol string, port int) (string, []string)
	CloseCmd func(protocol string, port int) (string, []string)
	Exec     CommandExecutor
}

func (m *OSCommandManager) OpenPort(protocol string, port int) error {
	protocol = strings.ToLower(protocol)
	bin, args := m.OpenCmd(protocol, port)
	execFn := m.Exec
	if execFn == nil {
		execFn = defaultExec
	}

	out, err := execFn(bin, args...)
	if err != nil {
		logFirewall("ERROR", "%s open port %s/%d failed: %v (output: %s)", strings.ToUpper(m.Name), protocol, port, err, string(out))
		return fmt.Errorf("%s open port %s/%d failed: %v (output: %s)", m.Name, protocol, port, err, string(out))
	}

	logFirewall("INFO", "%s opened %s port %d", strings.ToUpper(m.Name), protocol, port)
	return nil
}

func (m *OSCommandManager) ClosePort(protocol string, port int) error {
	protocol = strings.ToLower(protocol)
	bin, args := m.CloseCmd(protocol, port)
	execFn := m.Exec
	if execFn == nil {
		execFn = defaultExec
	}

	out, err := execFn(bin, args...)
	if err != nil {
		logFirewall("ERROR", "%s close port %s/%d failed: %v (output: %s)", strings.ToUpper(m.Name), protocol, port, err, string(out))
		return fmt.Errorf("%s close port %s/%d failed: %v (output: %s)", m.Name, protocol, port, err, string(out))
	}

	logFirewall("INFO", "%s closed %s port %d", strings.ToUpper(m.Name), protocol, port)
	return nil
}

// NewUFWManager creates a Manager for UFW (Uncomplicated Firewall).
func NewUFWManager() *OSCommandManager {
	return &OSCommandManager{
		Name: "ufw",
		OpenCmd: func(protocol string, port int) (string, []string) {
			return "ufw", []string{"allow", fmt.Sprintf("%d/%s", port, strings.ToLower(protocol))}
		},
		CloseCmd: func(protocol string, port int) (string, []string) {
			return "ufw", []string{"delete", "allow", fmt.Sprintf("%d/%s", port, strings.ToLower(protocol))}
		},
	}
}

// NewFirewalldManager creates a Manager for firewalld.
func NewFirewalldManager() *OSCommandManager {
	return &OSCommandManager{
		Name: "firewalld",
		OpenCmd: func(protocol string, port int) (string, []string) {
			return "firewall-cmd", []string{"--add-port=" + fmt.Sprintf("%d/%s", port, strings.ToLower(protocol))}
		},
		CloseCmd: func(protocol string, port int) (string, []string) {
			return "firewall-cmd", []string{"--remove-port=" + fmt.Sprintf("%d/%s", port, strings.ToLower(protocol))}
		},
	}
}

// NewIPTablesManager creates a Manager for iptables.
func NewIPTablesManager() *OSCommandManager {
	return &OSCommandManager{
		Name: "iptables",
		OpenCmd: func(protocol string, port int) (string, []string) {
			return "iptables", []string{"-A", "INPUT", "-p", strings.ToLower(protocol), "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"}
		},
		CloseCmd: func(protocol string, port int) (string, []string) {
			return "iptables", []string{"-D", "INPUT", "-p", strings.ToLower(protocol), "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"}
		},
	}
}

// NewNFTablesManager creates a Manager for nftables CLI.
func NewNFTablesManager() *OSCommandManager {
	return &OSCommandManager{
		Name: "nftables",
		OpenCmd: func(protocol string, port int) (string, []string) {
			return "nft", []string{"add", "rule", "inet", "filter", "input", strings.ToLower(protocol), "dport", fmt.Sprintf("%d", port), "accept"}
		},
		CloseCmd: func(protocol string, port int) (string, []string) {
			return "nft", []string{"delete", "rule", "inet", "filter", "input", strings.ToLower(protocol), "dport", fmt.Sprintf("%d", port), "accept"}
		},
	}
}
