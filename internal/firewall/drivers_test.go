package firewall

import (
	"fmt"
	"strings"
	"testing"
)

func TestOSCommandManagers(t *testing.T) {
	var lastCmd string
	var lastArgs []string

	mockExec := func(name string, args ...string) ([]byte, error) {
		lastCmd = name
		lastArgs = args
		return []byte("ok"), nil
	}

	ufw := NewUFWManager()
	ufw.Exec = mockExec

	if err := ufw.OpenPort("tcp", 8080); err != nil {
		t.Fatalf("UFW OpenPort failed: %v", err)
	}
	if lastCmd != "ufw" || strings.Join(lastArgs, " ") != "allow 8080/tcp" {
		t.Errorf("got %s %v, want ufw allow 8080/tcp", lastCmd, lastArgs)
	}

	firewalld := NewFirewalldManager()
	firewalld.Exec = mockExec
	if err := firewalld.OpenPort("udp", 9000); err != nil {
		t.Fatalf("Firewalld OpenPort failed: %v", err)
	}
	if lastCmd != "firewall-cmd" || strings.Join(lastArgs, " ") != "--add-port=9000/udp" {
		t.Errorf("got %s %v, want firewall-cmd --add-port=9000/udp", lastCmd, lastArgs)
	}

	iptables := NewIPTablesManager()
	iptables.Exec = mockExec
	if err := iptables.OpenPort("tcp", 443); err != nil {
		t.Fatalf("IPTables OpenPort failed: %v", err)
	}
	if lastCmd != "iptables" || strings.Join(lastArgs, " ") != "-A INPUT -p tcp --dport 443 -j ACCEPT" {
		t.Errorf("got %s %v, want iptables command", lastCmd, lastArgs)
	}
}

func TestOSCommandManagerErrorHandling(t *testing.T) {
	failExec := func(name string, args ...string) ([]byte, error) {
		return []byte("permission denied"), fmt.Errorf("exit code 1")
	}

	ufw := NewUFWManager()
	ufw.Exec = failExec

	if err := ufw.OpenPort("tcp", 8080); err == nil {
		t.Errorf("expected error on command failure")
	}
}
