package config

import (
	"testing"
)

func TestParseServerConfigData(t *testing.T) {
	yamlInput := `
api:
  listen: "127.0.0.1:9090"

database: "/var/lib/gateway/gateway.db"

public: false

firewall:
  driver: "auto"
  protected_ports:
    - 22
    - 9090

log:
  level: "info"
`

	cfg, err := parseServerConfigData([]byte(yamlInput))
	if err != nil {
		t.Fatalf("failed to parse server config YAML: %v", err)
	}

	if cfg.Addr != "127.0.0.1:9090" {
		t.Errorf("expected Addr 127.0.0.1:9090, got %s", cfg.Addr)
	}
	if cfg.DB != "/var/lib/gateway/gateway.db" {
		t.Errorf("expected DB /var/lib/gateway/gateway.db, got %s", cfg.DB)
	}
	if cfg.Firewall != "auto" {
		t.Errorf("expected Firewall auto, got %s", cfg.Firewall)
	}
	if len(cfg.ProtectedPorts) != 2 || cfg.ProtectedPorts[0] != "22" || cfg.ProtectedPorts[1] != "9090" {
		t.Errorf("expected ProtectedPorts [22 9090], got %v", cfg.ProtectedPorts)
	}
}
