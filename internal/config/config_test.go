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

func TestServerConfigTildeExpansion(t *testing.T) {
	yamlInput := `
database: "~/.local/share/gateway/gateway.db"
`
	cfg, err := parseServerConfigData([]byte(yamlInput))
	if err != nil {
		t.Fatalf("failed to parse server config with tilde: %v", err)
	}

	if cfg.DB == "~/.local/share/gateway/gateway.db" {
		t.Errorf("expected tilde in database path to be expanded, got raw: %s", cfg.DB)
	}
}

func TestResolveSiteTokenPriority(t *testing.T) {
	t.Setenv("GATEWAY_API_URL", "http://127.0.0.1:9999")
	t.Setenv("GATEWAY_API_TOKEN", "gw_testtoken123")

	cfg := &Config{Sites: map[string]SiteProfile{
		"local": {URL: "http://127.0.0.1:9090", Token: "gw_configtoken"},
	}}

	profile, err := ResolveSite(cfg, "")
	if err != nil {
		t.Fatalf("ResolveSite failed: %v", err)
	}

	if profile.URL != "http://127.0.0.1:9999" {
		t.Errorf("expected URL http://127.0.0.1:9999 from env, got %s", profile.URL)
	}
	if profile.Token != "gw_testtoken123" {
		t.Errorf("expected Token gw_testtoken123 from env, got %s", profile.Token)
	}
}
