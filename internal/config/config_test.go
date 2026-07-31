package config

import (
	"os"
	"path/filepath"
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

func TestServerConfigPathsPriority(t *testing.T) {
	tempXDG := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tempXDG)

	paths := serverConfigPaths()
	if len(paths) < 4 {
		t.Fatalf("expected at least 4 candidate paths, got %d", len(paths))
	}

	expectedUserPath := filepath.Join(tempXDG, "gateway", "server.yaml")
	if paths[0] != expectedUserPath {
		t.Errorf("expected first priority path to be user config %s, got %s", expectedUserPath, paths[0])
	}

	if paths[2] != "/etc/gateway/server.yaml" {
		t.Errorf("expected system path /etc/gateway/server.yaml at priority 2, got %s", paths[2])
	}
}

func TestLoadServerConfigUserModeVsSystemMode(t *testing.T) {
	tempXDG := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tempXDG)

	userConfigDir := filepath.Join(tempXDG, "gateway")
	if err := os.MkdirAll(userConfigDir, 0755); err != nil {
		t.Fatalf("failed to create user config dir: %v", err)
	}

	userConfigContent := `
api:
  listen: "127.0.0.1:8888"
database: "~/user_gateway.db"
`
	if err := os.WriteFile(filepath.Join(userConfigDir, "server.yaml"), []byte(userConfigContent), 0644); err != nil {
		t.Fatalf("failed to write user config file: %v", err)
	}

	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig failed in user mode: %v", err)
	}

	if cfg.Addr != "127.0.0.1:8888" {
		t.Errorf("expected Addr 127.0.0.1:8888 from user config, got %s", cfg.Addr)
	}
}

func TestDBPathUserVsEnvOverride(t *testing.T) {
	// 1. Env override takes highest priority
	tempDB := filepath.Join(t.TempDir(), "custom.db")
	t.Setenv("GATEWAY_DB", tempDB)

	if db := DBPath(); db != tempDB {
		t.Errorf("expected DBPath %s from env GATEWAY_DB, got %s", tempDB, db)
	}

	// 2. XDG_DATA_HOME in non-root user mode
	t.Setenv("GATEWAY_DB", "")
	tempDataDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDataDir)

	expectedUserDB := filepath.Join(tempDataDir, "gateway", "gateway.db")
	if os.Getuid() != 0 {
		if db := DBPath(); db != expectedUserDB {
			t.Errorf("expected DBPath %s in user mode, got %s", expectedUserDB, db)
		}
	}
}

func TestACMECacheDirResolution(t *testing.T) {
	tempXDG := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempXDG)

	expectedUserCache := filepath.Join(tempXDG, "gateway", "acme_certs")
	if os.Getuid() != 0 {
		if cache := ACMECacheDir(); cache != expectedUserCache {
			t.Errorf("expected ACMECacheDir %s in user mode, got %s", expectedUserCache, cache)
		}
	}
}
