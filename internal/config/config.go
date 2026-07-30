package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// StringOrList is a YAML-flexible type that accepts either a scalar string or
// a sequence of strings. Both forms are equivalent; the value is stored as a
// slice and can be converted to a comma-separated string with String().
//
//	protected_ports: "22/tcp"
//	protected_ports: ["22/tcp", "2222/tcp"]
type StringOrList []string

// String returns the entries joined by commas, matching the format expected by
// firewall.Detect and the GATEWAY_PROTECTED_PORTS environment variable.
func (s StringOrList) String() string {
	return strings.Join(s, ",")
}

// UnmarshalYAML implements yaml.Unmarshaler for StringOrList.
func (s *StringOrList) UnmarshalYAML(value *yaml.Node) error {
	// Scalar string
	if value.Kind == yaml.ScalarNode {
		*s = StringOrList{value.Value}
		return nil
	}
	// Sequence of strings
	if value.Kind == yaml.SequenceNode {
		var items []string
		if err := value.Decode(&items); err != nil {
			return err
		}
		*s = StringOrList(items)
		return nil
	}
	return fmt.Errorf("protected_ports must be a string or list of strings")
}

// ServerConfig holds configuration for the gateway daemon process.
// It is read from ~/.config/gateway/server.yaml at startup. CLI flags and
// environment variables take precedence over file values.
type ServerConfig struct {
	Addr           string       `yaml:"addr"`
	DB             string       `yaml:"db"`
	Firewall       string       `yaml:"firewall"`
	ProtectedPorts StringOrList `yaml:"protected_ports"`
	Public         bool         `yaml:"public"`
}

// serverConfigPaths returns candidate paths for the server config file,
// in priority order (first found wins).
func serverConfigPaths() []string {
	paths := []string{
		"/etc/gateway/server.yaml",
		"/etc/gateway/server.yml",
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".config", "gateway", "server.yaml"),
			filepath.Join(home, ".config", "gateway", "server.yml"),
		)
	}
	return paths
}

// LoadServerConfigFromPath reads a server config file from a specific path
// and merges in environment variable overrides.
func LoadServerConfigFromPath(path string) (*ServerConfig, error) {
	if path == "" {
		return LoadServerConfig()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading server config %s: %w", path, err)
	}
	cfg := &ServerConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing server config %s: %w", path, err)
	}
	applyServerEnvOverrides(cfg)
	return cfg, nil
}

// LoadServerConfig reads the server config file and merges in environment
// variable overrides. Returns a zero-value ServerConfig (no error) if no
// config file exists.
func LoadServerConfig() (*ServerConfig, error) {
	cfg := &ServerConfig{}

	for _, p := range serverConfigPaths() {
		data, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading server config %s: %w", p, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing server config %s: %w", p, err)
		}
		break
	}

	applyServerEnvOverrides(cfg)
	return cfg, nil
}

func applyServerEnvOverrides(cfg *ServerConfig) {
	if v := os.Getenv("GATEWAY_ADDR"); v != "" {
		cfg.Addr = v
	}
	if v := os.Getenv("GATEWAY_DB"); v != "" {
		cfg.DB = v
	}
	if v := os.Getenv("GATEWAY_FIREWALL"); v != "" {
		cfg.Firewall = v
	}
	if v := os.Getenv("GATEWAY_PROTECTED_PORTS"); v != "" {
		cfg.ProtectedPorts = strings.Split(v, ",")
	}
	if v := os.Getenv("GATEWAY_PUBLIC"); v != "" {
		cfg.Public = strings.EqualFold(v, "true") || v == "1"
	}
}

// SiteProfile defines a named Gateway target server.
type SiteProfile struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token,omitempty"`
}

// Config holds all site profiles loaded from config.yaml.
// The config file is user-owned and never modified by the CLI.
type Config struct {
	Sites map[string]SiteProfile `yaml:"sites"`
}

// ConfigDir returns $XDG_CONFIG_HOME/gateway or ~/.config/gateway.
func ConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "gateway")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "gateway")
	}
	return filepath.Join(".", ".config", "gateway")
}

// DataDir returns $XDG_DATA_HOME/gateway or ~/.local/share/gateway.
func DataDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "gateway")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", "gateway")
	}
	return filepath.Join(".", ".local", "share", "gateway")
}

// StateDir returns $XDG_STATE_HOME/gateway or ~/.local/state/gateway.
func StateDir() string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "gateway")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "gateway")
	}
	return filepath.Join(".", ".local", "state", "gateway")
}

// DBPath returns the canonical path to the SQLite database.
func DBPath() string {
	if env := os.Getenv("GATEWAY_DB"); env != "" {
		return env
	}
	if os.Getuid() == 0 {
		return "/var/lib/gateway/gateway.db"
	}
	if fi, err := os.Stat("/var/lib/gateway"); err == nil && fi.IsDir() {
		return "/var/lib/gateway/gateway.db"
	}
	return filepath.Join(DataDir(), "gateway.db")
}

// ACMECacheDir returns the canonical path to the ACME certificate cache.
func ACMECacheDir() string {
	return filepath.Join(DataDir(), "acme_certs")
}

// activeSitePath returns the path to the active_site state file.
func activeSitePath() string {
	return filepath.Join(StateDir(), "active_site")
}

// LoadConfig reads and parses ~/.config/gateway/config.yaml (or config.yml).
// config.yaml takes precedence. Returns an empty Config (no error) if neither exists.
func LoadConfig() (*Config, error) {
	dir := ConfigDir()
	var data []byte
	var err error

	for _, name := range []string{"config.yaml", "config.yml"} {
		data, err = os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}
	if os.IsNotExist(err) {
		return &Config{Sites: map[string]SiteProfile{}}, nil
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.Sites == nil {
		cfg.Sites = map[string]SiteProfile{}
	}
	return &cfg, nil
}

// ReadActiveSite reads the current active site name from state.
// Returns ("", nil) if not set.
func ReadActiveSite() (string, error) {
	data, err := os.ReadFile(activeSitePath())
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading active site: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// WriteActiveSite writes the active site name to state.
func WriteActiveSite(name string) error {
	if err := os.MkdirAll(StateDir(), 0755); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}
	return os.WriteFile(activeSitePath(), []byte(name+"\n"), 0644)
}

// ResolveSite returns the SiteProfile to use, applying the priority order:
//  1. nameOverride (from --site flag or GATEWAY_SITE env var) -> config lookup.
//  2. GATEWAY_API_URL + GATEWAY_API_TOKEN env vars (CI/CD mode, no config needed).
//  3. active_site state file -> config lookup.
//  4. Default local daemon (http://127.0.0.1:9090, no auth).
func ResolveSite(cfg *Config, nameOverride string) (SiteProfile, error) {
	// 1. Explicit --site / GATEWAY_SITE
	name := nameOverride
	if name == "" {
		name = os.Getenv("GATEWAY_SITE")
	}
	if name != "" {
		profile, ok := cfg.Sites[name]
		if !ok {
			return SiteProfile{}, fmt.Errorf("site %q not found in ~/.config/gateway/config.yaml", name)
		}
		return profile, nil
	}

	// 2. GATEWAY_API_URL + GATEWAY_API_TOKEN (CI/CD mode)
	if apiURL := os.Getenv("GATEWAY_API_URL"); apiURL != "" {
		return SiteProfile{
			URL:   apiURL,
			Token: os.Getenv("GATEWAY_API_TOKEN"),
		}, nil
	}

	// 3. active_site state file
	activeName, err := ReadActiveSite()
	if err == nil && activeName != "" {
		profile, ok := cfg.Sites[activeName]
		if !ok {
			return SiteProfile{}, fmt.Errorf("active site %q not found in ~/.config/gateway/config.yaml", activeName)
		}
		return profile, nil
	}

	// 4. First site in config (alphabetical) if no active site is recorded
	if len(cfg.Sites) > 0 {
		names := make([]string, 0, len(cfg.Sites))
		for n := range cfg.Sites {
			names = append(names, n)
		}
		sort.Strings(names)
		return cfg.Sites[names[0]], nil
	}

	// 5. Default local daemon (no config at all)
	return SiteProfile{URL: "http://127.0.0.1:9090"}, nil
}

// ResolveSiteName returns the target site name resolved according to priority order.
func ResolveSiteName(cfg *Config, nameOverride string) string {
	name := nameOverride
	if name == "" {
		name = os.Getenv("GATEWAY_SITE")
	}
	if name != "" {
		return name
	}
	if os.Getenv("GATEWAY_API_URL") != "" {
		return "env"
	}
	activeName, err := ReadActiveSite()
	if err == nil && activeName != "" {
		return activeName
	}
	if cfg != nil && len(cfg.Sites) > 0 {
		names := make([]string, 0, len(cfg.Sites))
		for n := range cfg.Sites {
			names = append(names, n)
		}
		sort.Strings(names)
		return names[0]
	}
	return "default"
}
