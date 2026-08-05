package serve

import "time"

// HTTPOptions configures an HTTP serve mount.
type HTTPOptions struct {
	Mount      string        `json:"mount"`
	Target     string        `json:"target"`
	Priority   int           `json:"priority,omitempty"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Background bool          `json:"background,omitempty"`
	Yes        bool          `json:"yes,omitempty"`
}

// HTTPSOptions configures an HTTPS serve mount.
type HTTPSOptions struct {
	Mount       string        `json:"mount"`
	Target      string        `json:"target"`
	Priority    int           `json:"priority,omitempty"`
	NoRedirect  bool          `json:"no_redirect,omitempty"`
	StripPrefix bool          `json:"strip_prefix,omitempty"`
	Password    string        `json:"password,omitempty"`
	PIN         string        `json:"pin,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"`
	Background  bool          `json:"background,omitempty"`
	Yes         bool          `json:"yes,omitempty"`
}

// TCPOptions configures a TCP stream serve mount.
type TCPOptions struct {
	ListenPort string        `json:"listen_port"`
	Target     string        `json:"target"`
	Priority   int           `json:"priority,omitempty"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Background bool          `json:"background,omitempty"`
	Yes        bool          `json:"yes,omitempty"`
}

// UDPOptions configures a UDP stream serve mount.
type UDPOptions struct {
	ListenPort string        `json:"listen_port"`
	Target     string        `json:"target"`
	Priority   int           `json:"priority,omitempty"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Background bool          `json:"background,omitempty"`
	Yes        bool          `json:"yes,omitempty"`
}

// MinecraftOptions configures a Minecraft server serve mount.
type MinecraftOptions struct {
	Domain       string        `json:"domain,omitempty"`
	HostOrPort   string        `json:"host_or_port,omitempty"`
	Target       string        `json:"target,omitempty"`
	AllowPlayers []string      `json:"allow_players,omitempty"`
	DenyPlayers  []string      `json:"deny_players,omitempty"`
	Priority     int           `json:"priority,omitempty"`
	TTL          time.Duration `json:"ttl,omitempty"`
	Background   bool          `json:"background,omitempty"`
	Yes          bool          `json:"yes,omitempty"`
}

// RedirectOptions configures an HTTP/HTTPS redirect serve mount.
type RedirectOptions struct {
	Mount         string        `json:"mount"`
	TargetURL     string        `json:"target_url"`
	StatusCode    int           `json:"status_code,omitempty"`
	Exact         bool          `json:"exact,omitempty"`
	NoForwardPath bool          `json:"no_forward_path,omitempty"`
	NoQuery       bool          `json:"no_query,omitempty"`
	Priority      int           `json:"priority,omitempty"`
	TTL           time.Duration `json:"ttl,omitempty"`
	Background    bool          `json:"background,omitempty"`
	Yes           bool          `json:"yes,omitempty"`
}


// ServeMountSummary describes an active serve mount for status/list endpoints.
type ServeMountSummary struct {
	Name      string `json:"name"`
	Listener  string `json:"listener"`
	Protocol  string `json:"protocol"`
	Match     string `json:"match"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl,omitempty"`
	ExpiresIn string `json:"expires_in"`
}
