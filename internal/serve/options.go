package serve

import "time"

// HTTPOptions configures an HTTP serve mount.
type HTTPOptions struct {
	Mount      string        `json:"mount"`
	Target     string        `json:"target"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Background bool          `json:"background,omitempty"`
	Yes        bool          `json:"yes,omitempty"`
}

// HTTPSOptions configures an HTTPS serve mount.
type HTTPSOptions struct {
	Mount       string        `json:"mount"`
	Target      string        `json:"target"`
	ListenAddr  string        `json:"listen_addr,omitempty"`
	ACME        bool          `json:"acme,omitempty"`
	NoRedirect  bool          `json:"no_redirect,omitempty"`
	StripPrefix bool          `json:"strip_prefix,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"`
	Background  bool          `json:"background,omitempty"`
	Yes         bool          `json:"yes,omitempty"`
}

// TCPOptions configures a TCP stream serve mount.
type TCPOptions struct {
	ListenPort string        `json:"listen_port"`
	Target     string        `json:"target"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Background bool          `json:"background,omitempty"`
	Yes        bool          `json:"yes,omitempty"`
}

// UDPOptions configures a UDP stream serve mount.
type UDPOptions struct {
	ListenPort string        `json:"listen_port"`
	Target     string        `json:"target"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Background bool          `json:"background,omitempty"`
	Yes        bool          `json:"yes,omitempty"`
}

// MinecraftOptions configures a Minecraft server serve mount.
type MinecraftOptions struct {
	HostOrPort string        `json:"host_or_port"`
	Target     string        `json:"target,omitempty"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Background bool          `json:"background,omitempty"`
	Yes        bool          `json:"yes,omitempty"`
}

// DirOptions configures a static directory, file, or SPA serve mount.
type DirOptions struct {
	Mount         string        `json:"mount"`
	LocalPath     string        `json:"local_path"`
	IsSPA         bool          `json:"is_spa,omitempty"`
	IsFile        bool          `json:"is_file,omitempty"`
	IsHTTP        bool          `json:"is_http,omitempty"`
	Index         string        `json:"index,omitempty"`
	Browse        bool          `json:"browse,omitempty"`
	ListenAddr    string        `json:"listen_addr,omitempty"`
	ListenerName  string        `json:"listener_name,omitempty"`
	Domain        string        `json:"domain,omitempty"`
	ACME          bool          `json:"acme,omitempty"`
	CertFile      string        `json:"cert_file,omitempty"`
	KeyFile       string        `json:"key_file,omitempty"`
	StripPrefix   string        `json:"strip_prefix,omitempty"`
	NoStripPrefix bool          `json:"no_strip_prefix,omitempty"`
	NoRedirect    bool          `json:"no_redirect,omitempty"`
	TTL           time.Duration `json:"ttl,omitempty"`
	Background    bool          `json:"background,omitempty"`
	Yes           bool          `json:"yes,omitempty"`
}

// RedirectOptions configures an HTTP/HTTPS redirect serve mount.
type RedirectOptions struct {
	Mount      string        `json:"mount"`
	TargetURL  string        `json:"target_url"`
	StatusCode int           `json:"status_code,omitempty"`
	TTL        time.Duration `json:"ttl,omitempty"`
	Background bool          `json:"background,omitempty"`
	Yes        bool          `json:"yes,omitempty"`
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
