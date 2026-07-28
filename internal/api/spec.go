package api

import "time"

// TLSConfigSpec defines TLS configuration options for a listener.
type TLSConfigSpec struct {
	Auto    bool     `json:"auto,omitempty"`    // Enable automatic ACME certificate management
	Domains []string `json:"domains,omitempty"` // Target domains for ACME auto-cert
	Cert    string   `json:"cert,omitempty"`    // Manual PEM certificate string
	Key     string   `json:"key,omitempty"`     // Manual PEM private key string
}

// ListenerSpec represents a network listener configuration.
type ListenerSpec struct {
	Name     string         `json:"name"`
	Address  string         `json:"address"`       // e.g. ":8080", "127.0.0.1:25565"
	Protocol string         `json:"protocol"`      // "tcp" or "udp"
	TTL      int            `json:"ttl,omitempty"` // optional lease duration in seconds (0 = permanent)
	TLS      *TLSConfigSpec `json:"tls,omitempty"` // optional TLS termination config
}

// HandlerSpec defines an inline handler specification inside a route.
// Handlers can optionally nest an inner handler via Next for pipeline composition.
type HandlerSpec struct {
	Type   string         `json:"type"`             // e.g. "tcp_proxy", "tcp_echo", "http_proxy", "http_static", "udp_echo"
	Config map[string]any `json:"config,omitempty"` // type-specific parameters (e.g. target address)
	Next   *HandlerSpec   `json:"next,omitempty"`   // optional nested inner handler for decorator/middleware handlers
}

// RuleSpec defines a single rule or a nested composite rule (and, or, not).
type RuleSpec struct {
	Type   string     `json:"type"`             // rule type string (e.g. "path_prefix", "host", "and", "or", "not", "is_minecraft")
	Value  string     `json:"value,omitempty"`  // single string value (path, host, header name, etc.)
	Values []string   `json:"values,omitempty"` // slice of string values (methods, players, hosts, header values, ports, etc.)
	Rules  []RuleSpec `json:"rules,omitempty"`  // child rules for "and" / "or"
	Rule   *RuleSpec  `json:"rule,omitempty"`   // child rule for "not"
}

// RouteSpec represents a full route specification.
type RouteSpec struct {
	Name     string      `json:"name"`
	Protocol string      `json:"protocol"` // "tcp", "http", or "udp"
	Listener string      `json:"listener"`
	Priority int         `json:"priority"`
	Rule     RuleSpec    `json:"rule"`
	Handler  HandlerSpec `json:"handler"`
	TTL      int         `json:"ttl,omitempty"` // optional lease duration in seconds (0 = permanent)
}

// MinecraftInfoSpec represents Minecraft protocol metadata in log events.
type MinecraftInfoSpec struct {
	RequestedHost   string `json:"requested_host,omitempty"`
	RequestedPort   uint16 `json:"requested_port,omitempty"`
	ProtocolState   int    `json:"protocol_state,omitempty"` // 1 = status ping, 2 = login
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	Username        string `json:"username,omitempty"`
	IsLoginStart    bool   `json:"is_login_start,omitempty"`
}

// LogEvent represents a request/connection log event streamed over the API.
type LogEvent struct {
	Timestamp     time.Time          `json:"timestamp"`
	Protocol      string             `json:"protocol"` // "http", "tcp", "udp", "minecraft"
	Route         string             `json:"route"`
	Listener      string             `json:"listener"`
	Method        string             `json:"method,omitempty"`
	Path          string             `json:"path,omitempty"`
	Status        int                `json:"status,omitempty"`
	DurationMs    int64              `json:"duration_ms"`
	RemoteIP      string             `json:"remote_ip"`
	Error         string             `json:"error,omitempty"`
	MinecraftInfo *MinecraftInfoSpec `json:"minecraft_info,omitempty"`
}

