package gateway

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"
)

func TestGenericRuleCombinators(t *testing.T) {
	alwaysTrue := RuleFunc[int](func(v int) bool { return true })
	alwaysFalse := RuleFunc[int](func(v int) bool { return false })
	isEven := RuleFunc[int](func(v int) bool { return v%2 == 0 })
	isPositive := RuleFunc[int](func(v int) bool { return v > 0 })

	t.Run("Any", func(t *testing.T) {
		rule := Any[int]()
		if !rule.Match(42) || !rule.Match(-1) {
			t.Errorf("Any() should always return true")
		}
	})

	t.Run("And", func(t *testing.T) {
		tests := []struct {
			name  string
			rules []Rule[int]
			val   int
			want  bool
		}{
			{"all true", []Rule[int]{isEven, isPositive}, 4, true},
			{"one false (odd)", []Rule[int]{isEven, isPositive}, 3, false},
			{"one false (negative)", []Rule[int]{isEven, isPositive}, -2, false},
			{"empty rules", []Rule[int]{}, 4, true},
			{"always false", []Rule[int]{alwaysTrue, alwaysFalse}, 4, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				rule := And(tt.rules...)
				if got := rule.Match(tt.val); got != tt.want {
					t.Errorf("And() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("Or", func(t *testing.T) {
		tests := []struct {
			name  string
			rules []Rule[int]
			val   int
			want  bool
		}{
			{"both true", []Rule[int]{isEven, isPositive}, 4, true},
			{"one true (even)", []Rule[int]{isEven, isPositive}, -2, true},
			{"one true (positive)", []Rule[int]{isEven, isPositive}, 3, true},
			{"both false", []Rule[int]{isEven, isPositive}, -3, false},
			{"empty rules", []Rule[int]{}, 4, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				rule := Or(tt.rules...)
				if got := rule.Match(tt.val); got != tt.want {
					t.Errorf("Or() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("Not", func(t *testing.T) {
		notEven := Not(isEven)
		if notEven.Match(4) {
			t.Errorf("Not(isEven) matched even number 4")
		}
		if !notEven.Match(3) {
			t.Errorf("Not(isEven) failed odd number 3")
		}
	})
}

func TestHTTPRules(t *testing.T) {
	reqURL, _ := url.Parse("https://example.com/api/v1/users?token=secret&role=admin")
	header := make(http.Header)
	header.Set("X-API-Key", "key123")
	header.Set("Content-Type", "application/json")

	req := &http.Request{
		Method:     "POST",
		Host:       "example.com",
		URL:        reqURL,
		Header:     header,
		RemoteAddr: "192.168.1.50:12345",
		TLS:        &tls.ConnectionState{},
	}

	t.Run("Combinator Helpers", func(t *testing.T) {
		if !AnyHTTP().Match(req) {
			t.Errorf("AnyHTTP should match")
		}
		if !AndHTTP().Match(req) {
			t.Errorf("AndHTTP with empty rules should match")
		}
		if OrHTTP().Match(req) {
			t.Errorf("OrHTTP with empty rules should not match")
		}
	})

	tests := []struct {
		name string
		rule HTTPRule
		want bool
	}{
		{"Host match", Host("example.com"), true},
		{"Host mismatch", Host("other.com"), false},
		{"HostPrefix match", HostPrefix("example"), true},
		{"HostPrefix mismatch", HostPrefix("other"), false},
		{"Path match", Path("/api/v1/users"), true},
		{"Path mismatch", Path("/api/v1"), false},
		{"PathPrefix match", PathPrefix("/api/"), true},
		{"PathPrefix mismatch", PathPrefix("/v2/"), false},
		{"Method match single", Method("POST"), true},
		{"Method match multiple", Method("GET", "POST", "PUT"), true},
		{"Method mismatch", Method("GET", "DELETE"), false},
		{"Header match", Header("X-API-Key", "key123"), true},
		{"Header value mismatch", Header("X-API-Key", "wrong"), false},
		{"HeaderExists true", HeaderExists("X-Api-Key"), true},
		{"HeaderExists false", HeaderExists("Authorization"), false},
		{"QueryParam match", QueryParam("token", "secret"), true},
		{"QueryParam mismatch", QueryParam("token", "invalid"), false},
		{"QueryParam missing", QueryParam("unknown", "val"), false},
		{"Secure true", Secure(), true},
		{"Scheme match", Scheme("https"), true},
		{"Scheme mismatch", Scheme("http"), false},
		{"RemoteIP match", RemoteIP("192.168.1.50"), true},
		{"RemoteIP mismatch", RemoteIP("10.0.0.1"), false},
		{"RemoteIP invalid addr format", RemoteIP("192.168.1.50"), func() bool {
			invalidReq := &http.Request{RemoteAddr: "invalid-host-port"}
			return !RemoteIP("192.168.1.50").Match(invalidReq)
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.Match(req); got != tt.want {
				t.Errorf("HTTP Rule match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSNIRule(t *testing.T) {
	metaExact := TCPMetadata{TLS: &TLSInfo{SNI: "vault.example.com"}}
	metaSub := TCPMetadata{TLS: &TLSInfo{SNI: "api.internal.net"}}
	metaNoTLS := TCPMetadata{TLS: nil}

	if !SNI("vault.example.com").Match(metaExact) {
		t.Errorf("SNI exact match failed")
	}
	if SNI("other.example.com").Match(metaExact) {
		t.Errorf("SNI exact mismatch failed")
	}
	if !SNI("*.internal.net").Match(metaSub) {
		t.Errorf("SNI wildcard match failed")
	}
	if SNI("vault.example.com").Match(metaNoTLS) {
		t.Errorf("SNI should not match connection without TLS")
	}
}

func TestTCPAndMinecraftRules(t *testing.T) {
	mcInfo := &MinecraftInfo{
		RequestedHost:   "mc.example.com",
		RequestedPort:   25565,
		ProtocolState:   1, // Status
		ProtocolVersion: 754,
		Username:        "Steve",
		IsLoginStart:    true,
	}

	t.Run("NotTLS and NotHTTP", func(t *testing.T) {
		metaNoTLS := TCPMetadata{TLS: nil, IsHTTP: false}
		metaTLS := TCPMetadata{TLS: &TLSInfo{SNI: "example.com"}, IsHTTP: true}

		if !NotTLS().Match(metaNoTLS) {
			t.Errorf("NotTLS should match meta without TLS")
		}
		if NotTLS().Match(metaTLS) {
			t.Errorf("NotTLS should not match meta with TLS")
		}
		if !NotHTTP().Match(metaNoTLS) {
			t.Errorf("NotHTTP should match non-HTTP meta")
		}
		if NotHTTP().Match(metaTLS) {
			t.Errorf("NotHTTP should not match HTTP meta")
		}
	})

	t.Run("Minecraft rules with nil MinecraftInfo", func(t *testing.T) {
		emptyMeta := TCPMetadata{Minecraft: nil}

		if IsMinecraft().Match(emptyMeta) {
			t.Errorf("IsMinecraft matched empty meta")
		}
		if !NotMinecraft().Match(emptyMeta) {
			t.Errorf("NotMinecraft failed on empty meta")
		}
		if MinecraftHost("mc.example.com").Match(emptyMeta) {
			t.Errorf("MinecraftHost matched empty meta")
		}
		if MinecraftVersion(754).Match(emptyMeta) {
			t.Errorf("MinecraftVersion matched empty meta")
		}
		if MinecraftLogin().Match(emptyMeta) {
			t.Errorf("MinecraftLogin matched empty meta")
		}
		if MinecraftStatus().Match(emptyMeta) {
			t.Errorf("MinecraftStatus matched empty meta")
		}
		if MinecraftLoginState().Match(emptyMeta) {
			t.Errorf("MinecraftLoginState matched empty meta")
		}
		if MinecraftRequestedPort(25565).Match(emptyMeta) {
			t.Errorf("MinecraftRequestedPort matched empty meta")
		}
		if MinecraftNotPlayer("Steve").Match(emptyMeta) {
			t.Errorf("MinecraftNotPlayer matched empty meta")
		}
	})

	t.Run("Minecraft rules with valid MinecraftInfo", func(t *testing.T) {
		meta := TCPMetadata{Minecraft: mcInfo}

		tests := []struct {
			name string
			rule TCPRule
			want bool
		}{
			{"IsMinecraft", IsMinecraft(), true},
			{"NotMinecraft", NotMinecraft(), false},
			{"MinecraftHost match", MinecraftHost("mc.example.com", "other.com"), true},
			{"MinecraftHost mismatch", MinecraftHost("other.com"), false},
			{"MinecraftVersion match", MinecraftVersion(754, 755), true},
			{"MinecraftVersion mismatch", MinecraftVersion(100), false},
			{"MinecraftLogin match", MinecraftLogin(), true},
			{"MinecraftStatus match", MinecraftStatus(), true},
			{"MinecraftLoginState mismatch", MinecraftLoginState(), false},
			{"MinecraftPlayer match", MinecraftPlayer("Steve", "Alex"), true},
			{"MinecraftPlayer mismatch", MinecraftPlayer("Alex"), false},
			{"MinecraftNotPlayer match", MinecraftNotPlayer("Alex"), true},
			{"MinecraftNotPlayer mismatch", MinecraftNotPlayer("Steve"), false},
			{"MinecraftRequestedPort match", MinecraftRequestedPort(25565, 25566), true},
			{"MinecraftRequestedPort mismatch", MinecraftRequestedPort(8080), false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := tt.rule.Match(meta); got != tt.want {
					t.Errorf("Minecraft Rule match = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("MinecraftPlayer and MinecraftNotPlayer when IsLoginStart is false", func(t *testing.T) {
		nonLoginMC := &MinecraftInfo{
			RequestedHost: "mc.example.com",
			Username:      "",
			IsLoginStart:  false,
		}
		meta := TCPMetadata{Minecraft: nonLoginMC}

		if !MinecraftPlayer("Steve").Match(meta) {
			t.Errorf("MinecraftPlayer should return true when IsLoginStart is false")
		}
		if !MinecraftNotPlayer("Steve").Match(meta) {
			t.Errorf("MinecraftNotPlayer should return true when IsLoginStart is false")
		}
	})
}
