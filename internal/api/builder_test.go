package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aidanhopper/gateway/internal/gateway"
)

func TestValidateAndBuildHandlers(t *testing.T) {
	t.Run("TCP Handlers", func(t *testing.T) {
		h, err := buildHandler("tcp", HandlerSpec{Type: "tcp_echo"})
		if err != nil {
			t.Fatalf("buildHandler tcp_echo failed: %v", err)
		}
		if _, ok := h.(gateway.TCPHandler); !ok {
			t.Errorf("expected TCPHandler interface")
		}

		h, err = buildHandler("tcp", HandlerSpec{Type: "tcp_proxy", Config: map[string]any{"target": "127.0.0.1:25565"}})
		if err != nil {
			t.Fatalf("buildHandler tcp_proxy failed: %v", err)
		}
		if _, ok := h.(gateway.TCPHandler); !ok {
			t.Errorf("expected TCPHandler interface")
		}

		if _, err := buildHandler("tcp", HandlerSpec{Type: "tcp_proxy"}); err == nil {
			t.Errorf("expected error for missing target")
		}

		if _, err := buildHandler("tcp", HandlerSpec{Type: "http_proxy"}); err == nil {
			t.Errorf("expected mismatch protocol error")
		}
	})

	t.Run("HTTP Handlers", func(t *testing.T) {
		h, err := buildHandler("http", HandlerSpec{Type: "http_proxy", Config: map[string]any{"target": "http://127.0.0.1:8080"}})
		if err != nil {
			t.Fatalf("buildHandler http_proxy failed: %v", err)
		}
		if _, ok := h.(http.Handler); !ok {
			t.Errorf("expected http.Handler interface")
		}

		hRedirect, err := buildHandler("http", HandlerSpec{Type: "http_redirect", Config: map[string]any{"status": 301, "url": "https://example.com"}})
		if err != nil {
			t.Fatalf("buildHandler http_redirect failed: %v", err)
		}
		handler, ok := hRedirect.(http.Handler)
		if !ok {
			t.Fatalf("expected http.Handler")
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		handler.ServeHTTP(rec, req)

		if rec.Code != 301 || rec.Header().Get("Location") != "https://example.com/" {
			t.Errorf("got status %d header %q, want 301 https://example.com/", rec.Code, rec.Header().Get("Location"))
		}
	})

	t.Run("UDP Handlers", func(t *testing.T) {
		h, err := buildHandler("udp", HandlerSpec{Type: "udp_echo"})
		if err != nil {
			t.Fatalf("buildHandler udp_echo failed: %v", err)
		}
		if _, ok := h.(gateway.UDPHandler); !ok {
			t.Errorf("expected UDPHandler interface")
		}
	})
}

func TestBuildRules(t *testing.T) {
	t.Run("HTTP Rules", func(t *testing.T) {
		r, err := buildRule("http", RuleSpec{
			Type: "and",
			Rules: []RuleSpec{
				{Type: "path_prefix", Value: "/api"},
				{Type: "method", Value: "GET"},
			},
		})
		if err != nil {
			t.Fatalf("buildRule HTTP failed: %v", err)
		}

		httpRule, ok := r.(gateway.HTTPRule)
		if !ok {
			t.Fatalf("expected HTTPRule interface")
		}

		reqMatch := httptest.NewRequest("GET", "/api/v1/users", nil)
		if !httpRule.Match(reqMatch) {
			t.Errorf("expected rule to match GET /api/v1/users")
		}

		reqMismatch := httptest.NewRequest("POST", "/api/v1/users", nil)
		if httpRule.Match(reqMismatch) {
			t.Errorf("expected rule to not match POST /api/v1/users")
		}
	})

	t.Run("TCP Rules", func(t *testing.T) {
		r, err := buildRule("tcp", RuleSpec{
			Type: "and",
			Rules: []RuleSpec{
				{Type: "is_minecraft"},
				{Type: "minecraft_host", Value: "survival.example.com"},
			},
		})
		if err != nil {
			t.Fatalf("buildRule TCP failed: %v", err)
		}
		if _, ok := r.(gateway.TCPRule); !ok {
			t.Errorf("expected TCPRule interface")
		}
	})

	t.Run("Invalid Rule Type", func(t *testing.T) {
		if _, err := buildRule("http", RuleSpec{Type: "non_existent_rule"}); err == nil {
			t.Errorf("expected error for non-existent rule type")
		}
	})
}
