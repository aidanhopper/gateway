package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFormatRuleSummary(t *testing.T) {
	tests := []struct {
		rule     RuleSpec
		expected string
	}{
		{RuleSpec{Type: "any"}, "/*"},
		{RuleSpec{Type: "host", Value: "example.com"}, "example.com"},
		{RuleSpec{Type: "path", Value: "/api"}, "/api"},
		{RuleSpec{Type: "path_prefix", Value: "/docs"}, "/docs"},
	}

	for _, tt := range tests {
		got := FormatRuleSummary(tt.rule)
		if got != tt.expected {
			t.Errorf("FormatRuleSummary(%+v) = %q, want %q", tt.rule, got, tt.expected)
		}
	}
}

func TestFormatTTLRemaining(t *testing.T) {
	tests := []struct {
		ttl      int
		expected string
	}{
		{0, "never"},
		{-1, "never"},
	}

	for _, tt := range tests {
		got := FormatTTLRemaining(time.Now(), tt.ttl)
		if got != tt.expected {
			t.Errorf("FormatTTLRemaining(%d) = %q, want %q", tt.ttl, got, tt.expected)
		}
	}
}

func TestParseMountArg(t *testing.T) {
	domain, path := parseMountArg("https://example.com/api")
	if domain != "example.com" || path != "/api" {
		t.Errorf("parseMountArg failed: got domain=%q path=%q", domain, path)
	}
}

func TestServeRequestJSONSerialization(t *testing.T) {
	req := ServeRequestHTTP{
		Mount:  "/",
		Target: "3000",
		TTL:    3600,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ServeRequestHTTP
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Mount != "/" || decoded.Target != "3000" || decoded.TTL != 3600 {
		t.Errorf("decoded mismatch: %+v", decoded)
	}
}
