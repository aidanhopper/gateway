package cli

import (
	"testing"
	"time"
)

func TestParseTTL(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"", 0, false},
		{"30s", 30 * time.Second, false},
		{"15m", 15 * time.Minute, false},
		{"2h", 2 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"3600", 3600 * time.Second, false},
		{"invalid", 0, true},
		{"-10s", 0, true},
		{"-1d", 0, true},
	}

	for _, tt := range tests {
		got, err := ParseTTL(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseTTL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.expected {
			t.Errorf("ParseTTL(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}
