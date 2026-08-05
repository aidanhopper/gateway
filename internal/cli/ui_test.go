package cli

import (
	"strings"
	"testing"
)

func TestTableDynamicSpacing(t *testing.T) {
	SetColorEnabled(false)
	defer ResetColorMode()

	tbl := NewTable("NAME", "LISTENER", "PROTO", "STATUS")
	tbl.AddRow("serve-redirect-https-1", "serve-https-443", "tcp", "[ACTIVE]")
	tbl.AddRow("short", "ln", "udp", "[OFFLINE]")

	output := tbl.String()

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines (header, divider, 2 rows), got %d", len(lines))
	}

	headerLine := lines[0]
	if !strings.HasPrefix(headerLine, "NAME") || !strings.Contains(headerLine, "LISTENER") {
		t.Errorf("unexpected header line: %q", headerLine)
	}

	dividerLine := lines[1]
	if !strings.HasPrefix(dividerLine, "-") {
		t.Errorf("unexpected divider line: %q", dividerLine)
	}
}

func TestColorFormatting(t *testing.T) {
	SetColorEnabled(true)
	if !strings.Contains(BadgeSuccess("[ACTIVE]"), "\x1b[") {
		t.Errorf("expected ANSI escape code when color is enabled")
	}

	SetColorEnabled(false)
	if strings.Contains(BadgeSuccess("[ACTIVE]"), "\x1b[") {
		t.Errorf("did not expect ANSI escape code when color is disabled")
	}
	ResetColorMode()
}

func TestExtractPinFlag(t *testing.T) {
	// Test standalone --pin
	args, val, found := extractPinFlag([]string{"app.example.com", "3000", "--pin"})
	if !found || val != "true" {
		t.Errorf("expected found=true val='true', got found=%v val=%q", found, val)
	}
	if len(args) != 2 || args[0] != "app.example.com" || args[1] != "3000" {
		t.Errorf("unexpected clean args: %v", args)
	}

	// Test --pin 849201
	args, val, found = extractPinFlag([]string{"app.example.com", "3000", "--pin", "849201"})
	if !found || val != "849201" {
		t.Errorf("expected found=true val='849201', got found=%v val=%q", found, val)
	}
	if len(args) != 2 {
		t.Errorf("unexpected clean args: %v", args)
	}

	// Test --pin=123456
	args, val, found = extractPinFlag([]string{"--pin=123456", "app.example.com", "3000"})
	if !found || val != "123456" {
		t.Errorf("expected found=true val='123456', got found=%v val=%q", found, val)
	}
	if len(args) != 2 {
		t.Errorf("unexpected clean args: %v", args)
	}
}
