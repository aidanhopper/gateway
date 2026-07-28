package firewall

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestDryManager(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	dry := &DryManager{Logger: logger}

	if err := dry.OpenPort("tcp", 8080); err != nil {
		t.Fatalf("OpenPort failed: %v", err)
	}

	if !strings.Contains(buf.String(), "[FIREWALL DRY] Would open tcp port 8080") {
		t.Errorf("got log %q, expected open log message", buf.String())
	}

	buf.Reset()
	if err := dry.ClosePort("tcp", 8080); err != nil {
		t.Fatalf("ClosePort failed: %v", err)
	}

	if !strings.Contains(buf.String(), "[FIREWALL DRY] Would close tcp port 8080") {
		t.Errorf("got log %q, expected close log message", buf.String())
	}
}

func TestNoopManager(t *testing.T) {
	noop := NewNoopManager()
	if err := noop.OpenPort("tcp", 8080); err != nil {
		t.Errorf("expected nil error")
	}
	if err := noop.ClosePort("tcp", 8080); err != nil {
		t.Errorf("expected nil error")
	}
}

func TestProtectedManager(t *testing.T) {
	dry := NewDryManager()
	pm := NewProtectedManager(dry, "22/tcp,53/udp")

	// 1. Attempt to close protected SSH port 22/tcp -> Error
	err := pm.ClosePort("tcp", 22)
	if err == nil {
		t.Errorf("expected error when attempting to close protected port 22/tcp")
	}

	// 2. Attempt to close non-protected port 8080 -> Allowed
	_ = pm.OpenPort("tcp", 8080)
	if err := pm.ClosePort("tcp", 8080); err != nil {
		t.Errorf("expected success when closing non-protected port 8080, got %v", err)
	}
}

func TestDetect(t *testing.T) {
	fwDry := Detect("dry", "22/tcp")
	if fwDry == nil {
		t.Errorf("expected non-nil manager for 'dry'")
	}

	fwNone := Detect("none", "22/tcp")
	if fwNone == nil {
		t.Errorf("expected non-nil manager for 'none'")
	}

	fwAuto := Detect("auto", "22/tcp")
	if fwAuto == nil {
		t.Errorf("expected non-nil manager for 'auto'")
	}
}
