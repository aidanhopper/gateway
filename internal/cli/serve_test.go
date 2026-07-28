package cli

import (
	"testing"
)

func TestHttpStatusText(t *testing.T) {
	if got := httpStatusText(200); got != "OK" {
		t.Errorf("expected OK, got %s", got)
	}
	if got := httpStatusText(404); got != "Not Found" {
		t.Errorf("expected Not Found, got %s", got)
	}
}
