package handlers

import (
	"testing"
	"time"
)

func TestGenerateAndValidateAuthToken(t *testing.T) {
	secret := []byte("super-secret-key-12345")
	routeName := "https-app.example.com-3000"

	token, err := GenerateAuthToken(routeName, secret, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateAuthToken failed: %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token string")
	}

	// Valid validation
	if !ValidateAuthToken(token, routeName, secret) {
		t.Error("ValidateAuthToken returned false for valid token")
	}

	// Invalid route name
	if ValidateAuthToken(token, "other-route", secret) {
		t.Error("ValidateAuthToken returned true for wrong route name")
	}

	// Invalid secret key
	if ValidateAuthToken(token, routeName, []byte("wrong-secret-key")) {
		t.Error("ValidateAuthToken returned true for wrong secret key")
	}

	// Tampered token
	tamperedToken := token + "tampered"
	if ValidateAuthToken(tamperedToken, routeName, secret) {
		t.Error("ValidateAuthToken returned true for tampered token")
	}

	// Expired token
	expiredToken, err := GenerateAuthToken(routeName, secret, -1*time.Second)
	if err != nil {
		t.Fatalf("GenerateAuthToken failed for negative TTL: %v", err)
	}

	if ValidateAuthToken(expiredToken, routeName, secret) {
		t.Error("ValidateAuthToken returned true for expired token")
	}
}
