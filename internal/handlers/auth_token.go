package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuthTokenPayload represents the claims embedded inside a stateless session cookie token.
type AuthTokenPayload struct {
	RouteName string `json:"rt"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"nonce"`
}

// GenerateAuthToken creates an HMAC-SHA256 signed session token for a given route and secret key.
func GenerateAuthToken(routeName string, secretKey []byte, ttl time.Duration) (string, error) {
	if len(secretKey) == 0 {
		return "", fmt.Errorf("secret key cannot be empty")
	}
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	now := time.Now()
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}

	payload := AuthTokenPayload{
		RouteName: routeName,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		Nonce:     hex.EncodeToString(nonceBytes),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token payload: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(payloadB64))
	signatureHex := hex.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", payloadB64, signatureHex), nil
}

// ValidateAuthToken verifies an HMAC-SHA256 signed session token against a given route and secret key.
func ValidateAuthToken(tokenStr string, routeName string, secretKey []byte) bool {
	if tokenStr == "" || len(secretKey) == 0 {
		return false
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		return false
	}

	payloadB64, signatureHex := parts[0], parts[1]

	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(payloadB64))
	expectedSigHex := hex.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(signatureHex), []byte(expectedSigHex)) {
		return false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return false
	}

	var payload AuthTokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}

	if payload.RouteName != routeName {
		return false
	}

	if time.Now().Unix() > payload.ExpiresAt {
		return false
	}

	return true
}
