package api

import (
	"testing"
)

func TestTokenManagement(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	// 1. Initial validate should fail
	valid, err := ValidateToken(db, "gw_invalidtoken")
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if valid {
		t.Errorf("expected invalid token to return false")
	}

	// 2. Create token
	id1, token1, err := CreateToken(db, "admin-key")
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}
	if id1 == "" || token1 == "" {
		t.Fatalf("expected non-empty id and token")
	}

	// 3. Create second token
	id2, token2, err := CreateToken(db, "ci-key")
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}
	if id2 == "" || token2 == "" {
		t.Fatalf("expected non-empty id2 and token2")
	}

	// 4. Validate token1 and token2
	if ok, _ := ValidateToken(db, token1); !ok {
		t.Errorf("token1 should be valid")
	}
	if ok, _ := ValidateToken(db, token2); !ok {
		t.Errorf("token2 should be valid")
	}

	// 5. List tokens
	tokens, err := ListTokens(db)
	if err != nil {
		t.Fatalf("ListTokens failed: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}

	// 6. Revoke token1
	if err := RevokeToken(db, id1); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	// 7. Validate token1 (should now fail) and token2 (should remain valid)
	if ok, _ := ValidateToken(db, token1); ok {
		t.Errorf("revoked token1 should be invalid")
	}
	if ok, _ := ValidateToken(db, token2); !ok {
		t.Errorf("token2 should still be valid")
	}

	// 8. Revoke non-existent token should return error
	if err := RevokeToken(db, "non-existent-id"); err == nil {
		t.Errorf("expected error revoking non-existent token")
	}
}
