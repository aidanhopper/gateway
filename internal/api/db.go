package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// TokenInfo contains non-sensitive metadata about an API token.
type TokenInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// OpenDB opens a SQLite database at the specified path and runs schema migrations.
func OpenDB(dbPath string) (*sql.DB, error) {
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create directory for db: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to set pragma on database: %w", err)
	}

	if err := migrateDB(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to run database migrations: %w", err)
	}

	return db, nil
}

func migrateDB(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS listeners (
		name TEXT PRIMARY KEY,
		spec TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS routes (
		name TEXT PRIMARY KEY,
		spec TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS api_tokens (
		id TEXT PRIMARY KEY,
		name TEXT,
		hash TEXT NOT NULL UNIQUE,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := db.Exec(schema)
	return err
}

// HashToken computes the hex-encoded SHA-256 hash of a raw token string.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateToken generates a new random Bearer token, stores its hash, and returns the plaintext token once.
func CreateToken(db *sql.DB, name string) (id string, token string, err error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", "", fmt.Errorf("failed to read random bytes: %w", err)
	}

	token = "gw_" + base64.RawURLEncoding.EncodeToString(rawBytes)
	hash := HashToken(token)
	id = uuid.New().String()

	_, err = db.Exec("INSERT INTO api_tokens (id, name, hash, created_at) VALUES (?, ?, ?, ?)", id, name, hash, time.Now().UTC())
	if err != nil {
		return "", "", fmt.Errorf("failed to insert api_token into db: %w", err)
	}

	return id, token, nil
}

// ListTokens returns non-sensitive metadata for all registered API tokens.
func ListTokens(db *sql.DB) ([]TokenInfo, error) {
	rows, err := db.Query("SELECT id, COALESCE(name, ''), created_at FROM api_tokens ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("failed to query api_tokens: %w", err)
	}
	defer rows.Close()

	var tokens []TokenInfo
	for rows.Next() {
		var info TokenInfo
		var createdAtStr string
		if err := rows.Scan(&info.ID, &info.Name, &createdAtStr); err != nil {
			return nil, fmt.Errorf("failed to scan token row: %w", err)
		}
		// Parse created_at timestamp
		t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAtStr)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05Z", createdAtStr)
		}
		if err != nil {
			t, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
		}
		info.CreatedAt = t
		tokens = append(tokens, info)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tokens, nil
}

// RevokeToken removes an API token by its ID.
func RevokeToken(db *sql.DB, id string) error {
	res, err := db.Exec("DELETE FROM api_tokens WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("token with ID %s not found", id)
	}
	return nil
}

// ValidateToken returns true if the SHA-256 hash of the token exists in api_tokens.
func ValidateToken(db *sql.DB, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	hash := HashToken(token)
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM api_tokens WHERE hash = ?)", hash).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to validate token: %w", err)
	}
	return exists, nil
}
