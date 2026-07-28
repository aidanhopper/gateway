package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
	"github.com/aidanhopper/gateway/internal/gateway"
)

// Client encapsulates interactions with the Gateway REST API and provides offline SQLite fallback.
type Client struct {
	BaseURL    string
	Token      string
	DBPath     string
	HTTPClient *http.Client
}

// NewClient initializes a Client using environment variables or explicit flags.
func NewClient(apiAddr, token, dbPath string) *Client {
	if apiAddr == "" {
		apiAddr = os.Getenv("GATEWAY_API_ADDR")
	}
	if apiAddr == "" {
		apiAddr = "http://127.0.0.1:9090"
	}

	if token == "" {
		token = os.Getenv("GATEWAY_API_TOKEN")
	}

	if dbPath == "" {
		dbPath = os.Getenv("GATEWAY_DB")
	}
	if dbPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dbPath = filepath.Join(home, ".gateway", "gateway.db")
		} else {
			dbPath = "./gateway.db"
		}
	}

	return &Client{
		BaseURL: strings.TrimRight(apiAddr, "/"),
		Token:   token,
		DBPath:  dbPath,
		HTTPClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

// isConnectionRefused returns true if the error indicates the daemon is not running.
func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "Client.Timeout exceeded") ||
		strings.Contains(errStr, "no such host")
}

// request performs an HTTP request to the Gateway REST API.
func (c *Client) request(ctx context.Context, method, endpoint string, body any) ([]byte, error) {
	urlStr := fmt.Sprintf("%s/api/v1/%s", c.BaseURL, strings.TrimLeft(endpoint, "/"))

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, reqBody)
	if err != nil {
		return nil, err
	}

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized: missing or invalid API token. Pass --token <token> or set GATEWAY_API_TOKEN")
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBytes))
	}

	return respBytes, nil
}

// Health checks if the daemon is online and healthy.
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	data, err := c.request(ctx, "GET", "/health", nil)
	if err != nil {
		return nil, err
	}
	var res map[string]any
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// ListListeners returns all listeners from API or SQLite fallback.
func (c *Client) ListListeners(ctx context.Context) ([]api.ListenerSpec, error) {
	data, err := c.request(ctx, "GET", "/listeners", nil)
	if err == nil {
		var wrapper struct {
			Items []api.ListenerSpec `json:"items"`
		}
		if jsonErr := json.Unmarshal(data, &wrapper); jsonErr == nil {
			return wrapper.Items, nil
		}
		var items []api.ListenerSpec
		_ = json.Unmarshal(data, &items)
		return items, nil
	}

	if !isConnectionRefused(err) {
		return nil, err
	}

	// Direct SQLite fallback
	db, dbErr := api.OpenDB(c.DBPath)
	if dbErr != nil {
		return nil, fmt.Errorf("daemon unreachable and failed to open DB at %s: %w", c.DBPath, dbErr)
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, "SELECT spec FROM listeners")
	if err != nil {
		return nil, fmt.Errorf("failed to query listeners DB: %w", err)
	}
	defer rows.Close()

	var listeners []api.ListenerSpec
	for rows.Next() {
		var specJSON string
		if err := rows.Scan(&specJSON); err == nil {
			var spec api.ListenerSpec
			if jsonErr := json.Unmarshal([]byte(specJSON), &spec); jsonErr == nil {
				listeners = append(listeners, spec)
			}
		}
	}
	return listeners, nil
}

// CreateListener creates a new listener via API or SQLite fallback.
func (c *Client) CreateListener(ctx context.Context, spec api.ListenerSpec) error {
	_, err := c.request(ctx, "POST", "/listeners", spec)
	if err == nil {
		return nil
	}
	if !isConnectionRefused(err) {
		return err
	}

	db, dbErr := api.OpenDB(c.DBPath)
	if dbErr != nil {
		return fmt.Errorf("daemon unreachable and failed to open DB at %s: %w", c.DBPath, dbErr)
	}
	defer db.Close()

	specJSON, _ := json.Marshal(spec)
	if _, err := db.ExecContext(ctx, "INSERT INTO listeners (name, spec) VALUES (?, ?)", spec.Name, string(specJSON)); err != nil {
		return fmt.Errorf("failed to insert listener into DB: %w", err)
	}
	return nil
}

// DeleteListener deletes a listener via API or SQLite fallback.
func (c *Client) DeleteListener(ctx context.Context, name string) error {
	_, err := c.request(ctx, "DELETE", fmt.Sprintf("/listeners/%s", name), nil)
	if err == nil {
		return nil
	}
	if !isConnectionRefused(err) {
		return err
	}

	db, dbErr := api.OpenDB(c.DBPath)
	if dbErr != nil {
		return fmt.Errorf("daemon unreachable and failed to open DB at %s: %w", c.DBPath, dbErr)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, "DELETE FROM listeners WHERE name = ?", name); err != nil {
		return fmt.Errorf("failed to delete listener from DB: %w", err)
	}
	return nil
}

// ListRoutes returns all routes from API or SQLite fallback.
func (c *Client) ListRoutes(ctx context.Context) ([]api.RouteSpec, error) {
	data, err := c.request(ctx, "GET", "/routes", nil)
	if err == nil {
		var wrapper struct {
			Items []api.RouteSpec `json:"items"`
		}
		if jsonErr := json.Unmarshal(data, &wrapper); jsonErr == nil {
			return wrapper.Items, nil
		}
		var items []api.RouteSpec
		_ = json.Unmarshal(data, &items)
		return items, nil
	}

	if !isConnectionRefused(err) {
		return nil, err
	}

	db, dbErr := api.OpenDB(c.DBPath)
	if dbErr != nil {
		return nil, fmt.Errorf("daemon unreachable and failed to open DB at %s: %w", c.DBPath, dbErr)
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, "SELECT spec FROM routes")
	if err != nil {
		return nil, fmt.Errorf("failed to query routes DB: %w", err)
	}
	defer rows.Close()

	var routes []api.RouteSpec
	for rows.Next() {
		var specJSON string
		if err := rows.Scan(&specJSON); err == nil {
			var spec api.RouteSpec
			if jsonErr := json.Unmarshal([]byte(specJSON), &spec); jsonErr == nil {
				routes = append(routes, spec)
			}
		}
	}
	return routes, nil
}

// CreateRoute creates a route via API or SQLite fallback.
func (c *Client) CreateRoute(ctx context.Context, spec api.RouteSpec) error {
	_, err := c.request(ctx, "POST", "/routes", spec)
	if err == nil {
		return nil
	}
	if !isConnectionRefused(err) {
		return err
	}

	db, dbErr := api.OpenDB(c.DBPath)
	if dbErr != nil {
		return fmt.Errorf("daemon unreachable and failed to open DB at %s: %w", c.DBPath, dbErr)
	}
	defer db.Close()

	specJSON, _ := json.Marshal(spec)
	if _, err := db.ExecContext(ctx, "INSERT INTO routes (name, spec) VALUES (?, ?)", spec.Name, string(specJSON)); err != nil {
		return fmt.Errorf("failed to insert route into DB: %w", err)
	}
	return nil
}

// DeleteRoute deletes a route via API or SQLite fallback.
func (c *Client) DeleteRoute(ctx context.Context, name string) error {
	_, err := c.request(ctx, "DELETE", fmt.Sprintf("/routes/%s", name), nil)
	if err == nil {
		return nil
	}
	if !isConnectionRefused(err) {
		return err
	}

	db, dbErr := api.OpenDB(c.DBPath)
	if dbErr != nil {
		return fmt.Errorf("daemon unreachable and failed to open DB at %s: %w", c.DBPath, dbErr)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, "DELETE FROM routes WHERE name = ?", name); err != nil {
		return fmt.Errorf("failed to delete route from DB: %w", err)
	}
	return nil
}

// CreateToken creates a new token in SQLite.
func (c *Client) CreateToken(ctx context.Context, name string) (id string, token string, err error) {
	db, err := api.OpenDB(c.DBPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	return api.CreateToken(db, name)
}

// ListTokens lists registered token metadata.
func (c *Client) ListTokens(ctx context.Context) ([]api.TokenInfo, error) {
	db, err := api.OpenDB(c.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	return api.ListTokens(db)
}

// RevokeToken revokes a token by ID.
func (c *Client) RevokeToken(ctx context.Context, id string) error {
	db, err := api.OpenDB(c.DBPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	return api.RevokeToken(db, id)
}

// StreamLogs connects to the daemon SSE log endpoint and streams LogEvents to handler until ctx is cancelled.
func (c *Client) StreamLogs(ctx context.Context, routeFilter string, handler func(event gateway.LogEvent)) error {
	urlStr := fmt.Sprintf("%s/api/v1/logs/stream?route=%s", c.BaseURL, routeFilter)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return err
	}

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("unauthorized: missing or invalid API token")
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("stream error (%d): %s", resp.StatusCode, string(body))
	}

	buf := make([]byte, 4096)
	var lineAcc string

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := resp.Body.Read(buf)
		if n > 0 {
			lineAcc += string(buf[:n])
			lines := strings.Split(lineAcc, "\n")
			lineAcc = lines[len(lines)-1] // keep incomplete trailing line

			for _, l := range lines[:len(lines)-1] {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "data: ") {
					dataJSON := strings.TrimPrefix(l, "data: ")
					var ev gateway.LogEvent
					if jsonErr := json.Unmarshal([]byte(dataJSON), &ev); jsonErr == nil && !ev.Timestamp.IsZero() {
						handler(ev)
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}
