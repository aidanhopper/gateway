package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aidanhopper/gateway/internal/api"
)

func TestHttpStatusText(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{200, "OK"},
		{201, "Created"},
		{204, "No Content"},
		{301, "Moved Permanently"},
		{302, "Found"},
		{400, "Bad Request"},
		{401, "Unauthorized"},
		{403, "Forbidden"},
		{404, "Not Found"},
		{500, "Internal Server Error"},
		{502, "Bad Gateway"},
		{999, ""},
	}

	for _, tt := range tests {
		got := httpStatusText(tt.code)
		if got != tt.expected {
			t.Errorf("httpStatusText(%d) = %q, expected %q", tt.code, got, tt.expected)
		}
	}
}

func TestExtractBoolFlag(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		flagNames     []string
		expectedArgs  []string
		expectedFound bool
	}{
		{
			name:          "Flag at end",
			args:          []string{"tcp", "25565", "127.0.0.1:25565", "-w"},
			flagNames:     []string{"w", "watch"},
			expectedArgs:  []string{"tcp", "25565", "127.0.0.1:25565"},
			expectedFound: true,
		},
		{
			name:          "Flag at beginning",
			args:          []string{"--watch", "http", "/", "3000"},
			flagNames:     []string{"w", "watch"},
			expectedArgs:  []string{"http", "/", "3000"},
			expectedFound: true,
		},
		{
			name:          "Flag in middle",
			args:          []string{"http", "-w", "/", "3000"},
			flagNames:     []string{"w", "watch"},
			expectedArgs:  []string{"http", "/", "3000"},
			expectedFound: true,
		},
		{
			name:          "Flag absent",
			args:          []string{"http", "/", "3000"},
			flagNames:     []string{"w", "watch"},
			expectedArgs:  []string{"http", "/", "3000"},
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArgs, gotFound := extractBoolFlag(tt.args, tt.flagNames...)
			if gotFound != tt.expectedFound {
				t.Errorf("extractBoolFlag() found = %v, expected %v", gotFound, tt.expectedFound)
			}
			if len(gotArgs) != len(tt.expectedArgs) {
				t.Fatalf("extractBoolFlag() args length = %d, expected %d", len(gotArgs), len(tt.expectedArgs))
			}
			for i, arg := range gotArgs {
				if arg != tt.expectedArgs[i] {
					t.Errorf("args[%d] = %q, expected %q", i, arg, tt.expectedArgs[i])
				}
			}
		})
	}
}

func TestHasHelpFlag(t *testing.T) {
	tests := []struct {
		args     []string
		expected bool
	}{
		{[]string{"tcp", "25565", "target:25565", "-h"}, true},
		{[]string{"tcp", "25565", "target:25565", "--help"}, true},
		{[]string{"tcp", "25565", "target:25565", "-help"}, true},
		{[]string{"tcp", "25565", "target:25565"}, false},
	}

	for _, tt := range tests {
		got := hasHelpFlag(tt.args)
		if got != tt.expected {
			t.Errorf("hasHelpFlag(%v) = %v, expected %v", tt.args, got, tt.expected)
		}
	}
}

// setupServeMockServer creates an in-memory HTTP server handling /listeners and /routes endpoints for testing serve functions.
func setupServeMockServer(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()
	var mu sync.Mutex
	listeners := make(map[string]api.ListenerSpec)
	routes := make(map[string]api.RouteSpec)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		path := r.URL.Path
		switch {
		case path == "/api/v1/listeners":
			if r.Method == "GET" {
				var list []api.ListenerSpec
				for _, l := range listeners {
					list = append(list, l)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"items": list})
				return
			} else if r.Method == "POST" {
				var spec api.ListenerSpec
				_ = json.NewDecoder(r.Body).Decode(&spec)
				listeners[spec.Name] = spec
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(spec)
				return
			}

		case strings.HasPrefix(path, "/api/v1/listeners/"):
			name := strings.TrimPrefix(path, "/api/v1/listeners/")
			if r.Method == "DELETE" {
				delete(listeners, name)
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
				return
			}

		case path == "/api/v1/routes":
			if r.Method == "GET" {
				var list []api.RouteSpec
				for _, route := range routes {
					list = append(list, route)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"items": list})
				return
			} else if r.Method == "POST" {
				var spec api.RouteSpec
				_ = json.NewDecoder(r.Body).Decode(&spec)
				if _, ok := listeners[spec.Listener]; !ok {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "listener " + spec.Listener + " does not exist"})
					return
				}
				routes[spec.Name] = spec
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(spec)
				return
			}

		case strings.HasPrefix(path, "/api/v1/routes/"):
			name := strings.TrimPrefix(path, "/api/v1/routes/")
			if r.Method == "DELETE" {
				delete(routes, name)
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	client := NewClient(server.URL, "test-token", "")
	return server, client
}

func TestEnsureListenerAndReuse(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	// 1. First call: Create serve-tcp-25565 on address :25565
	lName1, err := ensureListener(ctx, client, "serve-tcp-25565", ":25565", "tcp", nil)
	if err != nil {
		t.Fatalf("ensureListener failed: %v", err)
	}
	if lName1 != "serve-tcp-25565" {
		t.Errorf("expected listener name serve-tcp-25565, got %s", lName1)
	}

	// 2. Second call: Attempt to create serve-mc-25565 on address :25565
	// It should reuse existing listener on :25565 and return "serve-tcp-25565"
	lName2, err := ensureListener(ctx, client, "serve-mc-25565", ":25565", "tcp", nil)
	if err != nil {
		t.Fatalf("ensureListener failed: %v", err)
	}
	if lName2 != "serve-tcp-25565" {
		t.Errorf("expected reused listener name serve-tcp-25565, got %s", lName2)
	}

	// 3. Create route using lName2
	routeSpec := api.RouteSpec{
		Name:     "serve-mc-route-1",
		Protocol: "tcp",
		Listener: lName2,
		Rule:     api.RuleSpec{Type: "is_minecraft"},
	}
	if err := client.CreateRoute(ctx, routeSpec); err != nil {
		t.Fatalf("CreateRoute failed with reused listener: %v", err)
	}
}

func TestCleanupUnusedServeListeners(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	// Create two listeners
	_, _ = ensureListener(ctx, client, "serve-http-80", ":80", "tcp", nil)
	_, _ = ensureListener(ctx, client, "serve-tcp-2222", ":2222", "tcp", nil)

	// Create route attached to serve-http-80 only
	_ = client.CreateRoute(ctx, api.RouteSpec{
		Name:     "serve-http-1",
		Protocol: "http",
		Listener: "serve-http-80",
	})

	// Run cleanup
	cleanupUnusedServeListeners(ctx, client)

	// Verify serve-http-80 remains, serve-tcp-2222 was deleted
	listeners, err := client.ListListeners(ctx)
	if err != nil {
		t.Fatalf("ListListeners failed: %v", err)
	}

	if len(listeners) != 1 {
		t.Fatalf("expected 1 remaining listener, got %d", len(listeners))
	}
	if listeners[0].Name != "serve-http-80" {
		t.Errorf("expected listener serve-http-80, got %s", listeners[0].Name)
	}
}

func TestRunServeOffAndReset(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	// Setup 2 serve mounts
	l1, _ := ensureListener(ctx, client, "serve-tcp-8080", ":8080", "tcp", nil)
	_ = client.CreateRoute(ctx, api.RouteSpec{Name: "serve-tcp-route-1", Protocol: "tcp", Listener: l1})

	l2, _ := ensureListener(ctx, client, "serve-tcp-9090", ":9090", "tcp", nil)
	_ = client.CreateRoute(ctx, api.RouteSpec{Name: "serve-tcp-route-2", Protocol: "tcp", Listener: l2})

	// Remove serve mount 8080 via runServeOff
	runServeOff(ctx, client, "8080")

	routes, _ := client.ListRoutes(ctx)
	if len(routes) != 1 || routes[0].Name != "serve-tcp-route-2" {
		t.Errorf("unexpected remaining routes after serve off: %+v", routes)
	}

	// Verify listener 8080 was cleaned up
	listeners, _ := client.ListListeners(ctx)
	if len(listeners) != 1 || listeners[0].Name != "serve-tcp-9090" {
		t.Errorf("unexpected remaining listeners after serve off: %+v", listeners)
	}

	// Reset remaining serve mounts
	runServeReset(ctx, client)

	routes, _ = client.ListRoutes(ctx)
	if len(routes) != 0 {
		t.Errorf("expected 0 routes after reset, got %d", len(routes))
	}

	listeners, _ = client.ListListeners(ctx)
	if len(listeners) != 0 {
		t.Errorf("expected 0 listeners after reset, got %d", len(listeners))
	}
}

func TestMinecraftLogEventSerialization(t *testing.T) {
	event := api.LogEvent{
		Protocol:   "minecraft",
		Route:      "serve-mc-route-1",
		Listener:   "serve-mc-25565",
		DurationMs: 150,
		RemoteIP:   "127.0.0.1:54321",
		MinecraftInfo: &api.MinecraftInfoSpec{
			RequestedHost: "mc.example.com",
			ProtocolState: 2,
			Username:      "Steve",
			IsLoginStart:  true,
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var unmarshaled api.LogEvent
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if unmarshaled.MinecraftInfo == nil {
		t.Fatal("expected MinecraftInfo to be non-nil after unmarshal")
	}
	if unmarshaled.MinecraftInfo.Username != "Steve" {
		t.Errorf("expected Username Steve, got %s", unmarshaled.MinecraftInfo.Username)
	}
	if unmarshaled.MinecraftInfo.RequestedHost != "mc.example.com" {
		t.Errorf("expected RequestedHost mc.example.com, got %s", unmarshaled.MinecraftInfo.RequestedHost)
	}
}

func TestServeHTTPAutoStripPrefix(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	// Run serve http with path /abc in background mode for unit test
	runServeHTTP(ctx, client, []string{"/abc", "3000", "--bg"})

	routes, err := client.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}

	r := routes[0]
	if r.Handler.Type != "http_strip_prefix" {
		t.Errorf("expected handler type http_strip_prefix, got %s", r.Handler.Type)
	}

	// Verify rule enforces NOT secure
	if r.Rule.Type != "and" || len(r.Rule.Rules) != 2 {
		t.Fatalf("expected composite 'and' rule, got %+v", r.Rule)
	}
	if r.Handler.Config["prefix"] != "/abc" {
		t.Errorf("expected prefix /abc, got %v", r.Handler.Config["prefix"])
	}

	// Verify rule enforces NOT secure
	if r.Rule.Type != "and" || len(r.Rule.Rules) != 2 {
		t.Fatalf("expected composite 'and' rule, got %+v", r.Rule)
	}
	if r.Rule.Rules[0].Type != "not" || r.Rule.Rules[0].Rule.Type != "secure" {
		t.Errorf("expected rule 0 to be 'not secure', got %+v", r.Rule.Rules[0])
	}
}

func TestParseServeMount(t *testing.T) {
	tests := []struct {
		input          string
		expectedDomain string
		expectedPath   string
	}{
		{"/", "", "/"},
		{"/abc", "", "/abc"},
		{"one.domain.com", "one.domain.com", "/"},
		{"two.domain.com/", "two.domain.com", "/"},
		{"three.domain.com/mypath", "three.domain.com", "/mypath"},
		{"https://four.domain.com/mypath", "four.domain.com", "/mypath"},
	}

	for _, tt := range tests {
		domain, path := parseServeMount(tt.input)
		if domain != tt.expectedDomain || path != tt.expectedPath {
			t.Errorf("parseServeMount(%q) = (%q, %q), want (%q, %q)",
				tt.input, domain, path, tt.expectedDomain, tt.expectedPath)
		}
	}
}

func TestExtractWatchAndBGFlags(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		expectedWatch bool
	}{
		{"Default is watch mode", []string{"http", "/", "3000"}, true},
		{"Background --bg disables watch mode", []string{"http", "/", "3000", "--bg"}, false},
		{"Background -d disables watch mode", []string{"http", "/", "3000", "-d"}, false},
		{"Explicit --watch enables watch mode", []string{"http", "/", "3000", "--watch"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotWatch := extractWatchAndBGFlags(tt.args)
			if gotWatch != tt.expectedWatch {
				t.Errorf("extractWatchAndBGFlags() watch = %v, expected %v", gotWatch, tt.expectedWatch)
			}
		})
	}
}

func TestServeHTTPSAutoRedirect(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	// Run serve https with domain and path in background mode
	runServeHTTPS(ctx, client, []string{"abc.localhost/mypath", "8096", "--bg"})

	routes, err := client.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes (HTTPS + HTTP redirect), got %d", len(routes))
	}

	hasHTTPS := false
	hasRedirect := false
	for _, r := range routes {
		if strings.HasPrefix(r.Name, "serve-https-") {
			hasHTTPS = true
		}
		if strings.HasPrefix(r.Name, "serve-redirect-") {
			hasRedirect = true
			if r.Handler.Type != "http_redirect" {
				t.Errorf("expected redirect handler type http_redirect, got %s", r.Handler.Type)
			}
			if r.Handler.Config["url"] != "https://abc.localhost/mypath" {
				t.Errorf("expected redirect url https://abc.localhost/mypath, got %v", r.Handler.Config["url"])
			}
		}
	}

	if !hasHTTPS {
		t.Error("expected HTTPS route to be created")
	}
	if !hasRedirect {
		t.Error("expected HTTP redirect route to be created")
	}
}

func TestServeMinecraftPositionalArgs(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	// Run serve minecraft abc.localhost docker-server:25565 --bg
	runServeMinecraft(ctx, client, []string{"abc.localhost", "docker-server:25565", "--bg"})

	routes, err := client.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 Minecraft route, got %d", len(routes))
	}

	r := routes[0]
	if r.Handler.Config["target"] != "docker-server:25565" {
		t.Errorf("expected target docker-server:25565, got %v", r.Handler.Config["target"])
	}

	// Verify Minecraft host rule
	if r.Rule.Type != "and" {
		t.Fatalf("expected Composite rule 'and', got %s", r.Rule.Type)
	}
	hasMCHost := false
	for _, rule := range r.Rule.Rules {
		if rule.Type == "minecraft_host" && rule.Value == "abc.localhost" {
			hasMCHost = true
		}
	}
	if !hasMCHost {
		t.Errorf("expected minecraft_host rule 'abc.localhost' in %+v", r.Rule.Rules)
	}
}

func TestServeDirCommand(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "serve-dir-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_ = os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte("<h1>SPA APP</h1>"), 0644)

	// Default HTTPS mode creates HTTPS static route + HTTP 301 redirect route
	runServeDir(ctx, client, []string{"app.domain.com/", tmpDir, "--spa", "--bg"}, true)

	routes, err := client.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes (HTTPS static + HTTP redirect), got %d", len(routes))
	}

	hasStatic := false
	hasRedirect := false
	for _, r := range routes {
		if r.Handler.Type == "http_static" {
			hasStatic = true
			if r.Handler.Config["spa"] != true {
				t.Errorf("expected spa = true, got %v", r.Handler.Config["spa"])
			}
		}
		if r.Handler.Type == "http_redirect" {
			hasRedirect = true
		}
	}

	if !hasStatic {
		t.Error("expected http_static route")
	}
	if !hasRedirect {
		t.Error("expected http_redirect route")
	}
}

func TestServeSingleFileCommand(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	tmpFile, err := os.CreateTemp("", "script-*.sh")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_, _ = tmpFile.WriteString("#!/bin/bash\necho hello\n")
	_ = tmpFile.Close()

	// Run serve file what.localhost/install.sh ./script.sh --http --bg
	runServeDir(ctx, client, []string{"--http", "--bg", "what.localhost/install.sh", tmpFile.Name()}, false)

	routes, err := client.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 file route, got %d", len(routes))
	}

	r := routes[0]
	if r.Handler.Type != "http_static" {
		t.Errorf("expected handler type http_static, got %s", r.Handler.Type)
	}
}

func TestServeSingleFileHTTPRedirectIntegration(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	tmpFile, err := os.CreateTemp("", "script-*.sh")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_, _ = tmpFile.WriteString("#!/bin/bash\necho install\n")
	_ = tmpFile.Close()

	// Run serve dir what.localhost/install.sh ./script.sh --bg (HTTPS default mode)
	runServeDir(ctx, client, []string{"--bg", "what.localhost/install.sh", tmpFile.Name()}, false)

	routes, err := client.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes (HTTPS static file + HTTP redirect), got %d", len(routes))
	}

	var redirectRoute *api.RouteSpec
	var staticRoute *api.RouteSpec

	for i := range routes {
		if routes[i].Handler.Type == "http_redirect" {
			redirectRoute = &routes[i]
		} else if routes[i].Handler.Type == "http_static" {
			staticRoute = &routes[i]
		}
	}

	if redirectRoute == nil {
		t.Fatal("missing http_redirect route")
	}
	if staticRoute == nil {
		t.Fatal("missing http_static route")
	}

	// Verify redirect target URL preserves path
	targetURL, _ := redirectRoute.Handler.Config["url"].(string)
	if targetURL != "https://what.localhost/install.sh" {
		t.Errorf("expected redirect target https://what.localhost/install.sh, got %q", targetURL)
	}

	// Verify static route rule uses exact path match for single file
	if staticRoute.Rule.Type != "and" || len(staticRoute.Rule.Rules) < 2 {
		t.Fatalf("expected composite and rule for static route, got %+v", staticRoute.Rule)
	}
	hasPathMatch := false
	for _, rule := range staticRoute.Rule.Rules {
		if rule.Type == "path" && rule.Value == "/install.sh" {
			hasPathMatch = true
		}
	}
	if !hasPathMatch {
		t.Errorf("expected exact path rule '/install.sh' in static route, got %+v", staticRoute.Rule.Rules)
	}
}
