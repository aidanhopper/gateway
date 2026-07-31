package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aidanhopper/gateway/internal/api"
)

type mockClient struct {
	server *httptest.Server
	client *http.Client
}

func (m *mockClient) ListRoutes(ctx context.Context) ([]api.RouteSpec, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", m.server.URL+"/api/v1/routes", nil)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Items []api.RouteSpec `json:"items"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body.Items, nil
}

func (m *mockClient) CreateRoute(ctx context.Context, spec api.RouteSpec) error {
	data, _ := json.Marshal(spec)
	req, _ := http.NewRequestWithContext(ctx, "POST", m.server.URL+"/api/v1/routes", strings.NewReader(string(data)))
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (m *mockClient) DeleteRoute(ctx context.Context, name string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE", m.server.URL+"/api/v1/routes/"+name, nil)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (m *mockClient) ListListeners(ctx context.Context) ([]api.ListenerSpec, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", m.server.URL+"/api/v1/listeners", nil)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Items []api.ListenerSpec `json:"items"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body.Items, nil
}

func (m *mockClient) CreateListener(ctx context.Context, spec api.ListenerSpec) error {
	data, _ := json.Marshal(spec)
	req, _ := http.NewRequestWithContext(ctx, "POST", m.server.URL+"/api/v1/listeners", strings.NewReader(string(data)))
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (m *mockClient) DeleteListener(ctx context.Context, name string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE", m.server.URL+"/api/v1/listeners/"+name, nil)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (m *mockClient) StreamLogs(ctx context.Context, routeFilter string, handler func(event api.LogEvent)) error {
	return nil
}

func (m *mockClient) ConfirmPublicSiteExposure(yesFlag bool, mountDesc string) bool {
	return true
}

func setupServeMockServer(t *testing.T) (*httptest.Server, GatewayClient) {
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
	mc := &mockClient{server: server, client: server.Client()}
	return server, mc
}

func TestHTTPStatusText(t *testing.T) {
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
		got := HTTPStatusText(tt.code)
		if got != tt.expected {
			t.Errorf("HTTPStatusText(%d) = %q, expected %q", tt.code, got, tt.expected)
		}
	}
}

func TestEnsureListenerAndReuse(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	lName1, err := EnsureListener(ctx, client, "serve-tcp-25565", ":25565", "tcp", nil)
	if err != nil {
		t.Fatalf("EnsureListener failed: %v", err)
	}
	if lName1 != "serve-tcp-25565" {
		t.Errorf("expected listener name serve-tcp-25565, got %s", lName1)
	}

	lName2, err := EnsureListener(ctx, client, "serve-mc-25565", ":25565", "tcp", nil)
	if err != nil {
		t.Fatalf("EnsureListener failed: %v", err)
	}
	if lName2 != "serve-tcp-25565" {
		t.Errorf("expected reused listener name serve-tcp-25565, got %s", lName2)
	}

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

	_, _ = EnsureListener(ctx, client, "serve-http-80", ":80", "tcp", nil)
	_, _ = EnsureListener(ctx, client, "serve-tcp-2222", ":2222", "tcp", nil)

	_ = client.CreateRoute(ctx, api.RouteSpec{
		Name:     "serve-http-1",
		Protocol: "http",
		Listener: "serve-http-80",
	})

	CleanupUnusedListeners(ctx, client)

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

	l1, _ := EnsureListener(ctx, client, "serve-tcp-8080", ":8080", "tcp", nil)
	_ = client.CreateRoute(ctx, api.RouteSpec{Name: "serve-tcp-route-1", Protocol: "tcp", Listener: l1})

	l2, _ := EnsureListener(ctx, client, "serve-tcp-9090", ":9090", "tcp", nil)
	_ = client.CreateRoute(ctx, api.RouteSpec{Name: "serve-tcp-route-2", Protocol: "tcp", Listener: l2})

	_, _ = Off(ctx, client, "8080")

	routes, _ := client.ListRoutes(ctx)
	if len(routes) != 1 || routes[0].Name != "serve-tcp-route-2" {
		t.Errorf("unexpected remaining routes after serve off: %+v", routes)
	}

	listeners, _ := client.ListListeners(ctx)
	if len(listeners) != 1 || listeners[0].Name != "serve-tcp-9090" {
		t.Errorf("unexpected remaining listeners after serve off: %+v", listeners)
	}

	_, _ = Reset(ctx, client)

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
		domain, path := ParseMount(tt.input)
		if domain != tt.expectedDomain || path != tt.expectedPath {
			t.Errorf("ParseMount(%q) = (%q, %q), want (%q, %q)",
				tt.input, domain, path, tt.expectedDomain, tt.expectedPath)
		}
	}
}

func TestServeHTTPSAutoRedirect(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	_, _ = HTTPS(ctx, client, HTTPSOptions{
		Mount:      "abc.localhost/mypath",
		Target:     "8096",
		Background: true,
		Yes:        true,
	})

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

	_, _ = Minecraft(ctx, client, MinecraftOptions{
		HostOrPort: "abc.localhost",
		Target:     "docker-server:25565",
		Background: true,
		Yes:        true,
	})

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

func TestServeRedirectCommand(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	_, _ = Redirect(ctx, client, RedirectOptions{
		Mount:      "docs.domain.com/",
		TargetURL:  "https://github.com/my-org/docs",
		Background: true,
		Yes:        true,
	})
	_, _ = Redirect(ctx, client, RedirectOptions{
		Mount:      "docs.domain.com/",
		TargetURL:  "https://github.com/my-org/docs",
		Background: true,
		Yes:        true,
	})

	routes, err := client.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes failed: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 redirect routes (HTTP + HTTPS) after deduplication, got %d", len(routes))
	}

	for _, r := range routes {
		if r.Handler.Type != "http_redirect" {
			t.Errorf("expected handler type http_redirect, got %s", r.Handler.Type)
		}
		targetURL, _ := r.Handler.Config["url"].(string)
		if targetURL != "https://github.com/my-org/docs" {
			t.Errorf("expected target URL https://github.com/my-org/docs, got %q", targetURL)
		}
	}
}

func TestServeHTTPDeduplication(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	routes1, err := HTTP(ctx, client, HTTPOptions{
		Mount:  "app.com/api",
		Target: "8080",
		Yes:    true,
	})
	if err != nil || len(routes1) != 1 {
		t.Fatalf("first HTTP call failed: err=%v routes=%v", err, routes1)
	}

	// Second identical call -> should return nil, nil due to HasMatchingRoute
	routes2, err := HTTP(ctx, client, HTTPOptions{
		Mount:  "app.com/api",
		Target: "8080",
		Yes:    true,
	})
	if err != nil || len(routes2) != 0 {
		t.Errorf("expected 0 created routes for duplicate HTTP serve request, got err=%v routes=%v", err, routes2)
	}

	allRoutes, _ := client.ListRoutes(ctx)
	if len(allRoutes) != 1 {
		t.Errorf("expected total routes count to remain 1, got %d", len(allRoutes))
	}
}

func TestServeHTTPSNoRedirect(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	routes, err := HTTPS(ctx, client, HTTPSOptions{
		Mount:      "secure.com/api",
		Target:     "8080",
		NoRedirect: true,
		Yes:        true,
	})
	if err != nil || len(routes) != 1 {
		t.Fatalf("HTTPS with NoRedirect failed: err=%v routes=%v", err, routes)
	}

	allRoutes, _ := client.ListRoutes(ctx)
	if len(allRoutes) != 1 {
		t.Errorf("expected only 1 HTTPS route without redirect, got %d", len(allRoutes))
	}
	if strings.HasPrefix(allRoutes[0].Name, "serve-redirect-") {
		t.Errorf("unexpected redirect route created when NoRedirect=true")
	}
}

func TestServeTCPAndUDP(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	tcpRoutes, err := TCP(ctx, client, TCPOptions{
		ListenPort: "9000",
		Target:     "127.0.0.1:9001",
		Yes:        true,
	})
	if err != nil || len(tcpRoutes) != 1 {
		t.Fatalf("TCP serve failed: err=%v routes=%v", err, tcpRoutes)
	}

	udpRoutes, err := UDP(ctx, client, UDPOptions{
		ListenPort: "9000",
		Target:     "127.0.0.1:9002",
		Yes:        true,
	})
	if err != nil || len(udpRoutes) != 1 {
		t.Fatalf("UDP serve failed: err=%v routes=%v", err, udpRoutes)
	}

	listeners, _ := client.ListListeners(ctx)
	if len(listeners) != 2 {
		t.Fatalf("expected 2 listeners (TCP and UDP on :9000), got %d", len(listeners))
	}

	hasTCP := false
	hasUDP := false
	for _, l := range listeners {
		if l.Name == "serve-tcp-9000" && l.Protocol == "tcp" {
			hasTCP = true
		}
		if l.Name == "serve-udp-9000" && l.Protocol == "udp" {
			hasUDP = true
		}
	}
	if !hasTCP || !hasUDP {
		t.Errorf("missing expected TCP/UDP listeners: hasTCP=%v hasUDP=%v listeners=%+v", hasTCP, hasUDP, listeners)
	}
}

func TestCleanupUnusedListenersSelective(t *testing.T) {
	server, client := setupServeMockServer(t)
	defer server.Close()
	ctx := context.Background()

	_, _ = EnsureListener(ctx, client, "serve-http-80", ":80", "tcp", nil)
	_, _ = EnsureListener(ctx, client, "serve-tcp-3333", ":3333", "tcp", nil)

	_ = client.CreateRoute(ctx, api.RouteSpec{
		Name:     "serve-http-route-1",
		Protocol: "http",
		Listener: "serve-http-80",
	})

	CleanupUnusedListeners(ctx, client)

	listeners, _ := client.ListListeners(ctx)
	if len(listeners) != 1 || listeners[0].Name != "serve-http-80" {
		t.Errorf("expected only serve-http-80 to remain, got %+v", listeners)
	}
}

