package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aidanhopper/gateway/internal/firewall"
	"github.com/aidanhopper/gateway/internal/gateway"
)

func TestFormatRuleSummary(t *testing.T) {
	tests := []struct {
		rule     RuleSpec
		expected string
	}{
		{RuleSpec{Type: "any"}, "/*"},
		{RuleSpec{Type: "host", Value: "example.com"}, "example.com"},
		{RuleSpec{Type: "path", Value: "/api"}, "/api"},
		{RuleSpec{Type: "path_prefix", Value: "/docs"}, "/docs"},
	}

	for _, tt := range tests {
		got := FormatRuleSummary(tt.rule)
		if got != tt.expected {
			t.Errorf("FormatRuleSummary(%+v) = %q, want %q", tt.rule, got, tt.expected)
		}
	}
}

func TestFormatTTLRemaining(t *testing.T) {
	tests := []struct {
		ttl      int
		expected string
	}{
		{0, "never"},
		{-1, "never"},
	}

	for _, tt := range tests {
		got := FormatTTLRemaining(time.Now(), tt.ttl)
		if got != tt.expected {
			t.Errorf("FormatTTLRemaining(%d) = %q, want %q", tt.ttl, got, tt.expected)
		}
	}
}

func TestParseMountArg(t *testing.T) {
	domain, path := parseMountArg("https://example.com/api")
	if domain != "example.com" || path != "/api" {
		t.Errorf("parseMountArg failed: got domain=%q path=%q", domain, path)
	}
}

func TestServeRequestJSONSerialization(t *testing.T) {
	req := ServeRequestHTTP{
		Mount:  "/",
		Target: "3000",
		TTL:    3600,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ServeRequestHTTP
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Mount != "/" || decoded.Target != "3000" || decoded.TTL != 3600 {
		t.Errorf("decoded mismatch: %+v", decoded)
	}
}

func TestAPIServeHTTPListenerCreationAndDBPersistence(t *testing.T) {
	apiInstance, _, token := setupTestAPI(t)
	handler := NewHandler(apiInstance)

	// 1. Invalid payload -> 400 Bad Request
	req := httptest.NewRequest("POST", "/api/v1/serve/http", bytes.NewBufferString(`{"mount":"","target":""}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for empty serve payload, got %d", rec.Code)
	}

	// 2. Initial Serve HTTP Request -> Creates listener serve-http-80 and route
	body1 := `{"mount":"app.localhost/api","target":"8080","ttl":300}`
	req = httptest.NewRequest("POST", "/api/v1/serve/http", bytes.NewBufferString(body1))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/serve/http failed: %d body: %s", rec.Code, rec.Body.String())
	}

	var routeResp RouteSpec
	if err := json.Unmarshal(rec.Body.Bytes(), &routeResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if routeResp.Listener != "serve-http-80" {
		t.Errorf("expected listener serve-http-80, got %s", routeResp.Listener)
	}

	// Verify Listener DB persistence
	var count int
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners WHERE name = 'serve-http-80'").Scan(&count); err != nil || count != 1 {
		t.Errorf("expected 1 listener serve-http-80 in DB, got count=%d err=%v", count, err)
	}

	// Verify Route DB persistence
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM routes WHERE name = ?", routeResp.Name).Scan(&count); err != nil || count != 1 {
		t.Errorf("expected 1 route %s in DB, got count=%d err=%v", routeResp.Name, count, err)
	}

	// 3. Second Serve HTTP Request -> Listener serve-http-80 reused, NOT duplicated
	body2 := `{"mount":"other.localhost/app","target":"8081"}`
	req = httptest.NewRequest("POST", "/api/v1/serve/http", bytes.NewBufferString(body2))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("second POST /api/v1/serve/http failed: %d", rec.Code)
	}

	// Total listeners should still be 1
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners").Scan(&count); err != nil || count != 1 {
		t.Errorf("expected listener count in DB to remain 1 after reuse, got %d", count)
	}

	// Total routes should now be 2
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM routes").Scan(&count); err != nil || count != 2 {
		t.Errorf("expected 2 routes in DB, got %d", count)
	}
}

func TestAPIServeHTTPSAndRedirectOption(t *testing.T) {
	apiInstance, _, token := setupTestAPI(t)
	handler := NewHandler(apiInstance)

	// 1. HTTPS serve mount with redirect (no_redirect = false)
	body := `{"mount":"secure.localhost/dash","target":"3000","no_redirect":false}`
	req := httptest.NewRequest("POST", "/api/v1/serve/https", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/serve/https failed: %d body: %s", rec.Code, rec.Body.String())
	}

	var httpsRoute RouteSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &httpsRoute)

	// Verify HTTPS listener serve-https-443 created in DB
	var listenerCount int
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners WHERE name = 'serve-https-443'").Scan(&listenerCount); err != nil || listenerCount != 1 {
		t.Errorf("expected HTTPS listener serve-https-443 in DB, got count=%d err=%v", listenerCount, err)
	}

	// Verify HTTP redirect listener serve-http-80 created in DB
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners WHERE name = 'serve-http-80'").Scan(&listenerCount); err != nil || listenerCount != 1 {
		t.Errorf("expected HTTP redirect listener serve-http-80 in DB, got count=%d err=%v", listenerCount, err)
	}

	// Verify HTTP redirect route created in DB
	redirectRouteName := httpsRoute.Name + "-redir"
	var routeCount int
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM routes WHERE name = ?", redirectRouteName).Scan(&routeCount); err != nil || routeCount != 1 {
		t.Errorf("expected redirect route %s in DB, got count=%d err=%v", redirectRouteName, routeCount, err)
	}

	// 2. HTTPS serve mount with no_redirect = true
	bodyNoRedirect := `{"mount":"noredirect.localhost","target":"3001","no_redirect":true}`
	req = httptest.NewRequest("POST", "/api/v1/serve/https", bytes.NewBufferString(bodyNoRedirect))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/serve/https with no_redirect failed: %d", rec.Code)
	}

	var noRedirRoute RouteSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &noRedirRoute)
	noRedirRedirectName := noRedirRoute.Name + "-redir"

	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM routes WHERE name = ?", noRedirRedirectName).Scan(&routeCount); err != nil || routeCount != 0 {
		t.Errorf("expected NO redirect route for no_redirect=true, got count=%d", routeCount)
	}
}

func TestAPIServeRedirectEndpoint(t *testing.T) {
	t.Setenv("GATEWAY_ACME_EMAIL", "")

	apiInstance, _, token := setupTestAPI(t)
	handler := NewHandler(apiInstance)

	body := `{"mount":"old.example.com","target_url":"https://new.example.com","status_code":301}`
	req := httptest.NewRequest("POST", "/api/v1/serve/redirect", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/serve/redirect failed: %d body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	httpsRouteName, ok1 := resp["https_route"].(string)
	httpRouteName, ok2 := resp["http_route"].(string)
	if !ok1 || !ok2 || httpsRouteName == "" || httpRouteName == "" {
		t.Fatalf("expected https_route and http_route names in response, got %+v", resp)
	}

	// Verify both routes exist in DB
	var count int
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM routes WHERE name IN (?, ?)", httpsRouteName, httpRouteName).Scan(&count); err != nil || count != 2 {
		t.Errorf("expected 2 redirect routes in DB, got count=%d err=%v", count, err)
	}
}

func TestAPIServeTCPAndUDP(t *testing.T) {
	apiInstance, _, token := setupTestAPI(t)
	handler := NewHandler(apiInstance)

	// 1. Create TCP serve mount on port 9000
	tcpBody := `{"listen_port":"9000","target":"127.0.0.1:9001"}`
	req := httptest.NewRequest("POST", "/api/v1/serve/tcp", bytes.NewBufferString(tcpBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/serve/tcp failed: %d body: %s", rec.Code, rec.Body.String())
	}

	var tcpRoute RouteSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &tcpRoute)
	if tcpRoute.Listener != "serve-tcp-9000" {
		t.Errorf("expected listener serve-tcp-9000, got %s", tcpRoute.Listener)
	}

	// 2. Create UDP serve mount on port 9000
	udpBody := `{"listen_port":"9000","target":"127.0.0.1:9002"}`
	req = httptest.NewRequest("POST", "/api/v1/serve/udp", bytes.NewBufferString(udpBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/serve/udp failed: %d body: %s", rec.Code, rec.Body.String())
	}

	var udpRoute RouteSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &udpRoute)
	if udpRoute.Listener != "serve-udp-9000" {
		t.Errorf("expected listener serve-udp-9000, got %s", udpRoute.Listener)
	}

	// Verify both TCP and UDP listeners in DB
	var listenerCount int
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners WHERE name IN ('serve-tcp-9000', 'serve-udp-9000')").Scan(&listenerCount); err != nil || listenerCount != 2 {
		t.Errorf("expected 2 listeners (TCP and UDP) in DB, got count=%d", listenerCount)
	}
}

func TestAPIServeMinecraft(t *testing.T) {
	apiInstance, _, token := setupTestAPI(t)
	handler := NewHandler(apiInstance)

	mcBody := `{"host_or_port":"mc.example.com","target":"127.0.0.1:25565"}`
	req := httptest.NewRequest("POST", "/api/v1/serve/minecraft", bytes.NewBufferString(mcBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/serve/minecraft failed: %d body: %s", rec.Code, rec.Body.String())
	}

	var mcRoute RouteSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &mcRoute)
	if mcRoute.Listener != "serve-mc-25565" {
		t.Errorf("expected listener serve-mc-25565, got %s", mcRoute.Listener)
	}

	var listenerCount int
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners WHERE name = 'serve-mc-25565'").Scan(&listenerCount); err != nil || listenerCount != 1 {
		t.Errorf("expected Minecraft listener serve-mc-25565 in DB, got %d", listenerCount)
	}
}

func TestAPIServeListAndGetMounts(t *testing.T) {
	apiInstance, _, token := setupTestAPI(t)
	handler := NewHandler(apiInstance)

	// Create serve route
	req := httptest.NewRequest("POST", "/api/v1/serve/http", bytes.NewBufferString(`{"mount":"/api","target":"8080"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var routeResp RouteSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &routeResp)

	// GET /api/v1/serve
	req = httptest.NewRequest("GET", "/api/v1/serve", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/serve failed: %d", rec.Code)
	}

	var listResp map[string][]ServeMountItem
	_ = json.Unmarshal(rec.Body.Bytes(), &listResp)
	if len(listResp["items"]) != 1 || listResp["items"][0].Name != routeResp.Name {
		t.Errorf("expected 1 serve mount item in list, got %+v", listResp["items"])
	}

	// GET /api/v1/serve/{name}
	req = httptest.NewRequest("GET", "/api/v1/serve/"+url.PathEscape(routeResp.Name), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/serve/%s failed: %d", routeResp.Name, rec.Code)
	}

	// GET /api/v1/serve/nonexistent -> 404
	req = httptest.NewRequest("GET", "/api/v1/serve/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent serve mount, got %d", rec.Code)
	}
}

func TestAPIServeDeleteAndResetListenersCleanup(t *testing.T) {
	apiInstance, _, token := setupTestAPI(t)
	handler := NewHandler(apiInstance)

	// Create 2 HTTP routes on listener serve-http-80
	req := httptest.NewRequest("POST", "/api/v1/serve/http", bytes.NewBufferString(`{"mount":"app1.localhost/a","target":"127.0.0.1:8081"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var r1 RouteSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &r1)

	time.Sleep(2 * time.Millisecond)

	req = httptest.NewRequest("POST", "/api/v1/serve/http", bytes.NewBufferString(`{"mount":"app2.localhost/b","target":"127.0.0.1:8082"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var r2 RouteSpec
	if err := json.Unmarshal(rec.Body.Bytes(), &r2); err != nil || r2.Name == "" {
		t.Fatalf("failed to create r2: status=%d body=%s", rec.Code, rec.Body.String())
	}

	time.Sleep(2 * time.Millisecond)

	// Create 1 TCP route on port 8090 (listener: serve-tcp-8090)
	req = httptest.NewRequest("POST", "/api/v1/serve/tcp", bytes.NewBufferString(`{"listen_port":"8090","target":"127.0.0.1:8091"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var r3 RouteSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &r3)

	// Delete route r1 (listener serve-http-80 still has active route r2)
	req = httptest.NewRequest("DELETE", "/api/v1/serve/"+url.PathEscape(r1.Name), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v1/serve/%s failed: %d", r1.Name, rec.Code)
	}

	// Listener serve-http-80 must STILL exist in DB because r2 is active
	var lCount int
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners WHERE name = 'serve-http-80'").Scan(&lCount); err != nil || lCount != 1 {
		t.Errorf("expected listener serve-http-80 to be preserved while r2 is active, got count=%d", lCount)
	}

	// Delete route r2 (now listener serve-http-80 has ZERO active routes!)
	req = httptest.NewRequest("DELETE", "/api/v1/serve/"+url.PathEscape(r2.Name), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v1/serve/%s failed: %d", r2.Name, rec.Code)
	}

	// Listener serve-http-80 must NOW be cleaned up and removed from DB
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners WHERE name = 'serve-http-80'").Scan(&lCount); err != nil || lCount != 0 {
		t.Errorf("expected listener serve-http-80 to be cleaned up after r2 deletion, got count=%d", lCount)
	}

	// Listener serve-tcp-8090 must STILL exist in DB
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners WHERE name = 'serve-tcp-8090'").Scan(&lCount); err != nil || lCount != 1 {
		t.Errorf("expected listener serve-tcp-8090 to exist, got count=%d", lCount)
	}

	// Perform serve reset -> clears r3 and deletes serve-tcp-8090
	req = httptest.NewRequest("POST", "/api/v1/serve/reset", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/serve/reset failed: %d", rec.Code)
	}

	// Both listeners and routes should be 0 in DB
	var totalRoutes, totalListeners int
	_ = apiInstance.db.QueryRow("SELECT COUNT(*) FROM routes").Scan(&totalRoutes)
	_ = apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners").Scan(&totalListeners)

	if totalRoutes != 0 || totalListeners != 0 {
		t.Errorf("expected 0 routes and 0 listeners after reset, got %d routes and %d listeners", totalRoutes, totalListeners)
	}
}

func TestAPIServeDBRehydration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gateway_test.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}

	_, token, err := CreateToken(db, "rehydrate-key")
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	gw1 := gateway.New()
	fw1 := firewall.NewNoopManager()
	api1, err := New(gw1, db, fw1, false)
	if err != nil {
		t.Fatalf("New API failed: %v", err)
	}
	handler1 := NewHandler(api1)

	// Create HTTP serve mount and TCP serve mount
	req := httptest.NewRequest("POST", "/api/v1/serve/http", bytes.NewBufferString(`{"mount":"rehydrate.localhost/app","target":"8080"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler1.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/serve/http failed: %d", rec.Code)
	}

	req = httptest.NewRequest("POST", "/api/v1/serve/tcp", bytes.NewBufferString(`{"listen_port":"7000","target":"127.0.0.1:7001"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler1.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/serve/tcp failed: %d", rec.Code)
	}

	// Close initial database connection
	db.Close()

	// Re-open SQLite database file and construct NEW API instance
	db2, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("re-opening DB failed: %v", err)
	}
	defer db2.Close()

	gw2 := gateway.New()
	fw2 := firewall.NewNoopManager()
	api2, err := New(gw2, db2, fw2, false)
	if err != nil {
		t.Fatalf("New API rehydration failed: %v", err)
	}

	api2.mu.RLock()
	listenersLen := len(api2.listeners)
	routesLen := len(api2.routes)
	api2.mu.RUnlock()

	if listenersLen != 2 {
		t.Errorf("expected 2 rehydrated listeners in api2, got %d", listenersLen)
	}
	if routesLen != 2 {
		t.Errorf("expected 2 rehydrated routes in api2, got %d", routesLen)
	}

	// Verify listener specs in rehydrated state
	api2.mu.RLock()
	_, hasHTTPListener := api2.listeners["serve-http-80"]
	_, hasTCPListener := api2.listeners["serve-tcp-7000"]
	api2.mu.RUnlock()

	if !hasHTTPListener || !hasTCPListener {
		t.Errorf("missing expected listeners after rehydration: http=%v tcp=%v", hasHTTPListener, hasTCPListener)
	}
}

func TestHTTPSPublicDomainWithoutACMEEmail(t *testing.T) {
	os.Unsetenv("GATEWAY_ACME_EMAIL")

	apiInstance, _, token := setupTestAPI(t)
	handler := NewHandler(apiInstance)

	body := `{"mount":"dev.ahop.dev","target":"docker-server:8096"}`
	req := httptest.NewRequest("POST", "/api/v1/serve/https", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for public domain HTTPS serve without ACME email, got %d body: %s", rec.Code, rec.Body.String())
	}

	var routeResp RouteSpec
	if err := json.Unmarshal(rec.Body.Bytes(), &routeResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	var count int
	if err := apiInstance.db.QueryRow("SELECT COUNT(*) FROM listeners WHERE name = 'serve-https-443'").Scan(&count); err != nil || count != 1 {
		t.Errorf("expected listener serve-https-443 to exist in DB, got count=%d err=%v", count, err)
	}
}
