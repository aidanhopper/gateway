package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aidanhopper/gateway/internal/firewall"
	"github.com/aidanhopper/gateway/internal/gateway"
)

type mockInformerHandler struct {
	gateway.TCPHandler
	infoData map[string]any
}

func (m *mockInformerHandler) Info() json.RawMessage {
	b, _ := json.Marshal(m.infoData)
	return b
}

func generateTestTLSCert() (certPEM string, keyPEM string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Gateway Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	certBuf := new(bytes.Buffer)
	_ = pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	keyBuf := new(bytes.Buffer)
	_ = pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certBuf.String(), keyBuf.String(), nil
}

func setupTestAPI(t *testing.T) (*API, *gateway.Gateway, string) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}

	_, token, err := CreateToken(db, "test-key")
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	gw := gateway.New()
	fw := firewall.NewNoopManager()
	api, err := New(gw, db, fw)
	if err != nil {
		t.Fatalf("New API failed: %v", err)
	}

	return api, gw, token
}

func TestHealthEndpoint(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	handler := NewHandler(api)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", rec.Code)
	}

	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("got status %q, want 'ok'", resp["status"])
	}
}

func TestAuthMiddleware(t *testing.T) {
	api, _, token := setupTestAPI(t)
	handler := NewHandler(api)

	t.Run("Missing Auth Header -> 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/listeners", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("got status %d, want 401", rec.Code)
		}
	})

	t.Run("Invalid Token -> 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/listeners", nil)
		req.Header.Set("Authorization", "Bearer gw_invalid")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("got status %d, want 401", rec.Code)
		}
	})

	t.Run("Valid Token -> 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/listeners", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("got status %d, want 200", rec.Code)
		}
	})
}

func TestListenerCRUD(t *testing.T) {
	api, _, token := setupTestAPI(t)
	handler := NewHandler(api)

	// 1. Create Listener
	listenerJSON := `{"name":"web","address":":8080","protocol":"tcp"}`
	req := httptest.NewRequest("POST", "/api/v1/listeners", bytes.NewBufferString(listenerJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /listeners failed: %d body: %s", rec.Code, rec.Body.String())
	}

	// 2. Create Duplicate Listener -> 409 Conflict
	req = httptest.NewRequest("POST", "/api/v1/listeners", bytes.NewBufferString(listenerJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for duplicate listener, got %d", rec.Code)
	}

	// 3. Get Listener
	req = httptest.NewRequest("GET", "/api/v1/listeners/web", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /listeners/web failed: %d", rec.Code)
	}

	// 4. Delete Listener
	req = httptest.NewRequest("DELETE", "/api/v1/listeners/web", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /listeners/web failed: %d", rec.Code)
	}

	// 5. Get Listener after delete -> 404
	req = httptest.NewRequest("GET", "/api/v1/listeners/web", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found after delete, got %d", rec.Code)
	}
}

func TestRouteCRUDAndCascadeDelete(t *testing.T) {
	api, _, token := setupTestAPI(t)
	handler := NewHandler(api)

	// 1. Create Route without Listener -> 400 Bad Request
	routeNoListenerJSON := `{"name":"r1","protocol":"http","listener":"nonexistent","priority":1,"rule":{"type":"any"},"handler":{"type":"http_static","config":{"body":"OK"}}}`
	req := httptest.NewRequest("POST", "/api/v1/routes", bytes.NewBufferString(routeNoListenerJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for route pointing to non-existent listener, got %d", rec.Code)
	}

	// 2. Create Listener
	listenerJSON := `{"name":"web","address":":8080","protocol":"tcp"}`
	req = httptest.NewRequest("POST", "/api/v1/listeners", bytes.NewBufferString(listenerJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /listeners failed: %d", rec.Code)
	}

	// 3. Create Valid HTTP Route
	routeJSON := `{"name":"r1","protocol":"http","listener":"web","priority":1,"rule":{"type":"path_prefix","value":"/api"},"handler":{"type":"http_static","config":{"status":200,"body":"HELLO_API"}}}`
	req = httptest.NewRequest("POST", "/api/v1/routes", bytes.NewBufferString(routeJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /routes failed: %d body: %s", rec.Code, rec.Body.String())
	}

	// 4. Filter routes by ?protocol=http and ?listener=web
	req = httptest.NewRequest("GET", "/api/v1/routes?protocol=http&listener=web", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /routes with filter failed: %d", rec.Code)
	}

	var listResp map[string][]RouteSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &listResp)
	if len(listResp["items"]) != 1 || listResp["items"][0].Name != "r1" {
		t.Errorf("expected 1 route 'r1' in filter results, got %+v", listResp["items"])
	}

	// 5. Delete Listener -> Cascade Deletes Route
	req = httptest.NewRequest("DELETE", "/api/v1/listeners/web", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /listeners/web failed: %d", rec.Code)
	}

	// 6. Get Route after cascade delete -> 404
	req = httptest.NewRequest("GET", "/api/v1/routes/r1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected route r1 to be deleted via cascade, got status %d", rec.Code)
	}
}

func TestAPITTLLeases(t *testing.T) {
	api, _, token := setupTestAPI(t)
	handler := NewHandler(api)

	// Create listener with 1 second TTL
	listenerJSON := `{"name":"ttl-ln","address":":8081","protocol":"tcp","ttl":1}`
	req := httptest.NewRequest("POST", "/api/v1/listeners", bytes.NewBufferString(listenerJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST listener failed: %d", rec.Code)
	}

	// Wait 1.1s for TTL timer to fire
	time.Sleep(1100 * time.Millisecond)

	req = httptest.NewRequest("GET", "/api/v1/listeners/ttl-ln", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected listener ttl-ln to be deleted after TTL expiration, got %d", rec.Code)
	}
}

func TestACMEAutoCertEmailRequired(t *testing.T) {
	os.Unsetenv("GATEWAY_ACME_EMAIL")

	api, _, token := setupTestAPI(t)
	handler := NewHandler(api)

	listenerJSON := `{"name":"acme-ln","address":":8443","protocol":"tcp","tls":{"auto":true,"domains":["example.com"]}}`
	req := httptest.NewRequest("POST", "/api/v1/listeners", bytes.NewBufferString(listenerJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request when ACME email is missing, got status %d", rec.Code)
	}
}

func TestAPIACMEListenerCreationWithEnvVar(t *testing.T) {
	os.Setenv("GATEWAY_ACME_EMAIL", "admin@test-domain.org")
	defer os.Unsetenv("GATEWAY_ACME_EMAIL")

	api, _, token := setupTestAPI(t)
	handler := NewHandler(api)

	listenerJSON := `{"name":"acme-auto-ln","address":":8444","protocol":"tcp","tls":{"auto":true,"domains":["test-domain.org"]}}`
	req := httptest.NewRequest("POST", "/api/v1/listeners", bytes.NewBufferString(listenerJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for ACME auto listener with env email, got %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestStaticTLSTermination(t *testing.T) {
	certPEM, keyPEM, err := generateTestTLSCert()
	if err != nil {
		t.Fatalf("failed to generate test TLS cert: %v", err)
	}

	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind dummy listener: %v", err)
	}
	addr := dummyLn.Addr().String()
	dummyLn.Close()

	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	_, token, _ := CreateToken(db, "tls-token")
	gw := gateway.New()
	fw := firewall.NewNoopManager()
	api, err := New(gw, db, fw)
	if err != nil {
		t.Fatalf("New API failed: %v", err)
	}
	apiHandler := NewHandler(api)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = gw.Listen(ctx)
	}()

	// 1. Create Listener with TLS Config via API
	spec := ListenerSpec{
		Name:     "tls-ln",
		Address:  addr,
		Protocol: "tcp",
		TLS: &TLSConfigSpec{
			Cert: certPEM,
			Key:  keyPEM,
		},
	}
	specBytes, _ := json.Marshal(spec)

	req := httptest.NewRequest("POST", "/api/v1/listeners", bytes.NewBuffer(specBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST TLS listener failed: %d body: %s", rec.Code, rec.Body.String())
	}

	// 2. Add HTTP Route to the TLS listener
	routeJSON := `{"name":"https-route","protocol":"http","listener":"tls-ln","priority":1,"rule":{"type":"path_prefix","value":"/secure"},"handler":{"type":"http_static","config":{"status":200,"body":"TLS_SUCCESS"}}}`
	req = httptest.NewRequest("POST", "/api/v1/routes", bytes.NewBufferString(routeJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST route failed: %d body: %s", rec.Code, rec.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	// 3. Perform HTTPS client GET request to the gateway TLS listener
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}

	resp, err := client.Get(fmt.Sprintf("https://%s/secure", addr))
	if err != nil {
		t.Fatalf("HTTPS GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(body) != "TLS_SUCCESS" {
		t.Errorf("got body %q, want 'TLS_SUCCESS'", string(body))
	}
}

func TestInformerIntegration(t *testing.T) {
	api, _, token := setupTestAPI(t)
	handler := NewHandler(api)

	// Create listener
	req := httptest.NewRequest("POST", "/api/v1/listeners", bytes.NewBufferString(`{"name":"tcp-l","address":":9999","protocol":"tcp"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Manually inject a route with a mock Informer handler
	mockH := &mockInformerHandler{
		TCPHandler: gateway.TCPHandlerFunc(func(c net.Conn, m gateway.TCPMetadata) {}),
		infoData:   map[string]any{"active_connections": 5, "backend": "127.0.0.1:25565"},
	}

	spec := RouteSpec{
		Name:     "informer-route",
		Protocol: "tcp",
		Listener: "tcp-l",
		Priority: 10,
		Rule:     RuleSpec{Type: "any"},
		Handler:  HandlerSpec{Type: "mock_informer"},
	}

	api.mu.Lock()
	api.routes["informer-route"] = routeEntry{spec: spec, handler: mockH}
	api.mu.Unlock()

	// GET route and check if "info" block exists
	req = httptest.NewRequest("GET", "/api/v1/routes/informer-route", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET route failed: %d", rec.Code)
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	handlerMap, ok := resp["handler"].(map[string]any)
	if !ok {
		t.Fatalf("expected handler object in response")
	}

	infoMap, ok := handlerMap["info"].(map[string]any)
	if !ok {
		t.Fatalf("expected info object in handler response")
	}

	if infoMap["backend"] != "127.0.0.1:25565" || infoMap["active_connections"].(float64) != 5 {
		t.Errorf("got info map %+v", infoMap)
	}
}

func TestE2ENetworkRoutingViaAPI(t *testing.T) {
	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind dummy listener: %v", err)
	}
	addr := dummyLn.Addr().String()
	dummyLn.Close()

	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	_, token, _ := CreateToken(db, "e2e-token")

	gw := gateway.New()
	fw := firewall.NewNoopManager()
	api, err := New(gw, db, fw)
	if err != nil {
		t.Fatalf("New API failed: %v", err)
	}
	apiHandler := NewHandler(api)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = gw.Listen(ctx)
	}()

	// 1. Create Listener via API
	listenerJSON := fmt.Sprintf(`{"name":"e2e-ln","address":%q,"protocol":"tcp"}`, addr)
	req := httptest.NewRequest("POST", "/api/v1/listeners", bytes.NewBufferString(listenerJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST listener failed: %d body: %s", rec.Code, rec.Body.String())
	}

	// 2. Create HTTP Route via API
	routeJSON := `{"name":"http-e2e","protocol":"http","listener":"e2e-ln","priority":1,"rule":{"type":"path_prefix","value":"/hello"},"handler":{"type":"http_static","config":{"status":200,"body":"API_E2E_SUCCESS"}}}`
	req = httptest.NewRequest("POST", "/api/v1/routes", bytes.NewBufferString(routeJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	apiHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST route failed: %d body: %s", rec.Code, rec.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	// 3. Make HTTP request to live gateway address
	client := &http.Client{Timeout: 2 * time.Second}
	httpResp, err := client.Get(fmt.Sprintf("http://%s/hello", addr))
	if err != nil {
		t.Fatalf("HTTP GET /hello failed: %v", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatalf("ReadAll body failed: %v", err)
	}

	if string(body) != "API_E2E_SUCCESS" {
		t.Errorf("got body %q, want 'API_E2E_SUCCESS'", string(body))
	}
}
