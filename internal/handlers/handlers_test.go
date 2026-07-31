package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aidanhopper/gateway/internal/gateway"
)

func TestTCPEchoServer(t *testing.T) {
	echoServer := NewTCPEchoServer()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		echoServer.ServeTCP(serverConn, gateway.TCPMetadata{})
	}()

	testMsg := []byte("HELLO_ECHO_GATEWAY_TEST\n")
	go func() {
		_, _ = clientConn.Write(testMsg)
	}()

	buf := make([]byte, 100)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from echo server: %v", err)
	}

	if string(buf[:n]) != string(testMsg) {
		t.Errorf("got echo %q, want %q", string(buf[:n]), string(testMsg))
	}

	_ = clientConn.Close()
	wg.Wait()
}

func TestTCPLoadBalancer(t *testing.T) {
	// Backend 1
	backend1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen backend1: %v", err)
	}
	defer backend1.Close()

	go func() {
		for {
			conn, err := backend1.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("BACKEND_1"))
			conn.Close()
		}
	}()

	// Backend 2
	backend2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen backend2: %v", err)
	}
	defer backend2.Close()

	go func() {
		for {
			conn, err := backend2.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("BACKEND_2"))
			conn.Close()
		}
	}()

	lb := NewTCPLoadBalancer(backend1.Addr().String(), backend2.Addr().String())
	lb.Strategy = "round_robin"

	// Request 1 -> Backend 1
	sConn1, cConn1 := net.Pipe()
	go lb.ServeTCP(sConn1, gateway.TCPMetadata{})
	buf1 := make([]byte, 20)
	n1, _ := cConn1.Read(buf1)
	cConn1.Close()
	sConn1.Close()

	// Request 2 -> Backend 2
	sConn2, cConn2 := net.Pipe()
	go lb.ServeTCP(sConn2, gateway.TCPMetadata{})
	buf2 := make([]byte, 20)
	n2, _ := cConn2.Read(buf2)
	cConn2.Close()
	sConn2.Close()

	if string(buf1[:n1]) != "BACKEND_1" || string(buf2[:n2]) != "BACKEND_2" {
		t.Errorf("round robin load balancing failed: got %q and %q", string(buf1[:n1]), string(buf2[:n2]))
	}
}

func TestHTTPLoadBalancer(t *testing.T) {
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("HTTP_1"))
	}))
	defer ts1.Close()

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("HTTP_2"))
	}))
	defer ts2.Close()

	lb, err := NewHTTPLoadBalancer(ts1.URL, ts2.URL)
	if err != nil {
		t.Fatalf("NewHTTPLoadBalancer failed: %v", err)
	}

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/", nil)
	lb.ServeHTTP(rec1, req1)

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	lb.ServeHTTP(rec2, req2)

	if rec1.Body.String() != "HTTP_1" || rec2.Body.String() != "HTTP_2" {
		t.Errorf("HTTP load balancing failed: got %q and %q", rec1.Body.String(), rec2.Body.String())
	}
}

func TestHTTPMiddlewares(t *testing.T) {
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("PATH:" + r.URL.Path))
	})

	t.Run("HTTPStripPrefix", func(t *testing.T) {
		sp := &HTTPStripPrefix{Prefix: "/api/v1", Next: finalHandler}

		// Exact match on prefix without trailing slash -> Traefik 301 redirect to /api/v1/
		req1 := httptest.NewRequest("GET", "/api/v1", nil)
		rec1 := httptest.NewRecorder()
		sp.ServeHTTP(rec1, req1)
		if rec1.Code != http.StatusMovedPermanently {
			t.Errorf("expected 301 Moved Permanently for /api/v1, got %d", rec1.Code)
		}
		if rec1.Header().Get("Location") != "/api/v1/" {
			t.Errorf("expected Location /api/v1/, got %q", rec1.Header().Get("Location"))
		}

		// Match with subpath -> strips prefix /api/v1
		req2 := httptest.NewRequest("GET", "/api/v1/users", nil)
		rec2 := httptest.NewRecorder()
		sp.ServeHTTP(rec2, req2)
		if rec2.Body.String() != "PATH:/users" {
			t.Errorf("got %q, want 'PATH:/users'", rec2.Body.String())
		}
	})

	t.Run("HTTPHeaders", func(t *testing.T) {
		hh := &HTTPHeaders{
			AddResponseHeaders: map[string]string{"X-Gateway": "v1"},
			Next:               finalHandler,
		}
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, req)

		if rec.Header().Get("X-Gateway") != "v1" {
			t.Errorf("expected header X-Gateway: v1, got %q", rec.Header().Get("X-Gateway"))
		}
	})

	t.Run("HTTPBasicAuth", func(t *testing.T) {
		ba := &HTTPBasicAuth{Username: "admin", Password: "secretPassword", Next: finalHandler}

		// Invalid Auth
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ba.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
		}

		// Valid Auth
		req = httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth("admin", "secretPassword")
		rec = httptest.NewRecorder()
		ba.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("HTTPRedirectSuite", func(t *testing.T) {
		// 1. Root redirect preserves path and query string
		redirRoot := &HTTPRedirect{URL: "https://what.localhost/"}
		req := httptest.NewRequest("GET", "/install.sh?v=1", nil)
		rec := httptest.NewRecorder()
		redirRoot.ServeHTTP(rec, req)
		if rec.Code != http.StatusMovedPermanently {
			t.Errorf("expected 301, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "https://what.localhost/install.sh?v=1" {
			t.Errorf("expected Location https://what.localhost/install.sh?v=1, got %q", loc)
		}

		// 2. Explicit full file URL redirect
		redirFile := &HTTPRedirect{URL: "https://what.localhost/install.sh"}
		req = httptest.NewRequest("GET", "/install.sh", nil)
		rec = httptest.NewRecorder()
		redirFile.ServeHTTP(rec, req)
		if rec.Code != http.StatusMovedPermanently {
			t.Errorf("expected 301, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "https://what.localhost/install.sh" {
			t.Errorf("expected Location https://what.localhost/install.sh, got %q", loc)
		}

		// 3. Empty target URL dynamically builds from Host header
		redirEmpty := &HTTPRedirect{URL: ""}
		req = httptest.NewRequest("GET", "/script.sh?foo=bar", nil)
		req.Host = "app.localhost"
		rec = httptest.NewRecorder()
		redirEmpty.ServeHTTP(rec, req)
		if rec.Code != http.StatusMovedPermanently {
			t.Errorf("expected 301, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "https://app.localhost/script.sh?foo=bar" {
			t.Errorf("expected Location https://app.localhost/script.sh?foo=bar, got %q", loc)
		}

		// 4. ForwardPath enabled with StripPrefix
		redirSubpath := &HTTPRedirect{
			URL:         "https://github.com/aidanhopper",
			ForwardPath: true,
			StripPrefix: "/github",
			KeepQuery:   true,
		}
		req = httptest.NewRequest("GET", "/github/gateway?ref=main", nil)
		rec = httptest.NewRecorder()
		redirSubpath.ServeHTTP(rec, req)
		if loc := rec.Header().Get("Location"); loc != "https://github.com/aidanhopper/gateway?ref=main" {
			t.Errorf("expected Location https://github.com/aidanhopper/gateway?ref=main, got %q", loc)
		}

		// 5. ForwardPath disabled (No forwarding subpath)
		redirNoFwd := &HTTPRedirect{
			URL:         "https://github.com/aidanhopper",
			ForwardPath: false,
			KeepQuery:   true,
		}
		req = httptest.NewRequest("GET", "/github/gateway?ref=main", nil)
		rec = httptest.NewRecorder()
		redirNoFwd.ServeHTTP(rec, req)
		if loc := rec.Header().Get("Location"); loc != "https://github.com/aidanhopper?ref=main" {
			t.Errorf("expected Location https://github.com/aidanhopper?ref=main, got %q", loc)
		}

		// 6. KeepQuery disabled (Strips query string)
		redirNoQuery := &HTTPRedirect{
			URL:         "https://github.com/aidanhopper",
			ForwardPath: false,
			KeepQuery:   false,
		}
		req = httptest.NewRequest("GET", "/github/gateway?ref=main", nil)
		rec = httptest.NewRecorder()
		redirNoQuery.ServeHTTP(rec, req)
		if loc := rec.Header().Get("Location"); loc != "https://github.com/aidanhopper" {
			t.Errorf("expected Location https://github.com/aidanhopper, got %q", loc)
		}

		// 7. Status codes 307 and 308
		redir307 := &HTTPRedirect{URL: "https://example.com", Status: 307}
		rec = httptest.NewRecorder()
		redir307.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
		if rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("expected 307 Temporary Redirect, got %d", rec.Code)
		}

		redir308 := &HTTPRedirect{URL: "https://example.com", Status: 308}
		rec = httptest.NewRecorder()
		redir308.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
		if rec.Code != http.StatusPermanentRedirect {
			t.Errorf("expected 308 Permanent Redirect, got %d", rec.Code)
		}
	})
}
