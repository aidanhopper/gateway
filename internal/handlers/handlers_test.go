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
		req := httptest.NewRequest("GET", "/api/v1/users", nil)
		rec := httptest.NewRecorder()
		sp.ServeHTTP(rec, req)

		if rec.Body.String() != "PATH:/users" {
			t.Errorf("got %q, want 'PATH:/users'", rec.Body.String())
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
}
