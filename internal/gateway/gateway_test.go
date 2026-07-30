package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestGatewayRouteManagement(t *testing.T) {
	gw := New()

	t.Run("TCP Route CRUD", func(t *testing.T) {
		route := TCPRoute{Name: "tcp-1", Listener: "main", Rule: Any[TCPMetadata]()}
		if err := gw.AddTCPRoute(route); err != nil {
			t.Fatalf("AddTCPRoute failed: %v", err)
		}
		if err := gw.AddTCPRoute(route); err == nil {
			t.Errorf("AddTCPRoute duplicate expected error, got nil")
		}

		routeUpdate := TCPRoute{Name: "tcp-1", Listener: "main", Priority: 10, Rule: Any[TCPMetadata]()}
		if err := gw.UpdateTCPRoute(routeUpdate); err != nil {
			t.Fatalf("UpdateTCPRoute failed: %v", err)
		}
		if err := gw.UpdateTCPRoute(TCPRoute{Name: "nonexistent"}); err == nil {
			t.Errorf("UpdateTCPRoute non-existent expected error")
		}

		if err := gw.RemoveTCPRoute("tcp-1"); err != nil {
			t.Fatalf("RemoveTCPRoute failed: %v", err)
		}
		if err := gw.RemoveTCPRoute("tcp-1"); err == nil {
			t.Errorf("RemoveTCPRoute non-existent expected error")
		}
	})

	t.Run("HTTP Route CRUD", func(t *testing.T) {
		route := HTTPRoute{Name: "http-1", Listener: "web", Rule: AnyHTTP()}
		if err := gw.AddHTTPRoute(route); err != nil {
			t.Fatalf("AddHTTPRoute failed: %v", err)
		}
		if err := gw.AddHTTPRoute(route); err == nil {
			t.Errorf("AddHTTPRoute duplicate expected error")
		}

		routeUpdate := HTTPRoute{Name: "http-1", Listener: "web", Priority: 5, Rule: AnyHTTP()}
		if err := gw.UpdateHTTPRoute(routeUpdate); err != nil {
			t.Fatalf("UpdateHTTPRoute failed: %v", err)
		}
		if err := gw.UpdateHTTPRoute(HTTPRoute{Name: "nonexistent"}); err == nil {
			t.Errorf("UpdateHTTPRoute non-existent expected error")
		}

		if err := gw.RemoveHTTPRoute("http-1"); err != nil {
			t.Fatalf("RemoveHTTPRoute failed: %v", err)
		}
		if err := gw.RemoveHTTPRoute("http-1"); err == nil {
			t.Errorf("RemoveHTTPRoute non-existent expected error")
		}
	})

	t.Run("UDP Route CRUD", func(t *testing.T) {
		route := UDPRoute{Name: "udp-1", Listener: "dns", Rule: Any[UDPMetadata]()}
		if err := gw.AddUDPRoute(route); err != nil {
			t.Fatalf("AddUDPRoute failed: %v", err)
		}
		if err := gw.AddUDPRoute(route); err == nil {
			t.Errorf("AddUDPRoute duplicate expected error")
		}

		routeUpdate := UDPRoute{Name: "udp-1", Listener: "dns", Priority: 1, Rule: Any[UDPMetadata]()}
		if err := gw.UpdateUDPRoute(routeUpdate); err != nil {
			t.Fatalf("UpdateUDPRoute failed: %v", err)
		}
		if err := gw.UpdateUDPRoute(UDPRoute{Name: "nonexistent"}); err == nil {
			t.Errorf("UpdateUDPRoute non-existent expected error")
		}

		if err := gw.RemoveUDPRoute("udp-1"); err != nil {
			t.Fatalf("RemoveUDPRoute failed: %v", err)
		}
		if err := gw.RemoveUDPRoute("udp-1"); err == nil {
			t.Errorf("RemoveUDPRoute non-existent expected error")
		}
	})

	t.Run("Listener Management", func(t *testing.T) {
		ln := Listener{Name: "l1", Address: "127.0.0.1:0", Protocol: ProtoTCP}
		if err := gw.AddListener(ln); err != nil {
			t.Fatalf("AddListener failed: %v", err)
		}
		if err := gw.AddListener(ln); err == nil {
			t.Errorf("AddListener duplicate expected error")
		}

		if err := gw.RemoveListener("l1"); err != nil {
			t.Fatalf("RemoveListener failed: %v", err)
		}
		if err := gw.RemoveListener("l1"); err == nil {
			t.Errorf("RemoveListener non-existent expected error")
		}
	})
}

func TestAddListenerBindFailureCleanup(t *testing.T) {
	occupiedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind occupied socket: %v", err)
	}
	addr := occupiedLn.Addr().String()

	gw := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = gw.Listen(ctx)
	}()
	time.Sleep(50 * time.Millisecond)

	// Attempt to add listener on occupied port while gateway is running -> expect bind error
	lnSpec := Listener{Name: "conflict-ln", Address: addr, Protocol: ProtoTCP}
	err = gw.AddListener(lnSpec)
	if err == nil {
		t.Fatalf("expected AddListener to fail due to port collision, got nil")
	}

	// Verify conflict-ln is NOT leaked in gw.listeners
	gw.mu.RLock()
	_, exists := gw.listeners["conflict-ln"]
	gw.mu.RUnlock()
	if exists {
		t.Errorf("gw.listeners map leaked 'conflict-ln' after startListener failure")
	}

	// Close occupied socket
	occupiedLn.Close()

	// Re-adding conflict-ln should now succeed cleanly
	if err := gw.AddListener(lnSpec); err != nil {
		t.Errorf("AddListener failed after freeing port: %v", err)
	}
}

func TestGatewayNetworkRoutingE2E(t *testing.T) {
	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind temp listener: %v", err)
	}
	addr := dummyLn.Addr().String()
	dummyLn.Close()

	gw := New()
	err = gw.AddListener(Listener{
		Name:     "web-tcp",
		Address:  addr,
		Protocol: ProtoTCP,
	})
	if err != nil {
		t.Fatalf("AddListener failed: %v", err)
	}

	err = gw.AddTCPRoute(TCPRoute{
		Name:     "tcp-low-priority",
		Listener: "web-tcp",
		Priority: 0,
		Rule:     NotHTTP(),
		Handler: TCPHandlerFunc(func(conn net.Conn, metadata TCPMetadata) {
			conn.Write([]byte("LOW_PRIORITY_RESPONSE"))
		}),
	})
	if err != nil {
		t.Fatalf("AddTCPRoute failed: %v", err)
	}

	err = gw.AddTCPRoute(TCPRoute{
		Name:     "tcp-high-priority",
		Listener: "web-tcp",
		Priority: 10,
		Rule:     And(NotHTTP(), NotTLS(), NotMinecraft()),
		Handler: TCPHandlerFunc(func(conn net.Conn, metadata TCPMetadata) {
			conn.Write([]byte("HIGH_PRIORITY_RESPONSE"))
		}),
	})
	if err != nil {
		t.Fatalf("AddTCPRoute failed: %v", err)
	}

	err = gw.AddHTTPRoute(HTTPRoute{
		Name:     "http-hello",
		Listener: "web-tcp",
		Priority: 1,
		Rule:     Path("/hello"),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("HELLO_HTTP_WORLD"))
		}),
	})
	if err != nil {
		t.Fatalf("AddHTTPRoute failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = gw.Listen(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	t.Run("Already Listening Error", func(t *testing.T) {
		if err := gw.Listen(ctx); err == nil {
			t.Errorf("Listen() twice should return error")
		}
	})

	t.Run("TCP Priority Routing Dispatch", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("net.Dial failed: %v", err)
		}
		defer conn.Close()

		conn.Write([]byte("RAW_TCP_STREAM_DATA\n"))

		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("conn.Read failed: %v", err)
		}

		resp := string(buf[:n])
		if resp != "HIGH_PRIORITY_RESPONSE" {
			t.Errorf("got response %q, want %q", resp, "HIGH_PRIORITY_RESPONSE")
		}
	})

	t.Run("HTTP Route Dispatch (/hello)", func(t *testing.T) {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://%s/hello", addr))
		if err != nil {
			t.Fatalf("HTTP GET /hello failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status code = %d, want 200", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll body failed: %v", err)
		}

		if string(body) != "HELLO_HTTP_WORLD" {
			t.Errorf("body = %q, want %q", string(body), "HELLO_HTTP_WORLD")
		}
	})

	t.Run("HTTP Unmatched Route (404 Not Found)", func(t *testing.T) {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://%s/unmatched-path", addr))
		if err != nil {
			t.Fatalf("HTTP GET /unmatched-path failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status code = %d, want 404 Not Found", resp.StatusCode)
		}
	})
}

func TestUDPSessionForceCloseOnRouteRemoval(t *testing.T) {
	gw := New()
	gw.AddListener(Listener{Name: "udp-test", Address: "127.0.0.1:19191", Protocol: ProtoUDP})

	sessionClosed := make(chan struct{})
	gw.AddUDPRoute(UDPRoute{
		Name:     "echo",
		Listener: "udp-test",
		Rule:     Any[UDPMetadata](),
		Handler: UDPHandlerFunc(func(conn net.Conn, meta UDPMetadata) {
			buf := make([]byte, 1024)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					close(sessionClosed)
					return
				}
			}
		}),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gw.Listen(ctx)
	time.Sleep(100 * time.Millisecond)

	client, err := net.Dial("udp", "127.0.0.1:19191")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if err := gw.RemoveUDPRoute("echo"); err != nil {
		t.Fatalf("remove route failed: %v", err)
	}

	select {
	case <-sessionClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("udp session was not closed within timeout after route removal — likely leaked")
	}
}
