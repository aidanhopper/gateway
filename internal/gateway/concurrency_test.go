package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestConcurrentRouteMutations(t *testing.T) {
	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind listener: %v", err)
	}
	addr := dummyLn.Addr().String()
	dummyLn.Close()

	gw := New()
	if err := gw.AddListener(Listener{Name: "web", Address: addr, Protocol: ProtoTCP}); err != nil {
		t.Fatalf("AddListener failed: %v", err)
	}

	// Add initial base HTTP route
	if err := gw.AddHTTPRoute(HTTPRoute{
		Name:     "base",
		Listener: "web",
		Rule:     Path("/base"),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}); err != nil {
		t.Fatalf("AddHTTPRoute base failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = gw.Listen(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	workers := 20
	requestsPerWorker := 30

	// 1. Worker goroutines hitting HTTP endpoint continuously
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 500 * time.Millisecond}
			for j := 0; j < requestsPerWorker; j++ {
				resp, err := client.Get(fmt.Sprintf("http://%s/base", addr))
				if err == nil {
					resp.Body.Close()
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// 2. Concurrently mutating routes on the fly
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			routeName := fmt.Sprintf("dynamic-route-%d", id)
			for j := 0; j < 10; j++ {
				_ = gw.AddHTTPRoute(HTTPRoute{
					Name:     routeName,
					Listener: "web",
					Rule:     Path(fmt.Sprintf("/path-%d", id)),
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
					}),
				})

				_ = gw.UpdateHTTPRoute(HTTPRoute{
					Name:     routeName,
					Listener: "web",
					Priority: j + 1,
					Rule:     Path(fmt.Sprintf("/path-%d", id)),
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
					}),
				})

				_ = gw.RemoveHTTPRoute(routeName)
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}

func TestContextShutdownUnderActiveStreaming(t *testing.T) {
	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind listener: %v", err)
	}
	addr := dummyLn.Addr().String()
	dummyLn.Close()

	gw := New()
	_ = gw.AddListener(Listener{Name: "stream-ln", Address: addr, Protocol: ProtoTCP})
	_ = gw.AddTCPRoute(TCPRoute{
		Name:     "stream-route",
		Listener: "stream-ln",
		Rule:     Any[TCPMetadata](),
		Handler: TCPHandlerFunc(func(conn net.Conn, metadata TCPMetadata) {
			// Stream data continuously until context cancel
			for {
				_, err := conn.Write([]byte("STREAMING_CHUNK\n"))
				if err != nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}),
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- gw.Listen(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Dial client connection and send data so protocol sniffing completes
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	_, _ = conn.Write([]byte("STREAM_REQ\n"))

	// Read one chunk
	buf := make([]byte, 128)
	_, _ = conn.Read(buf)

	// Cancel gateway context while client is actively streaming
	cancel()

	select {
	case listenErr := <-errCh:
		if listenErr != context.Canceled {
			t.Errorf("Listen error = %v, want context.Canceled", listenErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("gw.Listen failed to unblock and exit on context cancel")
	}

	conn.Close()
}
