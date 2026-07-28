package handlers

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

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
		_, err := clientConn.Write(testMsg)
		if err != nil {
			t.Errorf("client write failed: %v", err)
		}
	}()

	buf := make([]byte, 128)
	n, err := clientConn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("client read failed: %v", err)
	}

	if !bytes.Equal(buf[:n], testMsg) {
		t.Errorf("echo response = %q, want %q", string(buf[:n]), string(testMsg))
	}

	clientConn.Close()

	wg.Wait()
}

func TestTCPReverseProxy(t *testing.T) {
	// Start a mock upstream TCP server
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock upstream: %v", err)
	}
	defer upstreamLn.Close()
	upstreamAddr := upstreamLn.Addr().String()

	// Upstream echo server logic
	go func() {
		for {
			uConn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(uConn)
		}
	}()

	t.Run("Successful Proxy Flow", func(t *testing.T) {
		proxy := NewTCPReverseProxy(upstreamAddr)

		clientConn, gatewayConn := net.Pipe()
		defer clientConn.Close()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.ServeTCP(gatewayConn, gateway.TCPMetadata{})
		}()

		msg := []byte("REVERSE_PROXY_PAYLOAD\n")
		go func() {
			clientConn.Write(msg)
			time.Sleep(20 * time.Millisecond)
			clientConn.Close()
		}()

		buf := make([]byte, 128)
		n, _ := clientConn.Read(buf)

		if !bytes.Equal(buf[:n], msg) {
			t.Errorf("proxy output = %q, want %q", string(buf[:n]), string(msg))
		}

		wg.Wait()
	})

	t.Run("Failed Upstream Dial", func(t *testing.T) {
		proxy := NewTCPReverseProxy("127.0.0.1:59999") // Unreachable port

		clientConn, gatewayConn := net.Pipe()
		defer clientConn.Close()
		defer gatewayConn.Close()

		// ServeTCP should immediately return when upstream dial fails
		proxy.ServeTCP(gatewayConn, gateway.TCPMetadata{})
	})
}
