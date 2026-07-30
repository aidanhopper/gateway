package gateway

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestTLSClientHelloSniffing(t *testing.T) {
	t.Run("Valid TLS ClientHello with SNI and ALPN", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		go func() {
			defer clientConn.Close()
			tlsClient := tls.Client(clientConn, &tls.Config{
				ServerName:         "gateway.example.com",
				NextProtos:         []string{"h2", "http/1.1"},
				InsecureSkipVerify: true,
			})
			_ = tlsClient.Handshake()
		}()

		tcp := newTCPConn(serverConn)

		isHello, err := isClientHello(tcp)
		if err != nil {
			t.Fatalf("isClientHello error: %v", err)
		}
		if !isHello {
			t.Fatalf("isClientHello returned false for real TLS handshake")
		}

		if !tcp.IsTLS() {
			t.Errorf("IsTLS() returned false")
		}

		info, err := tcp.getTLSInfo()
		if err != nil {
			t.Fatalf("getTLSInfo error: %v", err)
		}
		if info == nil {
			t.Fatalf("expected non-nil TLSInfo")
		}

		if info.SNI != "gateway.example.com" {
			t.Errorf("SNI = %q, want %q", info.SNI, "gateway.example.com")
		}

		foundH2 := false
		foundHTTP11 := false
		for _, proto := range info.ALPN {
			if proto == "h2" {
				foundH2 = true
			}
			if proto == "http/1.1" {
				foundHTTP11 = true
			}
		}
		if !foundH2 || !foundHTTP11 {
			t.Errorf("ALPN = %v, want h2 and http/1.1", info.ALPN)
		}

		// Check caching
		cachedInfo, _ := tcp.getTLSInfo()
		if cachedInfo != info {
			t.Errorf("cached TLSInfo mismatch")
		}
	})

	t.Run("Non-TLS Stream (Plain Text)", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		go func() {
			defer clientConn.Close()
			clientConn.Write([]byte("HELLO RAW TCP DATA\n"))
		}()

		tcp := newTCPConn(serverConn)

		isHello, err := isClientHello(tcp)
		if err != nil {
			t.Fatalf("isClientHello error: %v", err)
		}
		if isHello {
			t.Errorf("isClientHello returned true for plain text")
		}

		if tcp.IsTLS() {
			t.Errorf("IsTLS() returned true for plain text")
		}

		info, err := tcp.getTLSInfo()
		if err != nil {
			t.Fatalf("unexpected error for non-TLS: %v", err)
		}
		if info != nil {
			t.Errorf("expected nil TLSInfo for plain text stream, got %+v", info)
		}
	})

	t.Run("TLSConfigHandlerFunc Execution", func(t *testing.T) {
		handler := TLSConfigHandlerFunc(func(info *TLSInfo) (*tls.Config, error) {
			if info.SNI != "test.domain" {
				t.Errorf("handler received SNI %q, want test.domain", info.SNI)
			}
			return &tls.Config{}, nil
		})

		cfg, err := handler.Handle(&TLSInfo{SNI: "test.domain"})
		if err != nil {
			t.Fatalf("handler returned error: %v", err)
		}
		if cfg == nil {
			t.Fatalf("handler returned nil config")
		}
	})
}
