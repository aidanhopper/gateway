package gateway

import (
	"net"
	"testing"
)

func TestIsHTTPMethodDetection(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    bool
	}{
		{"GET request", "GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
		{"POST request", "POST /api/login HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
		{"PUT request", "PUT /resource/1 HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
		{"DELETE request", "DELETE /resource/1 HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
		{"PATCH request", "PATCH /resource/1 HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
		{"HEAD request", "HEAD /status HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
		{"OPTIONS request", "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
		{"CONNECT request", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n", true},
		{"TRACE request", "TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
		{"SSH Protocol Header", "SSH-2.0-OpenSSH_8.9\r\n", false},
		{"Random binary stream", "\x00\x01\x02\x03\x04\x05\x06\x07", false},
		{"Plain text", "Hello World Gateway\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()

			go func() {
				defer clientConn.Close()
				clientConn.Write([]byte(tt.payload))
			}()

			tcp := newTCPConn(serverConn)
			got := tcp.IsHTTP()

			if got != tt.want {
				t.Errorf("IsHTTP() = %v, want %v for payload %q", got, tt.want, tt.payload)
			}

			// Verify cached result returns same
			if tcp.IsHTTP() != got {
				t.Errorf("cached IsHTTP() result mismatch")
			}
		})
	}
}

func TestIsHTTPTruncatedStream(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()
		clientConn.Write([]byte("GET")) // Only 3 bytes, short of 8 bytes Peek
	}()

	tcp := newTCPConn(serverConn)
	if tcp.IsHTTP() {
		t.Errorf("IsHTTP() returned true for truncated 3-byte stream")
	}
}
