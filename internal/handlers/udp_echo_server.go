package handlers

import (
	"io"
	"net"

	"github.com/aidanhopper/gateway/internal/gateway"
)

type udpEchoServer struct{}

func NewUDPEchoServer() gateway.UDPHandler {
	return &udpEchoServer{}
}

func (s *udpEchoServer) ServeUDP(conn net.Conn, metadata gateway.UDPMetadata) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				gateway.LogError("UDP", "echo read error: %v", err)
			}
			return
		}

		if _, err := conn.Write(buf[:n]); err != nil {
			gateway.LogError("UDP", "echo write error: %v", err)
			return
		}
	}
}
