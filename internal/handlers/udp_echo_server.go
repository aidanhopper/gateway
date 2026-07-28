package handlers

import (
	"io"
	"log"
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
				log.Printf("udp echo: read error: %v\n", err)
			}
			return
		}

		if _, err := conn.Write(buf[:n]); err != nil {
			log.Printf("udp echo: write error: %v\n", err)
			return
		}
	}
}
