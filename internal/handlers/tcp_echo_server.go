package handlers

import (
	"io"
	"net"

	"github.com/aidanhopper/gateway/internal/gateway"
)

func NewTCPEchoServer() gateway.TCPHandler {
	return gateway.TCPHandlerFunc(func(conn net.Conn, metadata gateway.TCPMetadata) {
		_, err := io.Copy(conn, conn)
		if err != nil {
			return
		}
	})
}
