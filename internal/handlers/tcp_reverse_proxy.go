package handlers

import (
	"io"
	"net"

	"github.com/aidanhopper/gateway/internal/gateway"
)

type TCPReverseProxy struct {
	Dial func() (net.Conn, error)
}

func NewTCPReverseProxy(address string) *TCPReverseProxy {
	return &TCPReverseProxy{
		Dial: func() (net.Conn, error) {
			return net.Dial("tcp", address)
		},
	}
}

func (p *TCPReverseProxy) ServeTCP(conn net.Conn, metadata gateway.TCPMetadata) {
	upstream, err := p.Dial()
	if err != nil {
		return
	}
	defer upstream.Close()

	errCh := make(chan struct{}, 2)

	go func() {
		io.Copy(upstream, conn)
		errCh <- struct{}{}
	}()

	go func() {
		io.Copy(conn, upstream)
		errCh <- struct{}{}
	}()

	// Wait until either direction closes
	<-errCh

	// Force the other copy loop to exit
	upstream.Close()
	conn.Close()
}
