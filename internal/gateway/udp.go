package gateway

import (
	"io"
	"net"
	"sync"
	"time"
)

type UDPMetadata struct {
	RemoteAddr net.Addr
	LocalAddr  net.Addr
}

type udpSession struct {
	pc         net.PacketConn
	remoteAddr net.Addr

	readCh    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

type UDPHandler interface {
	ServeUDP(conn net.Conn, metadata UDPMetadata)
}

type UDPHandlerFunc func(conn net.Conn, metadata UDPMetadata)

func (f UDPHandlerFunc) ServeUDP(conn net.Conn, metadata UDPMetadata) {
	f(conn, metadata)
}

func newUDPSession(pc net.PacketConn, remoteAddr net.Addr) *udpSession {
	return &udpSession{
		pc:         pc,
		remoteAddr: remoteAddr,
		readCh:     make(chan []byte, 64),
		closed:     make(chan struct{}),
	}
}

func (s *udpSession) push(data []byte) {
	select {
	case s.readCh <- data:
	case <-s.closed:
	default: // buffer full — drop rather than block the demux loop
	}
}

func (s *udpSession) Read(b []byte) (int, error) {
	select {
	case data, ok := <-s.readCh:
		if !ok {
			return 0, io.EOF
		}
		return copy(b, data), nil
	case <-s.closed:
		return 0, io.EOF
	}
}

func (s *udpSession) Write(b []byte) (int, error) {
	return s.pc.WriteTo(b, s.remoteAddr)
}

func (s *udpSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *udpSession) LocalAddr() net.Addr              { return s.pc.LocalAddr() }
func (s *udpSession) RemoteAddr() net.Addr             { return s.remoteAddr }
func (s *udpSession) SetDeadline(time.Time) error      { return nil }
func (s *udpSession) SetReadDeadline(time.Time) error  { return nil }
func (s *udpSession) SetWriteDeadline(time.Time) error { return nil }
