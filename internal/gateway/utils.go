package gateway

import (
	"io"
	"net"
	"time"
)

type singleConnListener struct {
	conn net.Conn
	addr net.Addr
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{
		conn: conn,
		addr: conn.LocalAddr(),
	}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}

	conn := l.conn
	l.conn = nil

	return conn, nil
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}

type peekConn struct {
	io.Reader
}

func (pc *peekConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
}

func (pc *peekConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (pc *peekConn) Close() error {
	return nil
}

func (pc *peekConn) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (pc *peekConn) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (pc *peekConn) SetDeadline(time.Time) error {
	return nil
}

func (pc *peekConn) SetReadDeadline(time.Time) error {
	return nil
}

func (pc *peekConn) SetWriteDeadline(time.Time) error {
	return nil
}

type dummyAddr string

func (d dummyAddr) Network() string {
	return "tcp"
}

func (d dummyAddr) String() string {
	return string(d)
}
