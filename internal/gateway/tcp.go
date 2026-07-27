package gateway

import (
	"bufio"
	"fmt"
	"net"
	"time"
)

type TCPInfo struct {
	LocalAddr  *net.TCPAddr
	RemoteAddr *net.TCPAddr
}

type tcpConn struct {
	net.Conn
	reader *bufio.Reader

	tcpInfo       *TCPInfo
	tlsInfo       *TLSInfo
	minecraftInfo *MinecraftInfo
	isHTTP        bool

	tcpChecked       bool
	tlsChecked       bool
	minecraftChecked bool
	httpChecked      bool
}

func newTCPConn(conn net.Conn) *tcpConn {
	return &tcpConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (c *tcpConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *tcpConn) Peek(n int) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer c.SetReadDeadline(time.Time{})

	return c.reader.Peek(n)
}

func (c *tcpConn) GetTCPInfo() (*TCPInfo, error) {
	if c.tcpChecked {
		return c.tcpInfo, nil
	}

	c.tcpChecked = true

	localAddr, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("local address is not a TCP address")
	}

	remoteAddr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("remote address is not a TCP address")
	}

	c.tcpInfo = &TCPInfo{
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
	}

	return c.tcpInfo, nil
}

type TCPHandler interface {
	Handle(conn net.Conn) error
}

type TCPConn interface {
	GetMinecraftInfo() (*MinecraftInfo, error)
	GetTCPInfo() (*TCPInfo, error)
	GetTLSInfo() (*TLSInfo, error)
}
