package gateway

import (
	"bufio"
	"fmt"
	"net"
)

type TCPMetadata struct {
	Minecraft *MinecraftInfo
	TCP       *TCPInfo
	TLS       *TLSInfo
}

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
	return c.reader.Peek(n)
}

func (c *tcpConn) getTCPInfo() (*TCPInfo, error) {
	if c.tcpChecked {
		return c.tcpInfo, nil
	}

	c.tcpChecked = true

	localAddr, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("local address is not a tcp address")
	}

	remoteAddr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("remote address is not a tcp address")
	}

	c.tcpInfo = &TCPInfo{
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
	}

	return c.tcpInfo, nil
}

type TCPHandler interface {
	ServeTCP(conn net.Conn, metadata TCPMetadata)
}

type TCPHandlerFunc func(conn net.Conn, metadata TCPMetadata)

func (f TCPHandlerFunc) ServeTCP(conn net.Conn, metadata TCPMetadata) {
	f(conn, metadata)
}

func newTCPMetadata(conn *tcpConn) TCPMetadata {
	minecraftInfo, _ := conn.getMinecraftInfo()
	tlsInfo, _ := conn.getTLSInfo()
	tcpInfo, _ := conn.getTCPInfo()

	return TCPMetadata{
		Minecraft: minecraftInfo,
		TLS:       tlsInfo,
		TCP:       tcpInfo,
	}
}
