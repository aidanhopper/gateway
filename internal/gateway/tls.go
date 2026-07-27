package gateway

import (
	"bytes"
	"crypto/tls"
	"io"
)

type TLSInfo struct {
	SNI             string
	ALPN            []string
	SupportedTLSVer []uint16
}

func isClientHello(conn *tcpConn) (bool, error) {
	bytes, err := conn.Peek(1)
	if err != nil {
		return false, err
	}
	return bytes[0] == 0x16, nil
}

func (c *tcpConn) getTLSInfo() (*TLSInfo, error) {
	if c.tlsChecked {
		return c.tlsInfo, nil
	}

	c.tlsChecked = true

	const tlsRecordHeaderLen = 5

	header, err := c.Peek(tlsRecordHeaderLen)
	if err != nil {
		return nil, err
	}

	// TLS Handshake record
	if header[0] != 0x16 {
		return nil, nil
	}

	payloadLen := int(header[3])<<8 | int(header[4])
	totalPeekLen := tlsRecordHeaderLen + payloadLen

	peekedBytes, err := c.Peek(totalPeekLen)
	if err != nil {
		return nil, err
	}

	var hello *tls.ClientHelloInfo

	testConn := &peekConn{
		Reader: bytes.NewReader(peekedBytes),
	}

	config := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = info
			return nil, io.EOF
		},
	}

	tlsConn := tls.Server(testConn, config)

	err = tlsConn.Handshake()
	if err != nil && err != io.EOF {
		return nil, err
	}

	if hello == nil {
		return nil, nil
	}

	c.tlsInfo = &TLSInfo{
		SNI:             hello.ServerName,
		ALPN:            hello.SupportedProtos,
		SupportedTLSVer: hello.SupportedVersions,
	}

	return c.tlsInfo, nil
}

func (c *tcpConn) IsTLS() bool {
	info, _ := c.getTLSInfo()
	return info != nil
}

type TLSConfigHandler interface {
	Handle(*TLSInfo) (*tls.Config, error)
}

type TLSConfigHandlerFunc func(info *TLSInfo) (*tls.Config, error)

func (f TLSConfigHandlerFunc) Handle(info *TLSInfo) (*tls.Config, error) {
	return f(info)
}
