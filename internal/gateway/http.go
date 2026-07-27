package gateway

import (
	"bytes"
)

var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("PATCH "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
}

func (c *tcpConn) IsHTTP() bool {
	if c.httpChecked {
		return c.isHTTP
	}
	c.httpChecked = true

	b, err := c.Peek(8) // longest method is "OPTIONS"

	if err != nil {
		return false
	}

	for _, method := range httpMethods {
		if bytes.HasPrefix(b, method) {
			c.isHTTP = true
			return true
		}
	}

	return false
}
