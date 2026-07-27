package gateway

import "net/http"

type TCPRoute struct {
	Name     string
	Listener string
	Handler  TCPHandler
	Rule     TCPRule
	Priority int
}

type HTTPRoute struct {
	Name     string
	Listener string
	Handler  http.Handler
	Rule     HTTPRule
	Priority int
}
