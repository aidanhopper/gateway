package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
)

// TODO: Change gateway to compiile routes based on priority when adding a removing.
//
//	Would be better than sorting the routes by priority for every request.
type Gateway struct {
	httpRoutes map[string]*HTTPRoute
	tcpRoutes  map[string]*TCPRoute
	listeners  map[string]*Listener
}

func New() *Gateway {
	return &Gateway{
		httpRoutes: make(map[string]*HTTPRoute),
		tcpRoutes:  make(map[string]*TCPRoute),
		listeners:  make(map[string]*Listener),
	}
}

func (gw *Gateway) AddTCPRoute(route TCPRoute) error {
	if _, ok := gw.tcpRoutes[route.Name]; ok {
		return fmt.Errorf("tcp route %s is already present within the gateway", route.Name)
	}

	gw.tcpRoutes[route.Name] = &route

	return nil
}

func (gw *Gateway) RemoveTCPRoute(name string) error {
	if _, ok := gw.tcpRoutes[name]; !ok {
		return fmt.Errorf("route %s does not exist within the gateway", name)
	}

	delete(gw.tcpRoutes, name)

	return nil
}

func (gw *Gateway) AddHTTPRoute(route HTTPRoute) error {
	if _, ok := gw.httpRoutes[route.Name]; ok {
		return fmt.Errorf("http route %s is already present within the gateway", route.Name)
	}

	gw.httpRoutes[route.Name] = &route

	return nil
}

func (gw *Gateway) RemoveHTTPRoute(name string) error {
	if _, ok := gw.httpRoutes[name]; !ok {
		return fmt.Errorf("http %s does not exist within the gateway", name)
	}

	delete(gw.httpRoutes, name)

	return nil
}

func (gw *Gateway) AddListener(listener Listener) error {
	if _, ok := gw.listeners[listener.Name]; ok {
		return fmt.Errorf("listener %s is already present within the gateway", listener.Name)
	}

	gw.listeners[listener.Name] = &listener

	return nil
}

func (gw *Gateway) RemoveListener(name string) error {
	if _, ok := gw.listeners[name]; !ok {
		return fmt.Errorf("listener %s does not exist within the gateway", name)
	}

	delete(gw.listeners, name)

	return nil
}

func (gw *Gateway) Listen(ctx context.Context) error {
	for _, listener := range gw.listeners {
		ln, err := net.Listen(string(listener.Protocol), listener.Address)
		if err != nil {
			return err
		}

		go gw.acceptLoop(ctx, listener.Name, ln)
	}

	select {}
}

func (gw *Gateway) acceptLoop(ctx context.Context, lnName string, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go gw.handleConnection(ctx, lnName, conn)
	}
}

func (gw *Gateway) handleConnection(ctx context.Context, lnName string, conn net.Conn) {
	protocol, err := getProtocol(conn.LocalAddr().Network())
	if err != nil {
		conn.Close()
		log.Println(err)
		return
	}

	switch protocol {
	case ProtoTCP:
		tcpConn := newTCPConn(conn)

		if tcpConn != nil {
			gw.handleTCPConnection(ctx, lnName, tcpConn)
		} else {
			conn.Close()
		}
	case ProtoUDP:
		defer conn.Close()
		gw.handleUDPConnection(ctx, conn)
	}
}

func (gw *Gateway) matchTCP(lnName string, conn *tcpConn) *TCPRoute {
	routes := make([]*TCPRoute, 0, len(gw.tcpRoutes))

	for _, route := range gw.tcpRoutes {
		routes = append(routes, route)
	}

	slices.SortFunc(routes, func(a, b *TCPRoute) int {
		return b.Priority - a.Priority // higher priority first
	})

	for _, route := range routes {
		if route.Listener == lnName && route.Rule.Match(conn) {
			return route
		}
	}

	return nil
}

func (gw *Gateway) matchHTTP(r *http.Request, lnName string) *HTTPRoute {
	routes := make([]*HTTPRoute, 0, len(gw.httpRoutes))

	for _, route := range gw.httpRoutes {
		routes = append(routes, route)
	}

	slices.SortFunc(routes, func(a, b *HTTPRoute) int {
		return b.Priority - a.Priority // higher priority first
	})

	for _, route := range routes {
		if route.Listener == lnName && route.Rule.Match(r) {
			return route
		}
	}

	return nil
}

func (gw *Gateway) handleTCPConnection(ctx context.Context, lnName string, conn *tcpConn) {
	if route := gw.matchTCP(lnName, conn); route != nil {
		defer conn.Close()
		route.Handler.Handle(conn)
	} else if conn.IsTLS() {
		gw.handleTLSConnection(ctx, lnName, conn)
	} else if conn.IsHTTP() {
		gw.handleHTTPConnection(ctx, lnName, conn)
	}
}

func (gw *Gateway) handleTLSConnection(ctx context.Context, lnName string, conn *tcpConn) {
	listener := gw.listeners[lnName]

	tlsInfo, err := conn.GetTLSInfo()
	if err != nil {
		log.Println(err)
		return
	}

	if listener.TLSHandler == nil {
		log.Printf("no tls handler configured for listener %s\n", lnName)
		return
	}

	config, err := listener.TLSHandler.Handle(tlsInfo)
	if err != nil {
		log.Println(err)
		return
	}

	tlsConn := tls.Server(conn, config)
	err = tlsConn.Handshake()
	if err != nil {
		log.Println(err)
		return
	}

	gw.handleHTTPConnection(ctx, lnName, tlsConn)
}

func (gw *Gateway) handleHTTPConnection(ctx context.Context, lnName string, conn net.Conn) {
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route := gw.matchHTTP(r, lnName)

			if route == nil {
				http.NotFound(w, r)
				return
			}

			route.Handler.ServeHTTP(w, r)
		}),
	}

	ln := &singleConnListener{
		conn: conn,
	}

	err := server.Serve(ln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Println(err)
	}
}

func (gw *Gateway) handleUDPConnection(ctx context.Context, conn net.Conn) {}
