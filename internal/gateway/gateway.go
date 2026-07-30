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
	"strings"
	"sync"
	"time"
)

// MinecraftInfoSpec represents Minecraft protocol metadata in log events.
type MinecraftInfoSpec struct {
	RequestedHost   string `json:"requested_host,omitempty"`
	RequestedPort   uint16 `json:"requested_port,omitempty"`
	ProtocolState   int    `json:"protocol_state,omitempty"` // 1 = status ping, 2 = login
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	Username        string `json:"username,omitempty"`
	IsLoginStart    bool   `json:"is_login_start,omitempty"`
}

// LogEvent is emitted for every proxied request/connection through the Gateway.
type LogEvent struct {
	Timestamp     time.Time          `json:"timestamp"`
	Protocol      string             `json:"protocol"` // "http", "tcp", "udp", "minecraft"
	Route         string             `json:"route"`
	Listener      string             `json:"listener"`
	Method        string             `json:"method,omitempty"`
	Path          string             `json:"path,omitempty"`
	Status        int                `json:"status,omitempty"`
	DurationMs    int64              `json:"duration_ms"`
	RemoteIP      string             `json:"remote_ip"`
	Error         string             `json:"error,omitempty"`
	MinecraftInfo *MinecraftInfoSpec `json:"minecraft_info,omitempty"`
}

// SystemLogger is an optional callback to route gateway internal system logs.
var SystemLogger func(level, component, format string, args ...any)

func logSystemFallback(level, component, format string, args ...any) {
	if SystemLogger != nil {
		SystemLogger(level, component, format, args...)
		return
	}
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	lvlPadded := fmt.Sprintf("%-5s", strings.ToUpper(strings.TrimSpace(level)))
	compPadded := fmt.Sprintf("%-8s", strings.ToUpper(strings.TrimSpace(component)))
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] [%s] [%s] %s\n", timeStr, lvlPadded, compPadded, msg)
}

// LogInfo logs an informational message.
func LogInfo(component, format string, args ...any) {
	logSystemFallback("INFO", component, format, args...)
}

// LogWarn logs a warning message.
func LogWarn(component, format string, args ...any) {
	logSystemFallback("WARN", component, format, args...)
}

// LogError logs an error message.
func LogError(component, format string, args ...any) {
	logSystemFallback("ERROR", component, format, args...)
}

// statusResponseWriter captures the status code written by a downstream handler.
type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *statusResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// TODO: Change gateway to compile routes based on priority when adding/removing.
//
//	Would be better than sorting the routes by priority for every request.
type Gateway struct {
	mu sync.RWMutex

	httpRoutes map[string]*HTTPRoute
	tcpRoutes  map[string]*TCPRoute
	udpRoutes  map[string]*UDPRoute

	listeners map[string]*Listener

	tcpListenerStates map[string]*tcpListenerState
	udpListenerStates map[string]*udpListenerState

	running bool

	ctx context.Context

	// OnLogEvent is called after each proxied request/connection. Thread-safe.
	OnLogEvent func(event LogEvent)
}

// emitLog fires OnLogEvent if set, without holding any locks.
func (gw *Gateway) emitLog(ev LogEvent) {
	gw.mu.RLock()
	fn := gw.OnLogEvent
	gw.mu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

func New() *Gateway {
	return &Gateway{
		httpRoutes:        make(map[string]*HTTPRoute),
		tcpRoutes:         make(map[string]*TCPRoute),
		udpRoutes:         make(map[string]*UDPRoute),
		listeners:         make(map[string]*Listener),
		tcpListenerStates: make(map[string]*tcpListenerState),
		udpListenerStates: make(map[string]*udpListenerState),
	}
}

func (gw *Gateway) AddTCPRoute(route TCPRoute) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if _, ok := gw.tcpRoutes[route.Name]; ok {
		return fmt.Errorf("tcp route %s is already present within the gateway", route.Name)
	}

	gw.tcpRoutes[route.Name] = &route

	return nil
}

func (gw *Gateway) RemoveTCPRoute(name string) error {
	gw.mu.Lock()
	route, ok := gw.tcpRoutes[name]
	if !ok {
		gw.mu.Unlock()
		return fmt.Errorf("tcp route %s does not exist within the gateway", name)
	}
	delete(gw.tcpRoutes, name)
	state := gw.tcpListenerStates[route.Listener]
	gw.mu.Unlock()

	if state != nil {
		state.closeRoute(name)
	}
	return nil
}

func (gw *Gateway) AddUDPRoute(route UDPRoute) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if _, ok := gw.udpRoutes[route.Name]; ok {
		return fmt.Errorf("udp route %s is already present within the gateway", route.Name)
	}

	gw.udpRoutes[route.Name] = &route

	return nil
}

func (gw *Gateway) RemoveUDPRoute(name string) error {
	gw.mu.Lock()
	route, ok := gw.udpRoutes[name]
	if !ok {
		gw.mu.Unlock()
		return fmt.Errorf("udp route %s does not exist within the gateway", name)
	}
	delete(gw.udpRoutes, name)
	state := gw.udpListenerStates[route.Listener]
	gw.mu.Unlock()

	if state != nil {
		state.closeRoute(name)
	}
	return nil
}

func (gw *Gateway) AddHTTPRoute(route HTTPRoute) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if _, ok := gw.httpRoutes[route.Name]; ok {
		return fmt.Errorf("http route %s is already present within the gateway", route.Name)
	}

	gw.httpRoutes[route.Name] = &route

	return nil
}

func (gw *Gateway) RemoveHTTPRoute(name string) error {
	gw.mu.Lock()
	route, ok := gw.httpRoutes[name]
	if !ok {
		gw.mu.Unlock()
		return fmt.Errorf("http route %s does not exist within the gateway", name)
	}
	delete(gw.httpRoutes, name)
	state := gw.tcpListenerStates[route.Listener]
	gw.mu.Unlock()

	if state != nil {
		state.closeRoute(name)
	}

	return nil
}

func (gw *Gateway) AddListener(listener Listener) error {
	gw.mu.Lock()
	if _, ok := gw.listeners[listener.Name]; ok {
		gw.mu.Unlock()
		return fmt.Errorf("listener %s is already present within the gateway", listener.Name)
	}
	gw.listeners[listener.Name] = &listener
	running := gw.running
	gw.mu.Unlock()

	if running {
		if err := gw.startListener(listener.Name); err != nil {
			gw.mu.Lock()
			delete(gw.listeners, listener.Name)
			gw.mu.Unlock()
			return err
		}
	}

	return nil
}

func (gw *Gateway) RemoveListener(name string) error {
	gw.mu.Lock()
	if _, ok := gw.listeners[name]; !ok {
		gw.mu.Unlock()
		return fmt.Errorf("listener %s does not exist within the gateway", name)
	}
	delete(gw.listeners, name)
	for routeName, route := range gw.tcpRoutes {
		if route.Listener == name {
			delete(gw.tcpRoutes, routeName)
		}
	}
	for routeName, route := range gw.httpRoutes {
		if route.Listener == name {
			delete(gw.httpRoutes, routeName)
		}
	}
	for routeName, route := range gw.udpRoutes {
		if route.Listener == name {
			delete(gw.udpRoutes, routeName)
		}
	}
	gw.mu.Unlock()

	gw.stopListener(name)
	return nil
}

func (gw *Gateway) Listen(ctx context.Context) error {
	gw.mu.Lock()
	if gw.running {
		gw.mu.Unlock()
		return errors.New("gateway is already listening")
	}
	gw.running = true
	gw.ctx = ctx
	names := make([]string, 0, len(gw.listeners))
	for name := range gw.listeners {
		names = append(names, name)
	}
	gw.mu.Unlock()

	for _, name := range names {
		if err := gw.startListener(name); err != nil {
			return err
		}
	}

	<-ctx.Done()

	gw.mu.Lock()
	stopNames := make(map[string]struct{})
	for name := range gw.tcpListenerStates {
		stopNames[name] = struct{}{}
	}
	for name := range gw.udpListenerStates {
		stopNames[name] = struct{}{}
	}
	gw.running = false
	gw.mu.Unlock()

	for name := range stopNames {
		gw.stopListener(name)
	}

	return ctx.Err()
}

func (gw *Gateway) tcpAcceptLoop(ctx context.Context, lnName string, ln net.Listener, state *tcpListenerState) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				LogWarn("LISTENER", "listener %s accept error: %v", lnName, err)
				return
			}
		}
		state.registerConn("", conn)
		remoteAddr := conn.RemoteAddr().String()
		LogInfo("LISTENER", "accepted connection from %s on listener %s (active conns: %d)", remoteAddr, lnName, state.connCount())

		go func(c net.Conn, rAddr string) {
			start := time.Now()
			defer func() {
				state.unregisterConn("", c)
				dur := time.Since(start).Truncate(time.Millisecond)
				LogInfo("LISTENER", "connection from %s on listener %s closed (duration: %v, active conns: %d)", rAddr, lnName, dur, state.connCount())
			}()
			gw.handleConnection(ctx, lnName, c)
		}(conn, remoteAddr)
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
		if tcpConn := newTCPConn(conn); tcpConn != nil {
			gw.handleTCPConnection(ctx, lnName, tcpConn)
		} else {
			conn.Close()
		}
	}
}

func (gw *Gateway) matchUDP(lnName string, meta UDPMetadata) *UDPRoute {
	gw.mu.RLock()
	routes := make([]*UDPRoute, 0, len(gw.udpRoutes))
	for _, route := range gw.udpRoutes {
		routes = append(routes, route)
	}
	gw.mu.RUnlock()

	slices.SortFunc(routes, func(a, b *UDPRoute) int {
		return b.Priority - a.Priority
	})

	for _, route := range routes {
		if route.Listener == lnName && route.Rule.Match(meta) {
			return route
		}
	}
	return nil
}

func (gw *Gateway) matchTCP(lnName string, conn *tcpConn) *TCPRoute {
	gw.mu.RLock()
	routes := make([]*TCPRoute, 0, len(gw.tcpRoutes))
	for _, route := range gw.tcpRoutes {
		routes = append(routes, route)
	}
	gw.mu.RUnlock()

	slices.SortFunc(routes, func(a, b *TCPRoute) int {
		return b.Priority - a.Priority // higher priority first
	})

	for _, route := range routes {
		if route.Listener == lnName && route.Rule.Match(newTCPMetadata(conn)) {
			return route
		}
	}

	return nil
}

func (gw *Gateway) matchHTTP(r *http.Request, lnName string) *HTTPRoute {
	gw.mu.RLock()
	routes := make([]*HTTPRoute, 0, len(gw.httpRoutes))
	for _, route := range gw.httpRoutes {
		routes = append(routes, route)
	}
	gw.mu.RUnlock()

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
		gw.mu.RLock()
		state, ok := gw.tcpListenerStates[lnName]
		gw.mu.RUnlock()
		if !ok {
			conn.Close()
			log.Printf("could not get listener state for %s\n", lnName)
			return
		}

		state.registerConn(route.Name, conn)
		defer state.unregisterConn(route.Name, conn)
		defer conn.Close()

		start := time.Now()
		remoteAddr := conn.RemoteAddr().String()
		meta := newTCPMetadata(conn)

		proto := "tcp"
		if meta.Minecraft != nil {
			proto = "minecraft"
		}

		var mc *MinecraftInfoSpec
		if meta.Minecraft != nil {
			mc = &MinecraftInfoSpec{
				RequestedHost:   meta.Minecraft.RequestedHost,
				RequestedPort:   meta.Minecraft.RequestedPort,
				ProtocolState:   meta.Minecraft.ProtocolState,
				ProtocolVersion: meta.Minecraft.ProtocolVersion,
				Username:        meta.Minecraft.Username,
				IsLoginStart:    meta.Minecraft.IsLoginStart,
			}
		}

		gw.emitLog(LogEvent{
			Timestamp:     start,
			Protocol:      proto,
			Route:         route.Name,
			Listener:      lnName,
			RemoteIP:      remoteAddr,
			MinecraftInfo: mc,
		})

		route.Handler.ServeTCP(conn, meta)
	} else if conn.IsTLS() {
		gw.handleTLSConnection(ctx, lnName, conn)
	} else if conn.IsHTTP() {
		gw.handleHTTPConnection(ctx, lnName, conn)
	} else {
		conn.Close()
	}
}

func (gw *Gateway) handleTLSConnection(ctx context.Context, lnName string, conn *tcpConn) {
	gw.mu.RLock()
	listener, ok := gw.listeners[lnName]
	gw.mu.RUnlock()
	if !ok {
		LogWarn("GATEWAY", "listener %s no longer exists", lnName)
		return
	}

	tlsInfo, err := conn.getTLSInfo()
	if err != nil {
		LogWarn("GATEWAY", "listener %s failed to parse TLS info: %v", lnName, err)
		return
	}

	if listener.TLSHandler == nil {
		LogWarn("GATEWAY", "no TLS handler configured for listener %s", lnName)
		return
	}

	tlsConfig, err := listener.TLSHandler.Handle(tlsInfo)
	if err != nil {
		LogWarn("GATEWAY", "listener %s TLS config error: %v", lnName, err)
		return
	}

	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		LogWarn("GATEWAY", "listener %s TLS handshake failed from %s: %v", lnName, conn.RemoteAddr(), err)
		tlsConn.Close()
		return
	}

	gw.handleHTTPConnection(ctx, lnName, tlsConn)
}

func (gw *Gateway) handleHTTPConnection(ctx context.Context, lnName string, conn net.Conn) {
	gw.mu.RLock()
	state, ok := gw.tcpListenerStates[lnName]
	gw.mu.RUnlock()
	if !ok {
		conn.Close()
		LogWarn("GATEWAY", "could not get listener state for %s", lnName)
		return
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route := gw.matchHTTP(r, lnName)
			if route == nil {
				http.NotFound(w, r)
				return
			}

			state.registerConn(route.Name, conn)
			defer state.unregisterConn(route.Name, conn)

			start := time.Now()
			rw := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			route.Handler.ServeHTTP(rw, r)
			gw.emitLog(LogEvent{
				Timestamp:  start,
				Protocol:   "http",
				Route:      route.Name,
				Listener:   lnName,
				Method:     r.Method,
				Path:       r.URL.Path,
				Status:     rw.statusCode,
				DurationMs: time.Since(start).Milliseconds(),
				RemoteIP:   r.RemoteAddr,
			})
		}),
	}

	ln := &singleConnListener{conn: conn}
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		LogWarn("GATEWAY", "listener %s HTTP server error: %v", lnName, err)
	}
}

func (gw *Gateway) stopListener(name string) {
	gw.stopTCPListener(name)
	gw.stopUDPListener(name)
}

func (gw *Gateway) stopTCPListener(name string) {
	gw.mu.Lock()
	state, ok := gw.tcpListenerStates[name]
	if ok {
		delete(gw.tcpListenerStates, name)
	}
	gw.mu.Unlock()
	if !ok {
		return
	}
	state.cancel()
	state.ln.Close()
	state.closeAll()
	state.wg.Wait()
}

func (gw *Gateway) stopUDPListener(name string) {
	gw.mu.Lock()
	state, ok := gw.udpListenerStates[name]
	if ok {
		delete(gw.udpListenerStates, name)
	}
	gw.mu.Unlock()
	if !ok {
		return
	}
	state.cancel()
	state.pc.Close()
	state.closeAll() // force-close any sessions still running
	state.wg.Wait()
}

func (gw *Gateway) startListener(name string) error {
	gw.mu.Lock()
	cfg, ok := gw.listeners[name]
	gw.mu.Unlock()
	if !ok {
		return fmt.Errorf("listener %s does not exist within the gateway", name)
	}

	switch cfg.Protocol {
	case ProtoTCP:
		return gw.startTCPListener(name, cfg)
	case ProtoUDP:
		return gw.startUDPListener(name, cfg)
	default:
		return fmt.Errorf("listener %s has unsupported protocol %s", name, cfg.Protocol)
	}
}

func (gw *Gateway) startTCPListener(name string, cfg *Listener) error {
	ln, err := net.Listen(string(cfg.Protocol), cfg.Address)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(gw.ctx)
	state := &tcpListenerState{
		ln:     ln,
		cancel: cancel,
		conns:  make(map[string]map[net.Conn]struct{}),
	}

	gw.mu.Lock()
	if _, ok := gw.listeners[name]; !ok {
		gw.mu.Unlock()
		cancel()
		ln.Close()
		return nil
	}
	gw.tcpListenerStates[name] = state
	gw.mu.Unlock()

	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		gw.tcpAcceptLoop(ctx, name, ln, state)
	}()

	return nil
}

func (gw *Gateway) startUDPListener(name string, cfg *Listener) error {
	gw.mu.Lock()
	if _, running := gw.udpListenerStates[name]; running {
		gw.mu.Unlock()
		return nil
	}
	gw.mu.Unlock()

	pc, err := net.ListenPacket(string(cfg.Protocol), cfg.Address)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(gw.ctx)
	state := &udpListenerState{pc: pc, cancel: cancel, sessions: make(map[string]map[*udpSession]struct{})}

	gw.mu.Lock()
	if _, ok := gw.listeners[name]; !ok {
		gw.mu.Unlock()
		cancel()
		pc.Close()
		return nil
	}
	gw.udpListenerStates[name] = state
	gw.mu.Unlock()

	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		gw.handleUDPConnection(ctx, name, pc, state)
	}()

	return nil
}

func (gw *Gateway) handleUDPConnection(ctx context.Context, lnName string, pc net.PacketConn, state *udpListenerState) {
	buf := make([]byte, 65535)
	var sessMu sync.Mutex
	sessions := make(map[string]*udpSession) // local: addr -> session, for demuxing incoming packets

	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("listener %s: read error: %v\n", lnName, err)
				return
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		key := addr.String()
		sessMu.Lock()
		sess, exists := sessions[key]
		if !exists {
			sess = newUDPSession(pc, addr)
			sessions[key] = sess
		}
		sessMu.Unlock()

		if !exists {
			route := gw.matchUDP(lnName, UDPMetadata{RemoteAddr: addr, LocalAddr: pc.LocalAddr()})
			if route == nil {
				sess.Close()
				sessMu.Lock()
				delete(sessions, key)
				sessMu.Unlock()
				continue
			}

			state.register(route.Name, sess)

			go func() {
				defer func() {
					state.unregister(route.Name, sess)
					sess.Close()
					sessMu.Lock()
					delete(sessions, key)
					sessMu.Unlock()
				}()
				route.Handler.ServeUDP(sess, UDPMetadata{RemoteAddr: addr, LocalAddr: pc.LocalAddr()})
			}()
		}

		sess.push(data)
	}
}

func (gw *Gateway) UpdateTCPRoute(route TCPRoute) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if _, ok := gw.tcpRoutes[route.Name]; !ok {
		return fmt.Errorf("tcp route %s does not exist within the gateway", route.Name)
	}
	gw.tcpRoutes[route.Name] = &route
	return nil
}

func (gw *Gateway) UpdateHTTPRoute(route HTTPRoute) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if _, ok := gw.httpRoutes[route.Name]; !ok {
		return fmt.Errorf("http route %s does not exist within the gateway", route.Name)
	}
	gw.httpRoutes[route.Name] = &route
	return nil
}

func (gw *Gateway) UpdateUDPRoute(route UDPRoute) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if _, ok := gw.udpRoutes[route.Name]; !ok {
		return fmt.Errorf("udp route %s does not exist within the gateway", route.Name)
	}
	gw.udpRoutes[route.Name] = &route
	return nil
}
