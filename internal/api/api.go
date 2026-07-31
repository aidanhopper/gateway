package api

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aidanhopper/gateway/internal/acme"
	"github.com/aidanhopper/gateway/internal/config"
	"github.com/aidanhopper/gateway/internal/firewall"
	"github.com/aidanhopper/gateway/internal/gateway"
)

type routeEntry struct {
	spec    RouteSpec
	handler any // live handler instance (shared with gateway)
}

// API manages REST API request routing, SQLite persistence, and spec state.
type API struct {
	gw             *gateway.Gateway
	db             *sql.DB
	fw             firewall.Manager
	public         bool
	startTime      time.Time
	mu             sync.RWMutex
	listeners      map[string]ListenerSpec
	routes         map[string]routeEntry
	listenerTimers map[string]*time.Timer
	routeTimers    map[string]*time.Timer
}

// New creates and initializes an API instance, rehydrating listeners and routes from the database.
// isPublic indicates whether this daemon is exposed to the open Internet; the value is
// sourced from ~/.config/gateway/server.yaml or the GATEWAY_PUBLIC env var.
func New(gw *gateway.Gateway, db *sql.DB, fw firewall.Manager, isPublic bool) (*API, error) {
	if gw == nil {
		return nil, errors.New("gateway instance cannot be nil")
	}
	if db == nil {
		return nil, errors.New("database instance cannot be nil")
	}
	if fw == nil {
		fw = firewall.NewNoopManager()
	}

	api := &API{
		gw:             gw,
		db:             db,
		fw:             fw,
		public:         isPublic,
		startTime:      time.Now(),
		listeners:      make(map[string]ListenerSpec),
		routes:         make(map[string]routeEntry),
		listenerTimers: make(map[string]*time.Timer),
		routeTimers:    make(map[string]*time.Timer),
	}

	if err := api.rehydrate(); err != nil {
		return nil, fmt.Errorf("failed to rehydrate state from db: %w", err)
	}

	// Wire gateway and firewall system loggers into the SSE broadcasters.
	log.SetFlags(0)
	gateway.SystemLogger = LogSystem
	firewall.Logger = func(level, format string, args ...any) {
		LogSystem(level, "FIREWALL", format, args...)
	}
	gw.OnLogEvent = func(event gateway.LogEvent) {
		DefaultLogBroadcaster.Broadcast(event)
	}

	return api, nil
}

func buildTLSHandler(spec *TLSConfigSpec) (gateway.TLSConfigHandler, error) {
	if spec == nil {
		return nil, nil
	}

	var sessionTicketKey [32]byte
	_, _ = rand.Read(sessionTicketKey[:])

	devCert, _ := acme.GenerateSelfSignedCert(spec.Domains)

	if spec.Auto {
		serverCfg, _ := config.LoadServerConfig()
		acmeCfg := acme.Config{
			Domains: spec.Domains,
		}
		if serverCfg != nil {
			acmeCfg.Email = serverCfg.ACMEEmail
			acmeCfg.Directory = serverCfg.ACMEDirectory
			acmeCfg.CloudflareToken = serverCfg.ACMECloudflareToken
		}
		acmeMgr, err := acme.NewManager(acmeCfg)
		if err != nil {
			LogWarn("ACME", "failed to initialize ACME auto-cert manager: %v", err)
			hasPublicDomain := false
			for _, d := range spec.Domains {
				dStr := strings.ToLower(strings.TrimSpace(d))
				if dStr != "" && dStr != "localhost" && !strings.HasSuffix(dStr, ".localhost") && !strings.HasSuffix(dStr, ".local") && net.ParseIP(dStr) == nil {
					hasPublicDomain = true
					break
				}
			}
			if hasPublicDomain {
				return nil, fmt.Errorf("failed to initialize ACME auto-cert manager: %w", err)
			}
		} else if acmeMgr != nil {
			if !acmeMgr.HasDNSProvider() {
				LogWarn("ACME", "no Cloudflare DNS API token provided for DNS-01 solver (set cloudflare_token in server.yml or CF_DNS_API_TOKEN)")
			} else {
				for _, d := range spec.Domains {
					if d != "" && d != "localhost" && !strings.HasSuffix(d, ".localhost") && strings.Contains(d, ".") {
						LogInfo("ACME", "obtaining wildcard cert for %s via Cloudflare DNS-01...", d)
						if _, err := acmeMgr.ObtainWildcardCertificate(d); err != nil {
							LogWarn("ACME", "failed to obtain wildcard cert for %s: %v", d, err)
						} else {
							LogInfo("ACME", "successfully obtained and cached wildcard cert for %s", d)
						}
					}
				}
			}
			return gateway.TLSConfigHandlerFunc(func(info *gateway.TLSInfo) (*tls.Config, error) {
				getCertFunc := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					sni := info.SNI
					if hello != nil && hello.ServerName != "" {
						sni = hello.ServerName
					}
					cert, err := acmeMgr.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
					if err == nil && cert != nil {
						return cert, nil
					}
					if devCert != nil {
						return devCert, nil
					}
					return nil, err
				}

				cert, _ := getCertFunc(&tls.ClientHelloInfo{ServerName: info.SNI})
				var certs []tls.Certificate
				if cert != nil {
					certs = []tls.Certificate{*cert}
				}
				return &tls.Config{
					Certificates:     certs,
					GetCertificate:   getCertFunc,
					SessionTicketKey: sessionTicketKey,
				}, nil
			}), nil
		}
	}

	if spec.Cert != "" && spec.Key != "" {
		cert, err := tls.X509KeyPair([]byte(spec.Cert), []byte(spec.Key))
		if err == nil {
		tlsConfig := &tls.Config{
			Certificates:     []tls.Certificate{cert},
			SessionTicketKey: sessionTicketKey,
		}
		return gateway.TLSConfigHandlerFunc(func(info *gateway.TLSInfo) (*tls.Config, error) {
			return tlsConfig, nil
		}), nil
		}
	}

	// Default fallback: Generate self-signed cert for local dev HTTPS (.localhost, localhost, or when ACME email is unset)
	if devCert != nil {
		tlsConfig := &tls.Config{
			Certificates:     []tls.Certificate{*devCert},
			SessionTicketKey: sessionTicketKey,
		}
		return gateway.TLSConfigHandlerFunc(func(info *gateway.TLSInfo) (*tls.Config, error) {
			return tlsConfig, nil
		}), nil
	}

	return nil, nil
}

func (a *API) rehydrate() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 1. Load listeners
	rows, err := a.db.Query("SELECT name, spec FROM listeners")
	if err != nil {
		return fmt.Errorf("failed to query listeners: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name, specJSON string
		if err := rows.Scan(&name, &specJSON); err != nil {
			return err
		}

		var spec ListenerSpec
		if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
			LogWarn("API", "rehydrate: failed to unmarshal listener %s: %v", name, err)
			continue
		}

		tlsHandler, err := buildTLSHandler(spec.TLS)
		if err != nil {
			LogWarn("API", "rehydrate: failed to build TLS handler for listener %s: %v", name, err)
		}

		gwListener := gateway.Listener{
			Name:       spec.Name,
			Address:    spec.Address,
			Protocol:   gateway.Protocol(spec.Protocol),
			TLSHandler: tlsHandler,
		}

		if err := a.gw.AddListener(gwListener); err != nil {
			LogWarn("LISTENER", "listener %s (%s/%s) failed to bind: %v", spec.Name, spec.Address, spec.Protocol, err)
		} else {
			LogInfo("LISTENER", "bound listener %s on %s (%s)", spec.Name, spec.Address, spec.Protocol)
		}

		// Ensure firewall port is opened
		if port, err := firewall.ParsePort(spec.Address); err == nil {
			_ = a.fw.OpenPort(spec.Protocol, port)
		}

		// Setup TTL timer if spec.TTL > 0
		if spec.TTL > 0 {
			lName := spec.Name
			a.listenerTimers[lName] = time.AfterFunc(time.Duration(spec.TTL)*time.Second, func() {
				a.deleteListenerByName(lName)
			})
		}

		a.listeners[spec.Name] = spec
	}

	// 2. Load routes
	routeRows, err := a.db.Query("SELECT name, spec FROM routes")
	if err != nil {
		return fmt.Errorf("failed to query routes: %w", err)
	}
	defer routeRows.Close()

	for routeRows.Next() {
		var name, specJSON string
		if err := routeRows.Scan(&name, &specJSON); err != nil {
			return err
		}

		var spec RouteSpec
		if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
			LogWarn("API", "rehydrate: failed to unmarshal route %s: %v", name, err)
			continue
		}

		// Check if referenced listener exists
		if _, exists := a.listeners[spec.Listener]; !exists {
			LogWarn("API", "rehydrate: skipping route %s because listener %s does not exist", spec.Name, spec.Listener)
			continue
		}

		if err := a.addRouteToGateway(spec); err != nil {
			LogWarn("API", "rehydrate: failed to load route %s: %v", spec.Name, err)
		} else {
			LogInfo("ROUTE", "loaded route %s on listener %s", spec.Name, spec.Listener)
			if spec.TTL > 0 {
				rName := spec.Name
				a.routeTimers[rName] = time.AfterFunc(time.Duration(spec.TTL)*time.Second, func() {
					LogInfo("ROUTE", "route %s TTL expired, auto-deleting", rName)
					a.deleteRouteByName(rName)
				})
			}
		}
	}

	LogInfo("API", "rehydrated %d listeners and %d routes from database", len(a.listeners), len(a.routes))
	return nil
}

func (a *API) addRouteToGateway(spec RouteSpec) error {
	handlerObj, err := buildHandler(spec.Protocol, spec.Handler)
	if err != nil {
		return fmt.Errorf("failed to build handler: %w", err)
	}

	ruleObj, err := buildRule(spec.Protocol, spec.Rule)
	if err != nil {
		return fmt.Errorf("failed to build rule: %w", err)
	}

	switch spec.Protocol {
	case "tcp":
		tcpHandler, ok := handlerObj.(gateway.TCPHandler)
		if !ok {
			return fmt.Errorf("handler is not a TCPHandler")
		}
		tcpRule, ok := ruleObj.(gateway.TCPRule)
		if !ok {
			return fmt.Errorf("rule is not a TCPRule")
		}
		route := gateway.TCPRoute{
			Name:     spec.Name,
			Listener: spec.Listener,
			Priority: spec.Priority,
			Handler:  tcpHandler,
			Rule:     tcpRule,
		}
		if err := a.gw.AddTCPRoute(route); err != nil {
			return err
		}

	case "http":
		httpHandler, ok := handlerObj.(http.Handler)
		if !ok {
			return fmt.Errorf("handler is not an http.Handler")
		}
		httpRule, ok := ruleObj.(gateway.HTTPRule)
		if !ok {
			return fmt.Errorf("rule is not an HTTPRule")
		}

		route := gateway.HTTPRoute{
			Name:     spec.Name,
			Listener: spec.Listener,
			Priority: spec.Priority,
			Handler:  httpHandler,
			Rule:     httpRule,
		}
		if err := a.gw.AddHTTPRoute(route); err != nil {
			return err
		}

	case "udp":
		udpHandler, ok := handlerObj.(gateway.UDPHandler)
		if !ok {
			return fmt.Errorf("handler is not a UDPHandler")
		}
		udpRule, ok := ruleObj.(gateway.UDPRule)
		if !ok {
			return fmt.Errorf("rule is not a UDPRule")
		}
		route := gateway.UDPRoute{
			Name:     spec.Name,
			Listener: spec.Listener,
			Priority: spec.Priority,
			Handler:  udpHandler,
			Rule:     udpRule,
		}
		if err := a.gw.AddUDPRoute(route); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported protocol %q", spec.Protocol)
	}

	a.routes[spec.Name] = routeEntry{
		spec:    spec,
		handler: handlerObj,
	}

	return nil
}

// NewHandler creates an http.Handler for the REST API with all endpoints and auth middleware registered.
func NewHandler(api *API) http.Handler {
	mux := http.NewServeMux()

	// Health endpoint (unauthenticated)
	mux.HandleFunc("GET /api/v1/health", api.handleHealth)

	// Authenticated routes wrapper
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == "" || authHeader == token {
				LogWarn("API", "unauthorized API request from %s (error: missing or malformed bearer token)", r.RemoteAddr)
				writeError(w, http.StatusUnauthorized, "unauthorized: missing or malformed bearer token")
				return
			}

			valid, err := ValidateToken(api.db, token)
			if err != nil || !valid {
				LogWarn("API", "unauthorized API request from %s (error: invalid bearer token)", r.RemoteAddr)
				writeError(w, http.StatusUnauthorized, "unauthorized: invalid token")
				return
			}

			h(w, r)
		}
	}

	// Listener endpoints
	mux.HandleFunc("GET /api/v1/listeners", auth(api.handleListListeners))
	mux.HandleFunc("GET /api/v1/listeners/{name}", auth(api.handleGetListener))
	mux.HandleFunc("POST /api/v1/listeners", auth(api.handleCreateListener))
	mux.HandleFunc("DELETE /api/v1/listeners/{name}", auth(api.handleDeleteListener))

	// Route endpoints
	mux.HandleFunc("GET /api/v1/routes", auth(api.handleListRoutes))
	mux.HandleFunc("GET /api/v1/routes/{name}", auth(api.handleGetRoute))
	mux.HandleFunc("POST /api/v1/routes", auth(api.handleCreateRoute))
	mux.HandleFunc("PUT /api/v1/routes/{name}", auth(api.handleUpdateRoute))
	mux.HandleFunc("DELETE /api/v1/routes/{name}", auth(api.handleDeleteRoute))

	// Serve endpoints for web apps, web UI dashboards, cURL, and remote clients
	mux.HandleFunc("GET /api/v1/serve", auth(api.handleListServeMounts))
	mux.HandleFunc("GET /api/v1/serve/{name}", auth(api.handleGetServeMount))
	mux.HandleFunc("POST /api/v1/serve/http", auth(api.handleServeHTTP))
	mux.HandleFunc("POST /api/v1/serve/https", auth(api.handleServeHTTPS))
	mux.HandleFunc("POST /api/v1/serve/static", auth(api.handleServeStatic))
	mux.HandleFunc("POST /api/v1/serve/redirect", auth(api.handleServeRedirect))
	mux.HandleFunc("POST /api/v1/serve/tcp", auth(api.handleServeTCP))
	mux.HandleFunc("POST /api/v1/serve/udp", auth(api.handleServeUDP))
	mux.HandleFunc("POST /api/v1/serve/minecraft", auth(api.handleServeMinecraft))
	mux.HandleFunc("DELETE /api/v1/serve/{name}", auth(api.handleServeDelete))
	mux.HandleFunc("POST /api/v1/serve/reset", auth(api.handleServeReset))

	// Log streaming endpoints
	mux.HandleFunc("GET /api/v1/logs/stream", auth(api.handleStreamLogs))
	mux.HandleFunc("GET /api/v1/logs/system", auth(api.handleStreamSystemLogs))

	return mux
}

// --- Handler Functions ---

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	listenerCount := len(a.listeners)
	routeCount := len(a.routes)
	a.mu.RUnlock()

	dbStatus := "ok"
	if err := a.db.Ping(); err != nil {
		dbStatus = fmt.Sprintf("error: %v", err)
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	resp := map[string]any{
		"status":          "ok",
		"public":          a.public,
		"uptime_seconds":  int(time.Since(a.startTime).Seconds()),
		"goroutines":      runtime.NumGoroutine(),
		"alloc_bytes":     memStats.Alloc,
		"sys_bytes":       memStats.Sys,
		"database":        dbStatus,
		"listeners_count": listenerCount,
		"routes_count":    routeCount,
	}

	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleListListeners(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]ListenerSpec, 0, len(a.listeners))
	for _, l := range a.listeners {
		result = append(result, l)
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": result})
}

func (a *API) handleGetListener(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	a.mu.RLock()
	spec, ok := a.listeners[name]
	a.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("listener %s not found", name))
		return
	}

	writeJSON(w, http.StatusOK, spec)
}

func (a *API) handleCreateListener(w http.ResponseWriter, r *http.Request) {
	var spec ListenerSpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1048576)).Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if spec.Name == "" || spec.Address == "" || (spec.Protocol != "tcp" && spec.Protocol != "udp") {
		writeError(w, http.StatusBadRequest, "listener name, address, and protocol (tcp|udp) are required")
		return
	}

	port, err := firewall.ParsePort(spec.Address)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid listener address: %v", err))
		return
	}

	tlsHandler, err := buildTLSHandler(spec.TLS)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid TLS config: %v", err))
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.listeners[spec.Name]; exists {
		writeError(w, http.StatusConflict, fmt.Sprintf("listener %s already exists", spec.Name))
		return
	}

	gwListener := gateway.Listener{
		Name:       spec.Name,
		Address:    spec.Address,
		Protocol:   gateway.Protocol(spec.Protocol),
		TLSHandler: tlsHandler,
	}

	if err := a.gw.AddListener(gwListener); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to bind listener on %s (%s): %v", spec.Address, spec.Protocol, err))
		return
	}

	// Open OS Firewall port
	if err := a.fw.OpenPort(spec.Protocol, port); err != nil {
		_ = a.gw.RemoveListener(spec.Name)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to open firewall port: %v", err))
		return
	}

	specJSON, _ := json.Marshal(spec)
	if _, err := a.db.Exec("INSERT INTO listeners (name, spec) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET spec = excluded.spec", spec.Name, string(specJSON)); err != nil {
		_ = a.fw.ClosePort(spec.Protocol, port)
		_ = a.gw.RemoveListener(spec.Name)
		writeError(w, http.StatusInternalServerError, "failed to persist listener to database")
		return
	}

	if spec.TTL > 0 {
		lName := spec.Name
		a.listenerTimers[lName] = time.AfterFunc(time.Duration(spec.TTL)*time.Second, func() {
			a.deleteListenerByName(lName)
		})
	}

	a.listeners[spec.Name] = spec
	writeJSON(w, http.StatusCreated, spec)
}

func (a *API) handleDeleteListener(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := a.deleteListenerByName(name); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("listener %s deleted", name)})
}

func (a *API) deleteListenerByName(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	spec, exists := a.listeners[name]
	if !exists {
		return fmt.Errorf("listener %s not found", name)
	}

	// Stop listener TTL timer if active
	if timer, ok := a.listenerTimers[name]; ok {
		timer.Stop()
		delete(a.listenerTimers, name)
	}

	port, _ := firewall.ParsePort(spec.Address)

	// Cascade delete child routes from DB and cache
	var childRoutes []string
	for rName, entry := range a.routes {
		if entry.spec.Listener == name {
			childRoutes = append(childRoutes, rName)
		}
	}

	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("database transaction error: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM listeners WHERE name = ?", name); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete listener from db: %w", err)
	}

	for _, cName := range childRoutes {
		if _, err := tx.Exec("DELETE FROM routes WHERE name = ?", cName); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to cascade delete child route from db: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit db deletion: %w", err)
	}

	// Close OS firewall port
	if port > 0 {
		_ = a.fw.ClosePort(spec.Protocol, port)
	}

	// Remove from Gateway live state and local cache
	_ = a.gw.RemoveListener(name)
	delete(a.listeners, name)
	for _, cName := range childRoutes {
		if timer, ok := a.routeTimers[cName]; ok {
			timer.Stop()
			delete(a.routeTimers, cName)
		}
		delete(a.routes, cName)
	}

	return nil
}

func (a *API) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	protocolFilter := r.URL.Query().Get("protocol")
	listenerFilter := r.URL.Query().Get("listener")

	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]RouteSpec, 0, len(a.routes))
	for _, entry := range a.routes {
		if protocolFilter != "" && entry.spec.Protocol != protocolFilter {
			continue
		}
		if listenerFilter != "" && entry.spec.Listener != listenerFilter {
			continue
		}
		result = append(result, entry.spec)
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": result})
}

func (a *API) handleGetRoute(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	a.mu.RLock()
	entry, ok := a.routes[name]
	a.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("route %s not found", name))
		return
	}

	resp := map[string]any{
		"name":     entry.spec.Name,
		"protocol": entry.spec.Protocol,
		"listener": entry.spec.Listener,
		"priority": entry.spec.Priority,
		"rule":     entry.spec.Rule,
		"handler":  entry.spec.Handler,
	}

	if entry.spec.TTL > 0 {
		resp["ttl"] = entry.spec.TTL
	}

	// Check if live handler implements Informer interface
	if informer, ok := entry.handler.(gateway.Informer); ok {
		infoJSON := informer.Info()
		if len(infoJSON) > 0 {
			handlerBlock := map[string]any{
				"type":   entry.spec.Handler.Type,
				"config": entry.spec.Handler.Config,
				"info":   infoJSON,
			}
			resp["handler"] = handlerBlock
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	var spec RouteSpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1048576)).Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if spec.Name == "" || spec.Listener == "" || spec.Protocol == "" {
		writeError(w, http.StatusBadRequest, "route name, listener, and protocol are required")
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.routes[spec.Name]; exists {
		writeError(w, http.StatusConflict, fmt.Sprintf("route %s already exists", spec.Name))
		return
	}

	if _, listenerExists := a.listeners[spec.Listener]; !listenerExists {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("listener %s does not exist", spec.Listener))
		return
	}

	if err := a.addRouteToGateway(spec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	specJSON, _ := json.Marshal(spec)
	if _, err := a.db.Exec("INSERT INTO routes (name, spec) VALUES (?, ?)", spec.Name, string(specJSON)); err != nil {
		a.removeRouteFromGateway(spec.Protocol, spec.Name)
		delete(a.routes, spec.Name)
		writeError(w, http.StatusInternalServerError, "failed to persist route to database")
		return
	}

	if spec.TTL > 0 {
		rName := spec.Name
		a.routeTimers[rName] = time.AfterFunc(time.Duration(spec.TTL)*time.Second, func() {
			a.deleteRouteByName(rName)
		})
	}

	writeJSON(w, http.StatusCreated, spec)
}

func (a *API) handleUpdateRoute(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var spec RouteSpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1048576)).Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	spec.Name = name

	a.mu.Lock()
	defer a.mu.Unlock()

	existing, exists := a.routes[name]
	if !exists {
		writeError(w, http.StatusNotFound, fmt.Sprintf("route %s not found", name))
		return
	}

	if _, listenerExists := a.listeners[spec.Listener]; !listenerExists {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("listener %s does not exist", spec.Listener))
		return
	}

	// Rebuild live handler & rule
	handlerObj, err := buildHandler(spec.Protocol, spec.Handler)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid handler: %v", err))
		return
	}

	ruleObj, err := buildRule(spec.Protocol, spec.Rule)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid rule: %v", err))
		return
	}

	switch spec.Protocol {
	case "tcp":
		tcpHandler, _ := handlerObj.(gateway.TCPHandler)
		tcpRule, _ := ruleObj.(gateway.TCPRule)
		route := gateway.TCPRoute{
			Name:     spec.Name,
			Listener: spec.Listener,
			Priority: spec.Priority,
			Handler:  tcpHandler,
			Rule:     tcpRule,
		}
		if err := a.gw.UpdateTCPRoute(route); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

	case "http":
		httpHandler, _ := handlerObj.(http.Handler)
		httpRule, _ := ruleObj.(gateway.HTTPRule)
		route := gateway.HTTPRoute{
			Name:     spec.Name,
			Listener: spec.Listener,
			Priority: spec.Priority,
			Handler:  httpHandler,
			Rule:     httpRule,
		}
		if err := a.gw.UpdateHTTPRoute(route); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

	case "udp":
		udpHandler, _ := handlerObj.(gateway.UDPHandler)
		udpRule, _ := ruleObj.(gateway.UDPRule)
		route := gateway.UDPRoute{
			Name:     spec.Name,
			Listener: spec.Listener,
			Priority: spec.Priority,
			Handler:  udpHandler,
			Rule:     udpRule,
		}
		if err := a.gw.UpdateUDPRoute(route); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported protocol %q", spec.Protocol))
		return
	}

	specJSON, _ := json.Marshal(spec)
	if _, err := a.db.Exec("UPDATE routes SET spec = ? WHERE name = ?", string(specJSON), name); err != nil {
		// Rollback to existing
		_ = a.addRouteToGateway(existing.spec)
		writeError(w, http.StatusInternalServerError, "failed to update route in database")
		return
	}

	if timer, ok := a.routeTimers[name]; ok {
		timer.Stop()
		delete(a.routeTimers, name)
	}

	if spec.TTL > 0 {
		rName := spec.Name
		a.routeTimers[rName] = time.AfterFunc(time.Duration(spec.TTL)*time.Second, func() {
			a.deleteRouteByName(rName)
		})
	}

	a.routes[name] = routeEntry{
		spec:    spec,
		handler: handlerObj,
	}

	writeJSON(w, http.StatusOK, spec)
}

func (a *API) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := a.DeleteRoute(name); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("route %s deleted", name)})
}

// AddListener registers and persists a ListenerSpec on the API instance.
func (a *API) AddListener(spec ListenerSpec) error {
	if spec.Name == "" || spec.Address == "" || (spec.Protocol != "tcp" && spec.Protocol != "udp") {
		return fmt.Errorf("listener name, address, and protocol (tcp|udp) are required")
	}

	port, err := firewall.ParsePort(spec.Address)
	if err != nil {
		return fmt.Errorf("invalid listener address: %w", err)
	}

	tlsHandler, err := buildTLSHandler(spec.TLS)
	if err != nil {
		return fmt.Errorf("invalid TLS config: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.listeners[spec.Name]; exists {
		_ = a.gw.RemoveListener(spec.Name)
	}

	gwListener := gateway.Listener{
		Name:       spec.Name,
		Address:    spec.Address,
		Protocol:   gateway.Protocol(spec.Protocol),
		TLSHandler: tlsHandler,
	}

	if err := a.gw.AddListener(gwListener); err != nil {
		return err
	}

	if err := a.fw.OpenPort(spec.Protocol, port); err != nil {
		_ = a.gw.RemoveListener(spec.Name)
		return fmt.Errorf("failed to open firewall port: %w", err)
	}

	specJSON, _ := json.Marshal(spec)
	if _, err := a.db.Exec("INSERT INTO listeners (name, spec) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET spec = excluded.spec", spec.Name, string(specJSON)); err != nil {
		_ = a.fw.ClosePort(spec.Protocol, port)
		_ = a.gw.RemoveListener(spec.Name)
		return fmt.Errorf("failed to persist listener to database: %w", err)
	}

	if spec.TTL > 0 {
		lName := spec.Name
		a.listenerTimers[lName] = time.AfterFunc(time.Duration(spec.TTL)*time.Second, func() {
			a.DeleteListener(lName)
		})
	}

	a.listeners[spec.Name] = spec
	return nil
}

// AddRoute registers and persists a RouteSpec on the API instance.
func (a *API) AddRoute(spec RouteSpec) error {
	if spec.Name == "" || spec.Listener == "" || spec.Protocol == "" {
		return fmt.Errorf("route name, listener, and protocol are required")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.routes[spec.Name]; exists {
		return fmt.Errorf("route %s already exists", spec.Name)
	}

	if _, listenerExists := a.listeners[spec.Listener]; !listenerExists {
		return fmt.Errorf("listener %s does not exist", spec.Listener)
	}

	if err := a.addRouteToGateway(spec); err != nil {
		return err
	}

	specJSON, _ := json.Marshal(spec)
	if _, err := a.db.Exec("INSERT INTO routes (name, spec) VALUES (?, ?)", spec.Name, string(specJSON)); err != nil {
		a.removeRouteFromGateway(spec.Protocol, spec.Name)
		delete(a.routes, spec.Name)
		return fmt.Errorf("failed to persist route to database: %w", err)
	}

	if spec.TTL > 0 {
		rName := spec.Name
		a.routeTimers[rName] = time.AfterFunc(time.Duration(spec.TTL)*time.Second, func() {
			a.DeleteRoute(rName)
		})
	}

	return nil
}

// DeleteRoute deletes a route by name.
func (a *API) DeleteRoute(name string) error {
	return a.deleteRouteByName(name)
}

// DeleteListener deletes a listener by name.
func (a *API) DeleteListener(name string) error {
	return a.deleteListenerByName(name)
}

func (a *API) deleteRouteByName(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry, exists := a.routes[name]
	if !exists {
		return fmt.Errorf("route %s not found", name)
	}

	if timer, ok := a.routeTimers[name]; ok {
		timer.Stop()
		delete(a.routeTimers, name)
	}

	if _, err := a.db.Exec("DELETE FROM routes WHERE name = ?", name); err != nil {
		return fmt.Errorf("failed to delete route from db: %w", err)
	}

	a.removeRouteFromGateway(entry.spec.Protocol, name)
	delete(a.routes, name)

	return nil
}

func (a *API) removeRouteFromGateway(protocol string, name string) {
	switch protocol {
	case "tcp":
		_ = a.gw.RemoveTCPRoute(name)
	case "http":
		_ = a.gw.RemoveHTTPRoute(name)
	case "udp":
		_ = a.gw.RemoveUDPRoute(name)
	}
}

// --- JSON Helpers ---

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
