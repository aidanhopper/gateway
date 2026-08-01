package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ServeRequestHTTP holds payload for POST /api/v1/serve/http
type ServeRequestHTTP struct {
	Mount    string `json:"mount"`
	Target   string `json:"target"`
	Priority int    `json:"priority,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
}

// ServeRequestHTTPS holds payload for POST /api/v1/serve/https
type ServeRequestHTTPS struct {
	Mount      string `json:"mount"`
	Target     string `json:"target"`
	ListenAddr string `json:"listen_addr,omitempty"`
	Priority   int    `json:"priority,omitempty"`
	ACME       bool   `json:"acme,omitempty"`
	NoRedirect bool   `json:"no_redirect,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
}


// ServeRequestRedirect holds payload for POST /api/v1/serve/redirect
type ServeRequestRedirect struct {
	Mount         string `json:"mount"`
	TargetURL     string `json:"target_url"`
	StatusCode    int    `json:"status_code,omitempty"`
	Exact         bool   `json:"exact,omitempty"`
	NoForwardPath bool   `json:"no_forward_path,omitempty"`
	NoQuery       bool   `json:"no_query,omitempty"`
	Priority      int    `json:"priority,omitempty"`
	TTL           int    `json:"ttl,omitempty"`
	ACME          bool   `json:"acme,omitempty"`
}

// ServeRequestPort holds payload for POST /api/v1/serve/tcp and udp
type ServeRequestPort struct {
	ListenPort string `json:"listen_port"`
	Target     string `json:"target"`
	Priority   int    `json:"priority,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
}

// ServeRequestMinecraft holds payload for POST /api/v1/serve/minecraft
type ServeRequestMinecraft struct {
	HostOrPort string `json:"host_or_port"`
	Target     string `json:"target,omitempty"`
	Priority   int    `json:"priority,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
}

// ServeMountItem represents summary format for GET /api/v1/serve
type ServeMountItem struct {
	Name      string `json:"name"`
	Listener  string `json:"listener"`
	Protocol  string `json:"protocol"`
	Match     string `json:"match"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl,omitempty"`
	ExpiresIn string `json:"expires_in"`
}

func (a *API) handleListServeMounts(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var items []ServeMountItem
	now := time.Now()

	for _, entry := range a.routes {
		spec := entry.spec
		if strings.HasPrefix(spec.Name, "serve-") {
			expiresIn := "never"
			if spec.TTL > 0 {
				rem := time.Duration(spec.TTL)*time.Second - now.Sub(a.startTime)
				if rem > 0 {
					expiresIn = rem.Round(time.Second).String()
				} else {
					expiresIn = "expired"
				}
			}

			items = append(items, ServeMountItem{
				Name:      spec.Name,
				Listener:  spec.Listener,
				Protocol:  spec.Protocol,
				Match:     FormatRuleSummary(spec.Rule),
				Target:    FormatTargetsSummary(spec.Handler),
				TTL:       spec.TTL,
				ExpiresIn: expiresIn,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) handleGetServeMount(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	a.mu.RLock()
	entry, exists := a.routes[name]
	a.mu.RUnlock()

	if !exists || !strings.HasPrefix(name, "serve-") {
		writeError(w, http.StatusNotFound, fmt.Sprintf("serve mount %q not found", name))
		return
	}

	spec := entry.spec
	now := time.Now()
	expiresIn := "never"
	if spec.TTL > 0 {
		rem := time.Duration(spec.TTL)*time.Second - now.Sub(a.startTime)
		if rem > 0 {
			expiresIn = rem.Round(time.Second).String()
		} else {
			expiresIn = "expired"
		}
	}

	writeJSON(w, http.StatusOK, ServeMountItem{
		Name:      spec.Name,
		Listener:  spec.Listener,
		Protocol:  spec.Protocol,
		Match:     FormatRuleSummary(spec.Rule),
		Target:    FormatTargetsSummary(spec.Handler),
		TTL:       spec.TTL,
		ExpiresIn: expiresIn,
	})
}

func (a *API) handleServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req ServeRequestHTTP
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.Mount == "" || req.Target == "" {
		writeError(w, http.StatusBadRequest, "fields 'mount' and 'target' are required")
		return
	}

	target := req.Target
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	domain, path := parseMountArg(req.Mount)
	listenerName := "serve-http-80"
	listenAddr := ":80"

	lSpec := ListenerSpec{
		Name:     listenerName,
		Address:  listenAddr,
		Protocol: "tcp",
	}

	if err := a.ensureListenerInternal(lSpec); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to ensure listener: %v", err))
		return
	}

	routeName := fmt.Sprintf("serve-http-%d", time.Now().UnixNano())

	handlerSpec := HandlerSpec{
		Type:   "http_lb",
		Config: map[string]any{"target": target},
	}

	if path != "/" && path != "" {
		inner := handlerSpec
		handlerSpec = HandlerSpec{
			Type:   "http_strip_prefix",
			Config: map[string]any{"prefix": path},
			Next:   &inner,
		}
	}

	var rules []RuleSpec
	rules = append(rules, RuleSpec{Type: "not", Rule: &RuleSpec{Type: "secure"}})
	if domain != "" {
		rules = append(rules, RuleSpec{Type: "host", Value: domain})
	}
	if path != "/" && path != "" {
		rules = append(rules, RuleSpec{Type: "path_prefix", Value: path})
	}

	ruleSpec := rules[0]
	if len(rules) > 1 {
		ruleSpec = RuleSpec{Type: "and", Rules: rules}
	}

	routeSpec := RouteSpec{
		Name:     routeName,
		Protocol: "http",
		Listener: listenerName,
		Priority: calculateServeAutoPriority(ruleSpec, req.Priority),
		TTL:      req.TTL,
		Rule:     ruleSpec,
		Handler:  handlerSpec,
	}

	if err := a.AddRoute(routeSpec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, routeSpec)
}

func (a *API) handleServeHTTPS(w http.ResponseWriter, r *http.Request) {
	var req ServeRequestHTTPS
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.Mount == "" || req.Target == "" {
		writeError(w, http.StatusBadRequest, "fields 'mount' and 'target' are required")
		return
	}

	domainVal, path := parseMountArg(req.Mount)
	target := req.Target
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	lAddr := req.ListenAddr
	if lAddr == "" {
		lAddr = ":443"
	}
	lName := fmt.Sprintf("serve-https-%s", strings.TrimPrefix(lAddr, ":"))

	var tlsSpec *TLSConfigSpec
	useACME := req.ACME
	if useACME || domainVal != "" {
		tlsSpec = &TLSConfigSpec{Auto: useACME}
		if domainVal != "" {
			tlsSpec.Domains = []string{domainVal}
		}
	}

	lSpec := ListenerSpec{
		Name:     lName,
		Address:  lAddr,
		Protocol: "tcp",
		TLS:      tlsSpec,
	}

	if err := a.ensureListenerInternal(lSpec); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to ensure HTTPS listener: %v", err))
		return
	}

	routeName := fmt.Sprintf("serve-https-%d", time.Now().UnixNano())
	var rules []RuleSpec
	rules = append(rules, RuleSpec{Type: "secure"})
	if domainVal != "" {
		rules = append(rules, RuleSpec{Type: "host", Value: domainVal})
	}
	if path != "/" && path != "" {
		rules = append(rules, RuleSpec{Type: "path_prefix", Value: path})
	}

	ruleSpec := rules[0]
	if len(rules) > 1 {
		ruleSpec = RuleSpec{Type: "and", Rules: rules}
	}

	handlerSpec := HandlerSpec{
		Type:   "http_lb",
		Config: map[string]any{"target": target},
	}

	if path != "/" && path != "" {
		inner := handlerSpec
		handlerSpec = HandlerSpec{
			Type:   "http_strip_prefix",
			Config: map[string]any{"prefix": path},
			Next:   &inner,
		}
	}

	routeSpec := RouteSpec{
		Name:     routeName,
		Protocol: "http",
		Listener: lName,
		Priority: calculateServeAutoPriority(ruleSpec, req.Priority),
		TTL:      req.TTL,
		Rule:     ruleSpec,
		Handler:  handlerSpec,
	}

	if err := a.AddRoute(routeSpec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !req.NoRedirect {
		_ = a.ensureListenerInternal(ListenerSpec{Name: "serve-http-80", Address: ":80", Protocol: "tcp"})
		redirectRouteName := fmt.Sprintf("serve-redirect-%s", routeName)
		var rRules []RuleSpec
		rRules = append(rRules, RuleSpec{Type: "not", Rule: &RuleSpec{Type: "secure"}})
		if domainVal != "" {
			rRules = append(rRules, RuleSpec{Type: "host", Value: domainVal})
		}
		if path != "/" && path != "" {
			rRules = append(rRules, RuleSpec{Type: "path_prefix", Value: path})
		}
		rRuleSpec := rRules[0]
		if len(rRules) > 1 {
			rRuleSpec = RuleSpec{Type: "and", Rules: rRules}
		}
		redirectTargetURL := "https://" + domainVal + path
		if domainVal == "" {
			redirectTargetURL = "https://" + path
		}
		_ = a.AddRoute(RouteSpec{
			Name:     redirectRouteName,
			Protocol: "http",
			Listener: "serve-http-80",
			Priority: calculateServeAutoPriority(rRuleSpec, req.Priority),
			TTL:      req.TTL,
			Rule:     rRuleSpec,
			Handler: HandlerSpec{
				Type:   "http_redirect",
				Config: map[string]any{"url": redirectTargetURL, "status": 301},
			},
		})
	}

	writeJSON(w, http.StatusCreated, routeSpec)
}

func (a *API) handleServeRedirect(w http.ResponseWriter, r *http.Request) {
	var req ServeRequestRedirect
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.Mount == "" || req.TargetURL == "" {
		writeError(w, http.StatusBadRequest, "fields 'mount' and 'target_url' are required")
		return
	}

	domain, path := parseMountArg(req.Mount)
	targetURL := req.TargetURL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	status := req.StatusCode
	if status != 301 && status != 302 && status != 307 && status != 308 {
		status = 301
	}

	_ = a.ensureListenerInternal(ListenerSpec{Name: "serve-https-443", Address: ":443", Protocol: "tcp", TLS: &TLSConfigSpec{Auto: req.ACME, Domains: []string{domain}}})
	_ = a.ensureListenerInternal(ListenerSpec{Name: "serve-http-80", Address: ":80", Protocol: "tcp"})

	pathRuleType := "path_prefix"
	if req.Exact {
		pathRuleType = "path"
	}

	handlerConfig := map[string]any{
		"url":          targetURL,
		"status":       float64(status),
		"forward_path": !req.NoForwardPath,
		"strip_prefix": path,
		"keep_query":   !req.NoQuery,
	}

	httpsRouteName := fmt.Sprintf("serve-redirect-https-%d", time.Now().UnixNano())
	var rules []RuleSpec
	rules = append(rules, RuleSpec{Type: "secure"})
	if domain != "" {
		rules = append(rules, RuleSpec{Type: "host", Value: domain})
	}
	if path != "/" && path != "" {
		rules = append(rules, RuleSpec{Type: pathRuleType, Value: path})
	}
	ruleSpec := rules[0]
	if len(rules) > 1 {
		ruleSpec = RuleSpec{Type: "and", Rules: rules}
	}

	httpsRoute := RouteSpec{
		Name:     httpsRouteName,
		Protocol: "http",
		Listener: "serve-https-443",
		Priority: calculateServeAutoPriority(ruleSpec, req.Priority),
		TTL:      req.TTL,
		Rule:     ruleSpec,
		Handler: HandlerSpec{
			Type:   "http_redirect",
			Config: handlerConfig,
		},
	}
	_ = a.AddRoute(httpsRoute)

	httpRouteName := fmt.Sprintf("serve-redirect-http-%d", time.Now().UnixNano())
	var rRules []RuleSpec
	rRules = append(rRules, RuleSpec{Type: "not", Rule: &RuleSpec{Type: "secure"}})
	if domain != "" {
		rRules = append(rRules, RuleSpec{Type: "host", Value: domain})
	}
	if path != "/" && path != "" {
		rRules = append(rRules, RuleSpec{Type: pathRuleType, Value: path})
	}
	rRuleSpec := rRules[0]
	if len(rRules) > 1 {
		rRuleSpec = RuleSpec{Type: "and", Rules: rRules}
	}

	httpRoute := RouteSpec{
		Name:     httpRouteName,
		Protocol: "http",
		Listener: "serve-http-80",
		Priority: calculateServeAutoPriority(rRuleSpec, req.Priority),
		TTL:      req.TTL,
		Rule:     rRuleSpec,
		Handler: HandlerSpec{
			Type:   "http_redirect",
			Config: handlerConfig,
		},
	}
	_ = a.AddRoute(httpRoute)

	writeJSON(w, http.StatusCreated, map[string]any{
		"https_route": httpsRouteName,
		"http_route":  httpRouteName,
		"target_url":   targetURL,
		"status_code":  status,
	})
}

func (a *API) handleServeTCP(w http.ResponseWriter, r *http.Request) {
	var req ServeRequestPort
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.ListenPort == "" || req.Target == "" {
		writeError(w, http.StatusBadRequest, "fields 'listen_port' and 'target' are required")
		return
	}

	listenAddr := ":" + req.ListenPort
	if strings.Contains(req.ListenPort, ":") {
		listenAddr = req.ListenPort
	}
	target := req.Target
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	listenerName := fmt.Sprintf("serve-tcp-%s", strings.TrimPrefix(listenAddr, ":"))
	if err := a.ensureListenerInternal(ListenerSpec{Name: listenerName, Address: listenAddr, Protocol: "tcp"}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	routeName := fmt.Sprintf("serve-tcp-route-%d", time.Now().UnixNano())
	routeSpec := RouteSpec{
		Name:     routeName,
		Protocol: "tcp",
		Listener: listenerName,
		Priority: calculateServeAutoPriority(RuleSpec{Type: "any"}, req.Priority),
		TTL:      req.TTL,
		Rule:     RuleSpec{Type: "any"},
		Handler: HandlerSpec{
			Type:   "tcp_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := a.AddRoute(routeSpec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, routeSpec)
}

func (a *API) handleServeUDP(w http.ResponseWriter, r *http.Request) {
	var req ServeRequestPort
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.ListenPort == "" || req.Target == "" {
		writeError(w, http.StatusBadRequest, "fields 'listen_port' and 'target' are required")
		return
	}

	listenAddr := ":" + req.ListenPort
	if strings.Contains(req.ListenPort, ":") {
		listenAddr = req.ListenPort
	}
	target := req.Target
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	listenerName := fmt.Sprintf("serve-udp-%s", strings.TrimPrefix(listenAddr, ":"))
	if err := a.ensureListenerInternal(ListenerSpec{Name: listenerName, Address: listenAddr, Protocol: "udp"}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	routeName := fmt.Sprintf("serve-udp-route-%d", time.Now().UnixNano())
	routeSpec := RouteSpec{
		Name:     routeName,
		Protocol: "udp",
		Listener: listenerName,
		Priority: calculateServeAutoPriority(RuleSpec{Type: "any"}, req.Priority),
		TTL:      req.TTL,
		Rule:     RuleSpec{Type: "any"},
		Handler: HandlerSpec{
			Type:   "udp_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := a.AddRoute(routeSpec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, routeSpec)
}

func (a *API) handleServeMinecraft(w http.ResponseWriter, r *http.Request) {
	var req ServeRequestMinecraft
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.HostOrPort == "" {
		writeError(w, http.StatusBadRequest, "field 'host_or_port' is required")
		return
	}

	parsedDomain, _ := parseMountArg(req.HostOrPort)
	listenAddr := ":25565"
	target := "127.0.0.1:25565"
	if req.Target != "" {
		target = req.Target
	}
	hostVal := ""

	if parsedDomain != "" || strings.Contains(req.HostOrPort, ".") {
		hostVal = parsedDomain
		if hostVal == "" {
			hostVal = req.HostOrPort
		}
	} else {
		listenPort := req.HostOrPort
		listenAddr = ":" + listenPort
		if strings.Contains(listenPort, ":") {
			listenAddr = listenPort
		}
	}

	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}

	listenerName := fmt.Sprintf("serve-mc-%s", strings.TrimPrefix(listenAddr, ":"))
	if err := a.ensureListenerInternal(ListenerSpec{Name: listenerName, Address: listenAddr, Protocol: "tcp"}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var rules []RuleSpec
	rules = append(rules, RuleSpec{Type: "is_minecraft"})
	if hostVal != "" {
		rules = append(rules, RuleSpec{Type: "minecraft_host", Value: hostVal})
	}
	ruleSpec := RuleSpec{Type: "any"}
	if len(rules) == 1 {
		ruleSpec = rules[0]
	} else if len(rules) > 1 {
		ruleSpec = RuleSpec{Type: "and", Rules: rules}
	}

	routeName := fmt.Sprintf("serve-mc-route-%d", time.Now().UnixNano())
	routeSpec := RouteSpec{
		Name:     routeName,
		Protocol: "tcp",
		Listener: listenerName,
		Priority: calculateServeAutoPriority(ruleSpec, req.Priority),
		TTL:      req.TTL,
		Rule:     ruleSpec,
		Handler: HandlerSpec{
			Type:   "tcp_lb",
			Config: map[string]any{"target": target},
		},
	}

	if err := a.AddRoute(routeSpec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, routeSpec)
}

func (a *API) handleServeDelete(w http.ResponseWriter, r *http.Request) {
	nameOrPort := r.PathValue("name")
	if nameOrPort == "" {
		writeError(w, http.StatusBadRequest, "name parameter is required")
		return
	}

	deletedCount := 0
	a.mu.RLock()
	var routesToDelete []string
	for name, entry := range a.routes {
		if name == nameOrPort || strings.Contains(name, nameOrPort) || strings.HasSuffix(entry.spec.Listener, "-"+nameOrPort) {
			routesToDelete = append(routesToDelete, name)
		}
	}
	a.mu.RUnlock()

	for _, name := range routesToDelete {
		if err := a.DeleteRoute(name); err == nil {
			deletedCount++
		}
	}

	if deletedCount == 0 {
		if err := a.DeleteRoute(nameOrPort); err == nil {
			deletedCount++
		}
	}

	a.cleanupUnusedServeListenersInternal()

	if deletedCount == 0 {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no active serve mounts matching %q", nameOrPort))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "removed_count": deletedCount})
}

func (a *API) handleServeReset(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	var serveRoutes []string
	for name := range a.routes {
		if strings.HasPrefix(name, "serve-") {
			serveRoutes = append(serveRoutes, name)
		}
	}
	a.mu.RUnlock()

	deletedCount := 0
	for _, name := range serveRoutes {
		if err := a.DeleteRoute(name); err == nil {
			deletedCount++
		}
	}

	a.cleanupUnusedServeListenersInternal()

	writeJSON(w, http.StatusOK, map[string]any{"status": "reset_complete", "removed_count": deletedCount})
}

// Helper methods for internal REST server serve handler logic

func parseMountArg(arg string) (domain string, path string) {
	arg = strings.TrimSpace(arg)
	arg = strings.TrimPrefix(arg, "http://")
	arg = strings.TrimPrefix(arg, "https://")

	if strings.HasPrefix(arg, "/") {
		return "", arg
	}

	parts := strings.SplitN(arg, "/", 2)
	domain = parts[0]
	path = "/"
	if len(parts) == 2 && parts[1] != "" {
		path = "/" + parts[1]
	}
	return domain, path
}

func (a *API) ensureListenerInternal(spec ListenerSpec) error {
	a.mu.RLock()
	for _, l := range a.listeners {
		if l.Name == spec.Name || (l.Address == spec.Address && l.Protocol == spec.Protocol) {
			if spec.TLS != nil {
				needUpdate := false
				var newDomains []string
				if l.TLS != nil {
					newDomains = append([]string{}, l.TLS.Domains...)
				}
				domainMap := make(map[string]bool)
				for _, d := range newDomains {
					domainMap[d] = true
				}
				for _, d := range spec.TLS.Domains {
					if d != "" && !domainMap[d] {
						domainMap[d] = true
						newDomains = append(newDomains, d)
						needUpdate = true
					}
				}
				if l.TLS == nil || needUpdate {
					a.mu.RUnlock()
					updatedSpec := l
					autoTLS := spec.TLS.Auto
					if l.TLS != nil && l.TLS.Auto {
						autoTLS = true
					}
					updatedSpec.TLS = &TLSConfigSpec{
						Auto:    autoTLS,
						Domains: newDomains,
						Cert:    spec.TLS.Cert,
						Key:     spec.TLS.Key,
					}
					if updatedSpec.TLS.Cert == "" && l.TLS != nil {
						updatedSpec.TLS.Cert = l.TLS.Cert
						updatedSpec.TLS.Key = l.TLS.Key
					}
					return a.AddListener(updatedSpec)
				}
			}
			a.mu.RUnlock()
			return nil
		}
	}
	a.mu.RUnlock()

	return a.AddListener(spec)
}

func (a *API) cleanupUnusedServeListenersInternal() {
	a.mu.RLock()
	usedListeners := make(map[string]bool)
	for _, r := range a.routes {
		usedListeners[r.spec.Listener] = true
	}

	var listenersToDelete []string
	for name, l := range a.listeners {
		if strings.HasPrefix(name, "serve-") && !usedListeners[name] {
			listenersToDelete = append(listenersToDelete, l.Name)
		}
	}
	a.mu.RUnlock()

	for _, name := range listenersToDelete {
		_ = a.DeleteListener(name)
	}
}

// FormatRuleSummary formats a rule for status output.
func FormatRuleSummary(rule RuleSpec) string {
	if rule.Type == "any" {
		return "/*"
	}
	if rule.Type == "host" {
		return rule.Value
	}
	if rule.Type == "path" || rule.Type == "path_prefix" {
		return rule.Value
	}
	if rule.Type == "and" {
		var parts []string
		for _, r := range rule.Rules {
			if r.Type != "secure" && r.Type != "not" {
				parts = append(parts, r.Value)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "")
		}
	}
	return "/*"
}

// FormatTargetsSummary formats a handler target for status output.
func FormatTargetsSummary(h HandlerSpec) string {
	if urlStr, ok := h.Config["url"].(string); ok {
		return urlStr
	}
	if targetStr, ok := h.Config["target"].(string); ok {
		return targetStr
	}
	if dirStr, ok := h.Config["dir"].(string); ok {
		return dirStr
	}
	if h.Next != nil {
		return FormatTargetsSummary(*h.Next)
	}
	return "-"
}

// FormatTTLRemaining returns formatted remaining TTL duration.
func FormatTTLRemaining(now time.Time, ttlSeconds int) string {
	if ttlSeconds <= 0 {
		return "never"
	}
	rem := time.Duration(ttlSeconds) * time.Second
	if rem <= 0 {
		return "expired"
	}
	if rem > 24*time.Hour {
		return fmt.Sprintf("%dd", int(rem.Hours()/24))
	}
	if rem > time.Hour {
		return fmt.Sprintf("%dh", int(rem.Hours()))
	}
	if rem > time.Minute {
		return fmt.Sprintf("%dm", int(rem.Minutes()))
	}
	return fmt.Sprintf("%ds", int(rem.Seconds()))
}

func calculateServeAutoPriority(rule RuleSpec, explicitPriority int) int {
	if explicitPriority > 0 {
		return explicitPriority
	}

	priority := 1
	domain, path := extractRuleDomainAndPathAPI(rule)

	if domain != "" {
		priority += 100
	}

	if path != "" && path != "/" {
		priority += 100 + len(path)*10
	}

	if rule.Type == "path" {
		priority += 1000
	} else if rule.Type == "and" || rule.Type == "or" {
		for _, child := range rule.Rules {
			if child.Type == "path" {
				priority += 1000
				break
			}
		}
	}

	return priority
}

func extractRuleDomainAndPathAPI(rule RuleSpec) (string, string) {
	if rule.Type == "host" {
		return rule.Value, ""
	}
	if rule.Type == "path_prefix" || rule.Type == "path" {
		return "", rule.Value
	}
	if rule.Type == "and" || rule.Type == "or" {
		var domain, path string
		for _, child := range rule.Rules {
			d, p := extractRuleDomainAndPathAPI(child)
			if d != "" {
				domain = d
			}
			if p != "" {
				path = p
			}
		}
		return domain, path
	}
	return "", ""
}
