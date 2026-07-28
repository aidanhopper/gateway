package handlers

import (
	"hash/fnv"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
)

// HTTPLoadBalancer handles HTTP proxying & load balancing across multiple backends.
type HTTPLoadBalancer struct {
	Targets  []*url.URL
	Weights  []int
	Strategy string
	counter  uint64
	proxies  []*httputil.ReverseProxy
	active   []int64
}

// NewHTTPLoadBalancer creates an HTTPLoadBalancer supporting single target or multi-target load balancing.
func NewHTTPLoadBalancer(targetURLs ...string) (*HTTPLoadBalancer, error) {
	if len(targetURLs) == 0 {
		targetURLs = []string{"http://127.0.0.1:80"}
	}

	urls := make([]*url.URL, len(targetURLs))
	proxies := make([]*httputil.ReverseProxy, len(targetURLs))
	active := make([]int64, len(targetURLs))

	for i, raw := range targetURLs {
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			raw = "http://" + raw
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		urls[i] = parsed
		proxies[i] = httputil.NewSingleHostReverseProxy(parsed)
	}

	return &HTTPLoadBalancer{
		Targets:  urls,
		Strategy: "round_robin",
		proxies:  proxies,
		active:   active,
	}, nil
}

func (p *HTTPLoadBalancer) selectTargetIndex(r *http.Request) int {
	n := len(p.Targets)
	if n == 1 {
		return 0
	}

	switch strings.ToLower(p.Strategy) {
	case "weighted":
		if len(p.Weights) == n {
			totalWeight := 0
			for _, w := range p.Weights {
				totalWeight += w
			}
			if totalWeight > 0 {
				rnd := rand.Intn(totalWeight)
				accum := 0
				for i, w := range p.Weights {
					accum += w
					if rnd < accum {
						return i
					}
				}
			}
		}
		fallthrough

	case "random":
		return rand.Intn(n)

	case "ip_hash", "sticky":
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		h := fnv.New32a()
		_, _ = h.Write([]byte(host))
		return int(h.Sum32()) % n

	case "least_conn":
		minIdx := 0
		minVal := atomic.LoadInt64(&p.active[0])
		for i := 1; i < n; i++ {
			val := atomic.LoadInt64(&p.active[i])
			if val < minVal {
				minVal = val
				minIdx = i
			}
		}
		return minIdx

	case "round_robin":
		fallthrough
	default:
		c := atomic.AddUint64(&p.counter, 1) - 1
		return int(c % uint64(n))
	}
}

func (p *HTTPLoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(p.proxies) == 0 {
		http.Error(w, "no upstream backends available", http.StatusBadGateway)
		return
	}

	idx := p.selectTargetIndex(r)
	atomic.AddInt64(&p.active[idx], 1)
	defer atomic.AddInt64(&p.active[idx], -1)

	p.proxies[idx].ServeHTTP(w, r)
}

// Info returns live load balancing metrics for Informer interface.
func (p *HTTPLoadBalancer) Info() map[string]any {
	targetStats := make([]map[string]any, len(p.Targets))
	for i, t := range p.Targets {
		targetStats[i] = map[string]any{
			"target":             t.String(),
			"active_connections": atomic.LoadInt64(&p.active[i]),
		}
	}
	return map[string]any{
		"strategy": p.Strategy,
		"targets":  targetStats,
	}
}
