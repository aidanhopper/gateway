package handlers

import (
	"hash/fnv"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aidanhopper/gateway/internal/gateway"
)

// TCPLoadBalancer handles raw TCP proxying & load balancing across multiple backends.
type TCPLoadBalancer struct {
	Targets  []string
	Strategy string
	counter  uint64
	active   []int64 // active conn counter per target for least_conn
}

// NewTCPLoadBalancer creates a TCPLoadBalancer supporting single target or multi-target load balancing.
func NewTCPLoadBalancer(targets ...string) *TCPLoadBalancer {
	if len(targets) == 0 {
		targets = []string{"127.0.0.1:80"}
	}
	return &TCPLoadBalancer{
		Targets:  targets,
		Strategy: "round_robin",
		active:   make([]int64, len(targets)),
	}
}

func (p *TCPLoadBalancer) selectTargetIndex(conn net.Conn) int {
	n := len(p.Targets)
	if n == 1 {
		return 0
	}

	switch strings.ToLower(p.Strategy) {
	case "random":
		return rand.Intn(n)

	case "ip_hash", "sticky":
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			host = conn.RemoteAddr().String()
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

func (p *TCPLoadBalancer) ServeTCP(conn net.Conn, metadata gateway.TCPMetadata) {
	if len(p.Targets) == 0 {
		return
	}

	idx := p.selectTargetIndex(conn)
	target := p.Targets[idx]

	atomic.AddInt64(&p.active[idx], 1)
	defer atomic.AddInt64(&p.active[idx], -1)

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		// Fallback retry to next target if initial dial fails
		for i, altTarget := range p.Targets {
			if i == idx {
				continue
			}
			upstream, err = net.Dial("tcp", altTarget)
			if err == nil {
				break
			}
		}
		if err != nil {
			return
		}
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, conn)
		_ = upstream.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
	}()

	wg.Wait()
}

// Info returns live load balancing metrics for Informer interface.
func (p *TCPLoadBalancer) Info() map[string]any {
	targetStats := make([]map[string]any, len(p.Targets))
	for i, t := range p.Targets {
		targetStats[i] = map[string]any{
			"target":             t,
			"active_connections": atomic.LoadInt64(&p.active[i]),
		}
	}
	return map[string]any{
		"strategy": p.Strategy,
		"targets":  targetStats,
	}
}
