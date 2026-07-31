package handlers

import (
	"math/rand"
	"net"
	"strings"
	"sync/atomic"

	"github.com/aidanhopper/gateway/internal/gateway"
)

// UDPLoadBalancer handles UDP packet proxying & load balancing across multiple backends.
type UDPLoadBalancer struct {
	Targets  []string
	Strategy string
	counter  uint64
	active   []int64
}

// NewUDPLoadBalancer creates a UDPLoadBalancer supporting single target or multi-target load balancing.
func NewUDPLoadBalancer(targets ...string) *UDPLoadBalancer {
	if len(targets) == 0 {
		targets = []string{"127.0.0.1:9000"}
	}
	return &UDPLoadBalancer{
		Targets:  targets,
		Strategy: "round_robin",
		active:   make([]int64, len(targets)),
	}
}

func (p *UDPLoadBalancer) selectTargetIndex() int {
	n := len(p.Targets)
	if n == 1 {
		return 0
	}

	switch strings.ToLower(p.Strategy) {
	case "random":
		return rand.Intn(n)

	case "round_robin":
		fallthrough
	default:
		c := atomic.AddUint64(&p.counter, 1) - 1
		return int(c % uint64(n))
	}
}

func (p *UDPLoadBalancer) ServeUDP(conn net.Conn, metadata gateway.UDPMetadata) {
	if len(p.Targets) == 0 {
		return
	}

	// Fanout Strategy: Broadcast packet to all targets simultaneously
	if strings.ToLower(p.Strategy) == "fanout" {
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		packet := buf[:n]

		for _, target := range p.Targets {
			go func(t string, data []byte) {
				up, err := net.Dial("udp", t)
				if err != nil {
					return
				}
				defer up.Close()
				_, _ = up.Write(data)
			}(target, packet)
		}
		return
	}

	// Standard Load Balanced Strategy
	idx := p.selectTargetIndex()
	target := p.Targets[idx]

	atomic.AddInt64(&p.active[idx], 1)
	defer atomic.AddInt64(&p.active[idx], -1)

	upstream, err := net.Dial("udp", target)
	if err != nil {
		gateway.LogError("UDP", "dial target %s error: %v", target, err)
		return
	}
	defer upstream.Close()

	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, err = upstream.Write(buf[:n])
		if err != nil {
			return
		}
	}
}

// Info returns live load balancing metrics for Informer interface.
func (p *UDPLoadBalancer) Info() map[string]any {
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
