package gateway

import (
	"context"
	"net"
	"sync"
)

type Listener struct {
	Name       string
	Address    string
	Protocol   Protocol
	TLSHandler TLSConfigHandler
}

type tcpListenerState struct {
	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup

	connsMu sync.Mutex
	conns   map[string]map[net.Conn]struct{} // route name -> conns
}

func (s *tcpListenerState) registerConn(route string, conn net.Conn) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.conns[route] == nil {
		s.conns[route] = make(map[net.Conn]struct{})
	}
	s.conns[route][conn] = struct{}{}
}

func (s *tcpListenerState) unregisterConn(route string, conn net.Conn) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if m, ok := s.conns[route]; ok {
		delete(m, conn)
		if len(m) == 0 {
			delete(s.conns, route)
		}
	}
}

func (s *tcpListenerState) connCount() int {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	total := 0
	for _, m := range s.conns {
		total += len(m)
	}
	return total
}

func (s *tcpListenerState) closeRoute(route string) {
	s.connsMu.Lock()
	bucket := s.conns[route]
	delete(s.conns, route)
	s.connsMu.Unlock()

	for conn := range bucket {
		conn.Close()
	}
}

func (s *tcpListenerState) closeAll() {
	s.connsMu.Lock()
	var all []net.Conn
	for _, bucket := range s.conns {
		for conn := range bucket {
			all = append(all, conn)
		}
	}
	clear(s.conns)
	s.connsMu.Unlock()

	for _, conn := range all {
		conn.Close()
	}
}

type udpListenerState struct {
	pc     net.PacketConn
	cancel context.CancelFunc
	wg     sync.WaitGroup

	sessMu   sync.Mutex
	sessions map[string]map[*udpSession]struct{} // route name -> sessions

}

func (s *udpListenerState) register(route string, sess *udpSession) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.sessions[route] == nil {
		s.sessions[route] = make(map[*udpSession]struct{})
	}
	s.sessions[route][sess] = struct{}{}
}

func (s *udpListenerState) unregister(route string, sess *udpSession) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if m, ok := s.sessions[route]; ok {
		delete(m, sess)
		if len(m) == 0 {
			delete(s.sessions, route)
		}
	}
}

func (s *udpListenerState) closeRoute(route string) {
	s.sessMu.Lock()
	bucket := s.sessions[route]
	delete(s.sessions, route)
	s.sessMu.Unlock()

	for sess := range bucket {
		sess.Close()
	}
}

func (s *udpListenerState) closeAll() {
	s.sessMu.Lock()
	var all []*udpSession
	for _, bucket := range s.sessions {
		for sess := range bucket {
			all = append(all, sess)
		}
	}
	clear(s.sessions)
	s.sessMu.Unlock()

	for _, sess := range all {
		sess.Close()
	}
}
