package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// LogBroadcaster manages pub-sub subscriptions for real-time log streaming.
type LogBroadcaster struct {
	mu          sync.RWMutex
	subscribers map[chan LogEvent]string // subscriber channel -> optional route filter
}

// NewLogBroadcaster creates a new LogBroadcaster.
func NewLogBroadcaster() *LogBroadcaster {
	return &LogBroadcaster{
		subscribers: make(map[chan LogEvent]string),
	}
}

// Subscribe registers a new subscriber channel with an optional route filter.
func (b *LogBroadcaster) Subscribe(routeFilter string) chan LogEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan LogEvent, 100)
	b.subscribers[ch] = routeFilter
	return ch
}

// Unsubscribe removes a subscriber channel.
func (b *LogBroadcaster) Unsubscribe(ch chan LogEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// Broadcast sends a log event to all matching subscribers.
func (b *LogBroadcaster) Broadcast(event LogEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch, routeFilter := range b.subscribers {
		if routeFilter == "" || routeFilter == event.Route {
			select {
			case ch <- event:
			default:
				// drop if subscriber is too slow to avoid blocking proxy path
			}
		}
	}
}

// DefaultLogBroadcaster is the global log event broadcaster.
var DefaultLogBroadcaster = NewLogBroadcaster()

// handleStreamLogs streams real-time log events via Server-Sent Events (SSE).
func (a *API) handleStreamLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusBadRequest, "streaming unsupported by client")
		return
	}

	routeFilter := r.URL.Query().Get("route")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := DefaultLogBroadcaster.Subscribe(routeFilter)
	defer DefaultLogBroadcaster.Unsubscribe(ch)

	// Send initial connection ACK
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"listening\",\"route\":%q}\n\n", routeFilter)
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(event)
			if err == nil {
				fmt.Fprintf(w, "event: log\ndata: %s\n\n", string(data))
				flusher.Flush()
			}
		}
	}
}
