package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// SystemLogEvent describes a daemon internal system log message.
type SystemLogEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`     // "INFO", "WARN", "ERROR"
	Component string    `json:"component"` // "DAEMON", "GATEWAY", "API", "FIREWALL", "LISTENER", "ACME"
	Message   string    `json:"message"`
}

// SystemLogBroadcaster manages pub-sub subscriptions for live daemon system log streaming.
type SystemLogBroadcaster struct {
	mu          sync.RWMutex
	subscribers map[chan SystemLogEvent]bool
}

// NewSystemLogBroadcaster initializes a SystemLogBroadcaster.
func NewSystemLogBroadcaster() *SystemLogBroadcaster {
	return &SystemLogBroadcaster{
		subscribers: make(map[chan SystemLogEvent]bool),
	}
}

// Subscribe registers a subscriber channel for live system logs.
func (b *SystemLogBroadcaster) Subscribe() chan SystemLogEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan SystemLogEvent, 200)
	b.subscribers[ch] = true
	return ch
}

// Unsubscribe removes a subscriber channel.
func (b *SystemLogBroadcaster) Unsubscribe(ch chan SystemLogEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// Broadcast sends a system log event to all active subscribers.
func (b *SystemLogBroadcaster) Broadcast(event SystemLogEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subscribers {
		select {
		case ch <- event:
		default:
			// drop slow subscribers to prevent blocking daemon
		}
	}
}

// DefaultSystemLogBroadcaster is the global system log broadcaster.
var DefaultSystemLogBroadcaster = NewSystemLogBroadcaster()

// LogSystem records a daemon log event, prints it to stdout/stderr, and broadcasts to SSE clients.
func LogSystem(level, component, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	cleanLevel := strings.ToUpper(strings.TrimSpace(level))
	cleanComp := strings.ToUpper(strings.TrimSpace(component))

	event := SystemLogEvent{
		Timestamp: time.Now(),
		Level:     cleanLevel,
		Component: cleanComp,
		Message:   msg,
	}

	timeStr := event.Timestamp.Format("2006-01-02 15:04:05")
	out := os.Stdout
	if cleanLevel == "ERROR" {
		out = os.Stderr
	}

	levelPadded := fmt.Sprintf("%-5s", cleanLevel)
	compPadded := fmt.Sprintf("%-8s", cleanComp)

	fmt.Fprintf(out, "[%s] [%s] [%s] %s\n", timeStr, levelPadded, compPadded, msg)
	DefaultSystemLogBroadcaster.Broadcast(event)
}

// LogInfo logs an informational daemon message.
func LogInfo(component, format string, args ...any) {
	LogSystem("INFO", component, format, args...)
}

// LogWarn logs a warning daemon message.
func LogWarn(component, format string, args ...any) {
	LogSystem("WARN", component, format, args...)
}

// LogError logs an error daemon message.
func LogError(component, format string, args ...any) {
	LogSystem("ERROR", component, format, args...)
}

// handleStreamSystemLogs streams live daemon system logs via Server-Sent Events (SSE).
func (a *API) handleStreamSystemLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusBadRequest, "streaming unsupported by client")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := DefaultSystemLogBroadcaster.Subscribe()
	defer DefaultSystemLogBroadcaster.Unsubscribe(ch)

	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"listening_system_logs\"}\n\n")
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
				fmt.Fprintf(w, "event: system_log\ndata: %s\n\n", string(data))
				flusher.Flush()
			}
		}
	}
}
