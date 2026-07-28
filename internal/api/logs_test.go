package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLogBroadcasterAndStream(t *testing.T) {
	broadcaster := NewLogBroadcaster()

	ch1 := broadcaster.Subscribe("")
	defer broadcaster.Unsubscribe(ch1)

	ch2 := broadcaster.Subscribe("target-route")
	defer broadcaster.Unsubscribe(ch2)

	event1 := LogEvent{
		Timestamp:  time.Now(),
		Protocol:   "http",
		Route:      "other-route",
		Method:     "GET",
		Path:       "/test",
		Status:     200,
		DurationMs: 12,
		RemoteIP:   "127.0.0.1",
	}

	broadcaster.Broadcast(event1)

	select {
	case ev := <-ch1:
		if ev.Route != "other-route" {
			t.Errorf("unexpected route: %s", ev.Route)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for subscriber 1 event")
	}

	select {
	case ev := <-ch2:
		t.Errorf("subscriber 2 received unfiltered event: %+v", ev)
	default:
		// Expected filtered out
	}

	event2 := LogEvent{
		Timestamp:  time.Now(),
		Protocol:   "minecraft",
		Route:      "target-route",
		Method:     "POST",
		Path:       "/data",
		Status:     201,
		DurationMs: 25,
		RemoteIP:   "127.0.0.1",
		MinecraftInfo: &MinecraftInfoSpec{
			RequestedHost: "mc.server.com",
			Username:      "Player1",
		},
	}

	broadcaster.Broadcast(event2)

	select {
	case ev := <-ch2:
		if ev.Route != "target-route" {
			t.Errorf("unexpected route: %s", ev.Route)
		}
		if ev.MinecraftInfo == nil || ev.MinecraftInfo.Username != "Player1" {
			t.Errorf("expected MinecraftInfo username Player1, got %+v", ev.MinecraftInfo)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for subscriber 2 event")
	}
}

func TestStreamLogsEndpoint(t *testing.T) {
	apiObj, _, token := setupTestAPI(t)
	handler := NewHandler(apiObj)

	req := httptest.NewRequest("GET", "/api/v1/logs/stream?route=my-route", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for log stream, got %d", rec.Code)
	}
}
