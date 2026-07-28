package api

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestListenerSpecJSON(t *testing.T) {
	spec := ListenerSpec{
		Name:     "web-tcp",
		Address:  ":8080",
		Protocol: "tcp",
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ListenerSpec
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(spec, decoded) {
		t.Errorf("got %+v, want %+v", decoded, spec)
	}
}

func TestRouteSpecJSON(t *testing.T) {
	spec := RouteSpec{
		Name:     "mc-route",
		Protocol: "tcp",
		Listener: "mc-listener",
		Priority: 10,
		Rule: RuleSpec{
			Type: "and",
			Rules: []RuleSpec{
				{Type: "is_minecraft"},
				{Type: "minecraft_player", Values: []string{"steve", "alex"}},
			},
		},
		Handler: HandlerSpec{
			Type: "tcp_proxy",
			Config: map[string]any{
				"target": "127.0.0.1:25565",
			},
		},
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded RouteSpec
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Name != spec.Name || decoded.Protocol != spec.Protocol || decoded.Priority != spec.Priority {
		t.Errorf("RouteSpec mismatch: got %+v, want %+v", decoded, spec)
	}

	if decoded.Handler.Type != "tcp_proxy" || decoded.Handler.Config["target"] != "127.0.0.1:25565" {
		t.Errorf("HandlerSpec mismatch: got %+v", decoded.Handler)
	}
}
