package cli

import (
	"flag"
	"testing"
	"time"

	"github.com/aidanhopper/gateway/internal/api"
)

func TestFormatTTLRemaining(t *testing.T) {
	now := time.Now()

	if got := FormatTTLRemaining(now, 0); got != "Permanent" {
		t.Errorf("expected Permanent, got %s", got)
	}

	if got := FormatTTLRemaining(now.Add(-10*time.Minute), 300); got != "[Expired]" {
		t.Errorf("expected [Expired], got %s", got)
	}

	got := FormatTTLRemaining(now, 3600)
	if got == "Permanent" || got == "[Expired]" {
		t.Errorf("unexpected TTL formatting for 3600s: %s", got)
	}
}

func TestFormatRuleSummary(t *testing.T) {
	ruleAny := api.RuleSpec{Type: "any"}
	if got := FormatRuleSummary(ruleAny); got != "Any" {
		t.Errorf("expected Any, got %s", got)
	}

	ruleHost := api.RuleSpec{Type: "host", Value: "app.local"}
	if got := FormatRuleSummary(ruleHost); got != `Host("app.local")` {
		t.Errorf("expected Host(\"app.local\"), got %s", got)
	}

	ruleMCPlayer := api.RuleSpec{Type: "minecraft_player", Values: []string{"Steve", "Alex"}}
	if got := FormatRuleSummary(ruleMCPlayer); got != "MinecraftPlayer(Steve,Alex)" {
		t.Errorf("expected MinecraftPlayer(Steve,Alex), got %s", got)
	}

	ruleMCPlayerNot := api.RuleSpec{Type: "minecraft_player_not", Values: []string{"Hacker"}}
	if got := FormatRuleSummary(ruleMCPlayerNot); got != "MinecraftNotPlayer(Hacker)" {
		t.Errorf("expected MinecraftNotPlayer(Hacker), got %s", got)
	}
}

func TestFormatTargetsSummary(t *testing.T) {
	handlerSingle := api.HandlerSpec{Config: map[string]any{"target": "127.0.0.1:8080"}}
	if got := FormatTargetsSummary(handlerSingle); got != "127.0.0.1:8080" {
		t.Errorf("expected 127.0.0.1:8080, got %s", got)
	}

	handlerMulti := api.HandlerSpec{Config: map[string]any{"targets": []any{"10.0.0.1:8080", "10.0.0.2:8080"}}}
	if got := FormatTargetsSummary(handlerMulti); got != "10.0.0.1:8080,10.0.0.2:8080" {
		t.Errorf("expected 10.0.0.1:8080,10.0.0.2:8080, got %s", got)
	}
}

func TestReorderFlagsFirst(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var allow stringSliceFlag
	fs.Var(&allow, "allow", "allow")
	var deny stringSliceFlag
	fs.Var(&deny, "deny", "deny")

	args := []string{"only-didscare.ahop.dev", "docker-server:25565", "--deny", "didscare"}
	reordered := ReorderFlagsFirst(fs, args)

	if err := fs.Parse(reordered); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deny) != 1 || deny[0] != "didscare" {
		t.Errorf("expected deny=['didscare'], got %v", deny)
	}
	if fs.NArg() != 2 || fs.Arg(0) != "only-didscare.ahop.dev" || fs.Arg(1) != "docker-server:25565" {
		t.Errorf("expected positional args ['only-didscare.ahop.dev', 'docker-server:25565'], got %v", fs.Args())
	}
}
