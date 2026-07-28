package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type customTestFactory struct{}

func (f customTestFactory) Protocol() string { return "tcp" }
func (f customTestFactory) Validate(spec HandlerSpec) error {
	if _, ok := spec.Config["key"].(string); !ok {
		return fmt.Errorf("custom_test requires 'key'")
	}
	return nil
}
func (f customTestFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	return "CUSTOM_HANDLER_INSTANCE", nil
}

type httpHeaderDecoratorFactory struct{}

func (f httpHeaderDecoratorFactory) Protocol() string { return "http" }
func (f httpHeaderDecoratorFactory) Validate(spec HandlerSpec) error {
	if spec.Next == nil {
		return fmt.Errorf("http_header_decorator requires a nested inner handler in 'next'")
	}
	return nil
}
func (f httpHeaderDecoratorFactory) Build(spec HandlerSpec, buildNext BuildNextFunc) (any, error) {
	nextObj, err := buildNext(*spec.Next)
	if err != nil {
		return nil, err
	}
	nextHandler, ok := nextObj.(http.Handler)
	if !ok {
		return nil, fmt.Errorf("inner handler is not an http.Handler")
	}

	headerKey := "X-Custom-Header"
	if k, ok := spec.Config["header"].(string); ok {
		headerKey = k
	}
	headerVal := "wrapped"
	if v, ok := spec.Config["value"].(string); ok {
		headerVal = v
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerKey, headerVal)
		nextHandler.ServeHTTP(w, r)
	}), nil
}

func TestHandlerRegistryCustomRegistration(t *testing.T) {
	registry := NewHandlerRegistry()
	registry.Register("custom_test", customTestFactory{})

	// Valid build
	inst, err := registry.Build("tcp", HandlerSpec{
		Type:   "custom_test",
		Config: map[string]any{"key": "val"},
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if inst != "CUSTOM_HANDLER_INSTANCE" {
		t.Errorf("got %v, want 'CUSTOM_HANDLER_INSTANCE'", inst)
	}

	// Protocol mismatch validation
	_, err = registry.Build("http", HandlerSpec{
		Type:   "custom_test",
		Config: map[string]any{"key": "val"},
	})
	if err == nil {
		t.Errorf("expected error on protocol mismatch")
	}

	// Config validation error
	_, err = registry.Build("tcp", HandlerSpec{
		Type:   "custom_test",
		Config: map[string]any{},
	})
	if err == nil {
		t.Errorf("expected error on missing config key")
	}
}

func TestNestedHandlerComposition(t *testing.T) {
	registry := NewHandlerRegistry()
	registry.Register("http_static", HTTPStaticFactory{})
	registry.Register("http_decorator", httpHeaderDecoratorFactory{})

	nestedSpec := HandlerSpec{
		Type: "http_decorator",
		Config: map[string]any{
			"header": "X-Decorated-By",
			"value":  "gateway-test",
		},
		Next: &HandlerSpec{
			Type: "http_static",
			Config: map[string]any{
				"status": 200,
				"body":   "INNER_STATIC_BODY",
			},
		},
	}

	obj, err := registry.Build("http", nestedSpec)
	if err != nil {
		t.Fatalf("Build nested handler failed: %v", err)
	}

	handler, ok := obj.(http.Handler)
	if !ok {
		t.Fatalf("expected http.Handler interface")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("got status %d, want 200", rec.Code)
	}

	if rec.Body.String() != "INNER_STATIC_BODY" {
		t.Errorf("got body %q, want 'INNER_STATIC_BODY'", rec.Body.String())
	}

	if rec.Header().Get("X-Decorated-By") != "gateway-test" {
		t.Errorf("got header %q, want 'gateway-test'", rec.Header().Get("X-Decorated-By"))
	}
}
