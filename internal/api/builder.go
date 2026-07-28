package api

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/aidanhopper/gateway/internal/gateway"
)

// validateHandlerForProtocol checks whether the HandlerSpec is valid for the given protocol using DefaultHandlerRegistry.
func validateHandlerForProtocol(protocol string, spec HandlerSpec) error {
	return DefaultHandlerRegistry.Validate(protocol, spec)
}

// buildHandler instantiates the concrete Go handler object using DefaultHandlerRegistry.
func buildHandler(protocol string, spec HandlerSpec) (any, error) {
	return DefaultHandlerRegistry.Build(protocol, spec)
}

// LeafCompiler compiles a leaf RuleSpec into a gateway.Rule[T].
type LeafCompiler[T any] func(spec RuleSpec) (gateway.Rule[T], error)

// RuleRegistry maps rule type names to their LeafCompilers.
type RuleRegistry[T any] struct {
	mu        sync.RWMutex
	compilers map[string]LeafCompiler[T]
}

// NewRuleRegistry creates an empty RuleRegistry.
func NewRuleRegistry[T any]() *RuleRegistry[T] {
	return &RuleRegistry[T]{
		compilers: make(map[string]LeafCompiler[T]),
	}
}

// Register registers a new LeafCompiler for a rule type string.
func (r *RuleRegistry[T]) Register(ruleType string, compiler LeafCompiler[T]) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.compilers[ruleType] = compiler
}

// Compile compiles a composite or leaf RuleSpec into a gateway.Rule[T].
func (r *RuleRegistry[T]) Compile(spec RuleSpec) (gateway.Rule[T], error) {
	return compileGenericRule(spec, func(leafSpec RuleSpec) (gateway.Rule[T], error) {
		r.mu.RLock()
		compiler, ok := r.compilers[leafSpec.Type]
		r.mu.RUnlock()

		if !ok {
			return nil, fmt.Errorf("unknown rule type %q", leafSpec.Type)
		}
		return compiler(leafSpec)
	})
}

// compileGenericRule recursively evaluates composite rules ("any", "and", "or", "not") for any type T.
func compileGenericRule[T any](spec RuleSpec, compileLeaf LeafCompiler[T]) (gateway.Rule[T], error) {
	switch spec.Type {
	case "any":
		return gateway.Any[T](), nil

	case "and":
		childRules := make([]gateway.Rule[T], 0, len(spec.Rules))
		for _, childSpec := range spec.Rules {
			child, err := compileGenericRule(childSpec, compileLeaf)
			if err != nil {
				return nil, err
			}
			childRules = append(childRules, child)
		}
		return gateway.And(childRules...), nil

	case "or":
		childRules := make([]gateway.Rule[T], 0, len(spec.Rules))
		for _, childSpec := range spec.Rules {
			child, err := compileGenericRule(childSpec, compileLeaf)
			if err != nil {
				return nil, err
			}
			childRules = append(childRules, child)
		}
		return gateway.Or(childRules...), nil

	case "not":
		if spec.Rule == nil {
			return nil, fmt.Errorf("rule type 'not' requires a child 'rule'")
		}
		child, err := compileGenericRule(*spec.Rule, compileLeaf)
		if err != nil {
			return nil, err
		}
		return gateway.Not(child), nil

	default:
		return compileLeaf(spec)
	}
}

// Global protocol rule registries
var (
	HTTPRuleRegistry = NewRuleRegistry[*http.Request]()
	TCPRuleRegistry  = NewRuleRegistry[gateway.TCPMetadata]()
	UDPRuleRegistry  = NewRuleRegistry[gateway.UDPMetadata]()
)

func init() {
	// HTTP Leaf Rules
	HTTPRuleRegistry.Register("host", func(s RuleSpec) (gateway.HTTPRule, error) { return gateway.Host(s.Value), nil })
	HTTPRuleRegistry.Register("host_prefix", func(s RuleSpec) (gateway.HTTPRule, error) { return gateway.HostPrefix(s.Value), nil })
	HTTPRuleRegistry.Register("path", func(s RuleSpec) (gateway.HTTPRule, error) { return gateway.Path(s.Value), nil })
	HTTPRuleRegistry.Register("path_prefix", func(s RuleSpec) (gateway.HTTPRule, error) { return gateway.PathPrefix(s.Value), nil })
	HTTPRuleRegistry.Register("method", func(s RuleSpec) (gateway.HTTPRule, error) { return gateway.Method(getValues(s)...), nil })
	HTTPRuleRegistry.Register("header", func(s RuleSpec) (gateway.HTTPRule, error) {
		val := ""
		if len(s.Values) > 0 {
			val = s.Values[0]
		}
		return gateway.Header(s.Value, val), nil
	})
	HTTPRuleRegistry.Register("header_exists", func(s RuleSpec) (gateway.HTTPRule, error) { return gateway.HeaderExists(s.Value), nil })
	HTTPRuleRegistry.Register("query_param", func(s RuleSpec) (gateway.HTTPRule, error) {
		val := ""
		if len(s.Values) > 0 {
			val = s.Values[0]
		}
		return gateway.QueryParam(s.Value, val), nil
	})
	HTTPRuleRegistry.Register("secure", func(s RuleSpec) (gateway.HTTPRule, error) { return gateway.Secure(), nil })
	HTTPRuleRegistry.Register("scheme", func(s RuleSpec) (gateway.HTTPRule, error) { return gateway.Scheme(s.Value), nil })
	HTTPRuleRegistry.Register("remote_ip", func(s RuleSpec) (gateway.HTTPRule, error) { return gateway.RemoteIP(s.Value), nil })

	// TCP & Minecraft Leaf Rules
	TCPRuleRegistry.Register("sni", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.SNI(getValues(s)...), nil })
	TCPRuleRegistry.Register("not_tls", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.NotTLS(), nil })
	TCPRuleRegistry.Register("not_http", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.NotHTTP(), nil })
	TCPRuleRegistry.Register("is_minecraft", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.IsMinecraft(), nil })
	TCPRuleRegistry.Register("not_minecraft", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.NotMinecraft(), nil })
	TCPRuleRegistry.Register("minecraft_host", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.MinecraftHost(getValues(s)...), nil })
	TCPRuleRegistry.Register("minecraft_version", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.MinecraftVersion(getIntValues(s)...), nil })
	TCPRuleRegistry.Register("minecraft_login", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.MinecraftLogin(), nil })
	TCPRuleRegistry.Register("minecraft_status", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.MinecraftStatus(), nil })
	TCPRuleRegistry.Register("minecraft_login_state", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.MinecraftLoginState(), nil })
	TCPRuleRegistry.Register("minecraft_player", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.MinecraftPlayer(getValues(s)...), nil })
	TCPRuleRegistry.Register("minecraft_player_not", func(s RuleSpec) (gateway.TCPRule, error) { return gateway.MinecraftNotPlayer(getValues(s)...), nil })
	TCPRuleRegistry.Register("minecraft_port", func(s RuleSpec) (gateway.TCPRule, error) {
		intVals := getIntValues(s)
		ports := make([]uint16, 0, len(intVals))
		for _, v := range intVals {
			ports = append(ports, uint16(v))
		}
		return gateway.MinecraftRequestedPort(ports...), nil
	})
}

// buildRule converts a RuleSpec into a gateway.TCPRule, gateway.HTTPRule, or gateway.UDPRule using the protocol registries.
func buildRule(protocol string, spec RuleSpec) (any, error) {
	switch protocol {
	case "tcp":
		return TCPRuleRegistry.Compile(spec)
	case "http":
		return HTTPRuleRegistry.Compile(spec)
	case "udp":
		return UDPRuleRegistry.Compile(spec)
	default:
		return nil, fmt.Errorf("unsupported protocol %q for rule build", protocol)
	}
}

func getValues(spec RuleSpec) []string {
	if len(spec.Values) > 0 {
		return spec.Values
	}
	if spec.Value != "" {
		return []string{spec.Value}
	}
	return nil
}

func getIntValues(spec RuleSpec) []int {
	var result []int
	for _, vStr := range spec.Values {
		if v, err := strconv.Atoi(vStr); err == nil {
			result = append(result, v)
		}
	}
	if len(result) == 0 && spec.Value != "" {
		if v, err := strconv.Atoi(spec.Value); err == nil {
			result = append(result, v)
		}
	}
	return result
}
