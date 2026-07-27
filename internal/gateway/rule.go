package gateway

import (
	"net"
	"net/http"
	"strings"
)

type Rule[T any] interface {
	Match(T) bool
}

type TCPRule = Rule[TCPConn]
type HTTPRule = Rule[*http.Request]

type RuleFunc[T any] func(T) bool

func (f RuleFunc[T]) Match(v T) bool {
	return f(v)
}

func And[T any](rules ...Rule[T]) Rule[T] {
	return RuleFunc[T](func(v T) bool {
		for _, r := range rules {
			if !r.Match(v) {
				return false
			}
		}
		return true
	})
}

func Or[T any](rules ...Rule[T]) Rule[T] {
	return RuleFunc[T](func(v T) bool {
		for _, r := range rules {
			if r.Match(v) {
				return true
			}
		}
		return false
	})
}

func Not[T any](r Rule[T]) Rule[T] {
	return RuleFunc[T](func(v T) bool {
		return !r.Match(v)
	})
}

func Any[T any]() Rule[T] {
	return RuleFunc[T](func(_ T) bool {
		return true
	})
}

func AnyHTTP() HTTPRule {
	return Any[*http.Request]()
}

func Host(host string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		return r.Host == host
	})
}

func HostPrefix(prefix string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		return strings.HasPrefix(r.Host, prefix)
	})
}

func Path(path string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		return r.URL.Path == path
	})
}

func PathPrefix(prefix string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		return strings.HasPrefix(r.URL.Path, prefix)
	})
}

func Method(methods ...string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		for _, method := range methods {
			if r.Method == method {
				return true
			}
		}
		return false
	})
}

func Header(name, value string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		return r.Header.Get(name) == value
	})
}

func HeaderExists(name string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		_, ok := r.Header[name]
		return ok
	})
}

func QueryParam(name, value string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		return r.URL.Query().Get(name) == value
	})
}

func Secure() HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		return r.TLS != nil
	})
}

func Scheme(scheme string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		return r.URL.Scheme == scheme
	})
}

func RemoteIP(ip string) HTTPRule {
	return RuleFunc[*http.Request](func(r *http.Request) bool {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return false
		}

		return host == ip
	})
}
