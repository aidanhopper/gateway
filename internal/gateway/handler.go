package gateway

import "encoding/json"

// Informer is an optional interface handlers may implement to expose
// live runtime data (such as connection stats or target addresses)
// in route GET API responses.
// Info must return valid, pre-encoded JSON (json.RawMessage).
type Informer interface {
	Info() json.RawMessage
}
