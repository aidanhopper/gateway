package gateway

type Listener struct {
	Name     string
	Address  string
	Protocol Protocol
	TLSHandler TLSConfigHandler
}
