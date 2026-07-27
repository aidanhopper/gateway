package gateway

import "fmt"

type Protocol string

const (
	ProtoTCP Protocol = "tcp"
	ProtoUDP Protocol = "udp"
)

func getProtocol(protocol string) (Protocol, error) {
	switch protocol {
	case "tcp":
		return ProtoTCP, nil
	case "tcp6":
		return ProtoTCP, nil
	case "tcp4":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	case "udp6":
		return ProtoUDP, nil
	case "udp4":
		return ProtoUDP, nil
	}

	return "", fmt.Errorf("protocol %s is unsupported", protocol)
}
