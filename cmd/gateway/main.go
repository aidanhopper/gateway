package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/aidanhopper/gateway/internal/gateway"
	"github.com/aidanhopper/gateway/internal/handlers"
)

func BasicTLS() gateway.TLSConfigHandler {
	return gateway.TLSConfigHandlerFunc(func(info *gateway.TLSInfo) (*tls.Config, error) {
		cert, err := tls.LoadX509KeyPair("cert/server.crt", "cert/server.key")
		if err != nil {
			return nil,
				fmt.Errorf("Failed to load x509 certifcate from the filesystem with error: %s\n", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}, nil
	})
}

func main() {
	gw := gateway.New()

	// gw.AddListener(gateway.Listener{
	// 	Name:       "minecraft",
	// 	Address:    ":25565",
	// 	Protocol:   gateway.ProtoTCP,
	// 	TLSHandler: BasicTLS(),
	// })

	// url, _ := url.Parse("http://docker-server:8096")
	// gw.AddHTTPRoute(gateway.HTTPRoute{
	// 	Name:     "hello",
	// 	Listener: "minecraft",
	// 	Rule:     gateway.Secure(),
	// 	Handler:  httputil.NewSingleHostReverseProxy(url),
	// })

	// gw.AddTCPRoute(gateway.TCPRoute{
	// 	Name:     "vanilla server",
	// 	Listener: "minecraft",
	// 	Rule:     gateway.And(gateway.IsMinecraft(), gateway.MinecraftPlayer("didscare")),
	// 	Priority: 1,
	// 	Handler:  handlers.NewTCPReverseProxy("docker-server:25565"),
	// })

	go gw.Listen(context.Background())

	for {
		gw.AddListener(gateway.Listener{
			Name:       "web",
			Address:    ":8080",
			Protocol:   gateway.ProtoTCP,
			TLSHandler: BasicTLS(),
		})
		gw.AddTCPRoute(gateway.TCPRoute{
			Name:     "echo back server",
			Listener: "web",
			Rule:     gateway.And(gateway.NotHTTP(), gateway.NotMinecraft(), gateway.NotTLS()),
			Handler:  handlers.NewTCPEchoServer(),
		})
		time.Sleep(3 * time.Second)
		gw.RemoveListener("web")
		time.Sleep(3 * time.Second)
	}
}
