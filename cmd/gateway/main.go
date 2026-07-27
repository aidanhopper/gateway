package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/httputil"
	"net/url"

	"github.com/aidanhopper/gateway/internal/gateway"
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

	gw.AddListener(gateway.Listener{
		Name:       "web",
		Address:    ":8080",
		Protocol:   gateway.ProtoTCP,
		TLSHandler: BasicTLS(),
	})

	gw.AddListener(gateway.Listener{
		Name:     "minecraft",
		Address:  ":25565",
		Protocol: gateway.ProtoTCP,
	})

	url, _ := url.Parse("http://docker-server:8096")

	gw.AddHTTPRoute(gateway.HTTPRoute{
		Name:     "hello",
		Listener: "web",
		Rule:     gateway.Secure(),
		Handler:  httputil.NewSingleHostReverseProxy(url),
	})

	gw.AddTCPRoute(gateway.TCPRoute{
		Name:     "echo back server",
		Listener: "minecraft",
		Rule:     gateway.Any[gateway.TCPMetadata](),
		Handler: gateway.TCPHandlerFunc(func(conn net.Conn, metadata gateway.TCPMetadata) {
			str := fmt.Sprintf("Hello %s\n", metadata.TCP)
			for range 1000 {
				conn.Write([]byte(str))
			}
		}),
	})

	gw.AddTCPRoute(gateway.TCPRoute{
		Name:     "vanilla server",
		Listener: "minecraft",
		Rule:     gateway.And(gateway.IsMinecraft(), gateway.MinecraftPlayer("didscare")),
		Priority: 1,
		Handler: gateway.TCPHandlerFunc(func(conn net.Conn, metadata gateway.TCPMetadata) {
			defer conn.Close()
			upstream, err := net.Dial("tcp", "docker-server:25565")
			if err != nil {
				return
			}
			defer upstream.Close()

			go io.Copy(upstream, conn)
			io.Copy(conn, upstream)
		}),
	})

	log.Fatal(gw.Listen(context.Background()))
}
