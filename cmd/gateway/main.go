package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

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

	gw.AddHTTPRoute(gateway.HTTPRoute{
		Name:     "hello",
		Listener: "web",
		Rule:     gateway.Path("/abc"),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello world"))
		}),
	})

	log.Fatal(gw.Listen(context.Background()))
}
