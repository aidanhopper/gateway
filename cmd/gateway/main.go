package main

import (
	"fmt"
	"os"

	"github.com/aidanhopper/gateway/internal/cli"
)

func main() {
	if len(os.Args) < 2 {
		cli.PrintUsage()
		os.Exit(0)
	}

	command := os.Args[1]
	if command == "--help" || command == "-h" || command == "help" {
		cli.PrintUsage()
		os.Exit(0)
	}

	switch command {
	case "daemon":
		cli.RunDaemon(os.Args[2:])
	case "serve":
		cli.RunServe(os.Args[2:])
	case "status":
		cli.RunStatus("", "", "")
	case "token":
		if len(os.Args) < 3 || os.Args[2] == "--help" || os.Args[2] == "-h" {
			fmt.Println("Usage: gateway token <create|list|revoke> [flags]")
			os.Exit(0)
		}
		cli.RunToken(os.Args[2], os.Args[3:])
	case "listener", "listeners":
		if len(os.Args) < 3 || os.Args[2] == "--help" || os.Args[2] == "-h" {
			fmt.Println("Usage: gateway listener <list|create|delete> [flags]")
			os.Exit(0)
		}
		cli.RunListener(os.Args[2], os.Args[3:])
	case "route", "routes":
		if len(os.Args) < 3 || os.Args[2] == "--help" || os.Args[2] == "-h" {
			fmt.Println("Usage: gateway route <list|create|delete> [flags]")
			os.Exit(0)
		}
		cli.RunRoute(os.Args[2], os.Args[3:])
	default:
		cli.PrintUsage()
		os.Exit(0)
	}
}
