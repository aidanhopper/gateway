package main

import (
	"fmt"
	"os"

	"github.com/aidanhopper/gateway/internal/cli"
)

const Version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		cli.PrintUsage()
		os.Exit(0)
	}

	command := os.Args[1]
	if command == "--version" || command == "-v" || command == "version" {
		fmt.Printf("gateway version %s\n", Version)
		os.Exit(0)
	}

	if command == "--help" || command == "-h" || command == "help" {
		cli.PrintUsage()
		os.Exit(0)
	}

	switch command {
	case "daemon":
		cli.RunDaemon(os.Args[2:])
	case "serve", "s":
		cli.RunServe(os.Args[2:])
	case "status", "stat":
		cli.RunStatus(os.Args[2:])
	case "logs", "log":
		cli.RunLogs(os.Args[2:])
	case "token", "tokens":
		if len(os.Args) < 3 || os.Args[2] == "--help" || os.Args[2] == "-h" {
			fmt.Println("Usage: gateway token <create|list|revoke> [flags]")
			os.Exit(0)
		}
		cli.RunToken(os.Args[2], os.Args[3:])
	case "listener", "listeners":
		if len(os.Args) < 3 || os.Args[2] == "--help" || os.Args[2] == "-h" {
			fmt.Println("Usage: gateway listener <list|delete> [flags]")
			os.Exit(0)
		}
		cli.RunListener(os.Args[2], os.Args[3:])
	case "route", "routes":
		if len(os.Args) < 3 || os.Args[2] == "--help" || os.Args[2] == "-h" {
			fmt.Println("Usage: gateway route <list|delete> [flags]")
			os.Exit(0)
		}
		cli.RunRoute(os.Args[2], os.Args[3:])
	case "site", "sites":
		if len(os.Args) < 3 || os.Args[2] == "--help" || os.Args[2] == "-h" {
			fmt.Println("Usage: gateway site <list|use|ping> [args]")
			os.Exit(0)
		}
		cli.RunSite(os.Args[2], os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] Unknown command %q\n\n", command)
		cli.PrintUsage()
		os.Exit(2)
	}
}
