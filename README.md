# Gateway

[![Build Status](https://github.com/aidanhopper/gateway/actions/workflows/go.yml/badge.svg)](https://github.com/aidanhopper/gateway/actions/workflows/go.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/aidanhopper/gateway)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Gateway is a lightweight, high-performance reverse proxy and stream routing daemon written in Go. It enables developer-friendly service exposure, automated HTTPS certificate management, dynamic multi-protocol routing (HTTP, HTTPS, TCP, UDP, Minecraft), SQLite persistence, and host firewall management through a single binary and CLI interface.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
  - [Exposing HTTP and HTTPS Services](#exposing-http-and-https-services)
  - [TCP and UDP Stream Proxying](#tcp-and-udp-stream-proxying)
  - [Minecraft Protocol Proxying](#minecraft-protocol-proxying)
  - [HTTP Redirects](#http-redirects)
  - [Inspecting Status and Streaming Logs](#inspecting-status-and-streaming-logs)
  - [Multi-Site Management](#multi-site-management)
- [Configuration](#configuration)
- [Support and Documentation](#support-and-documentation)
- [Maintainers and Contributing](#maintainers-and-contributing)
- [License](#license)

## Features

- **Multi-Protocol Proxying**: Route HTTP, HTTPS, TCP streams, UDP streams, Minecraft protocol, and HTTP redirects (301, 302, 307, 308).
- **Automated TLS & ACME**: Integrated Let's Encrypt / ACME auto-certification with Cloudflare DNS-01 challenge support and self-signed local development fallback.
- **Automated Host Firewall**: Dynamic firewall management supporting UFW, Firewalld, and IPTables to automatically manage open listener ports.
- **Minecraft Protocol Aware**: Deep packet inspection for Minecraft connections, including player name whitelisting, blacklisting, and SNI/host-based routing.
- **Single Binary & Embedded DB**: Pure Go implementation using embedded SQLite (`modernc.org/sqlite`) requiring no external database or CGO toolchain.
- **REST API & CLI**: Full CLI control with Tailscale-style status outputs, live log streaming, token authentication, and multi-site configuration support.

## Getting Started

### Prerequisites

- Linux or macOS operating system.
- [Go](https://go.dev/) version 1.25 or higher (for building from source).

### Installation

#### Automated Script Installation

Use the included installer script [deploy/install.sh](deploy/install.sh):

```bash
# Install server daemon, systemd unit, and /etc/gateway configuration (requires root/sudo)
sudo ./deploy/install.sh --server

# Install CLI client only (user-level installation to ~/.local/bin)
./deploy/install.sh --client
```

#### Building with Makefile

Clone the repository and build the binary:

```bash
git clone https://github.com/aidanhopper/gateway.git
cd gateway
make build
```

To install the built binary to your system:

```bash
# Server installation
make install-server

# Client-only installation
make install-client
```

### Quick Start

1. Start the Gateway daemon:
   ```bash
   gateway daemon
   ```
   *(If installed via `install-server`, the daemon runs automatically as a systemd service).*

2. Verify system status:
   ```bash
   gateway status
   ```

3. Expose your first local application:
   ```bash
   gateway serve http / 8080
   ```

## Usage Examples

### Exposing HTTP and HTTPS Services

Expose a local HTTP server running on port 8080 at path `/api`:
```bash
gateway serve http app.example.com/api 8080
```

Expose an HTTPS service with automatic ACME certificate generation:
```bash
gateway serve app.example.com 3000 --acme
```

### TCP and UDP Stream Proxying

Proxy raw TCP traffic from port 9000 to an internal service on 127.0.0.1:9001:
```bash
gateway serve tcp 9000 127.0.0.1:9001
```

Proxy UDP traffic on port 9000:
```bash
gateway serve udp 9000 127.0.0.1:9002
```

### Minecraft Protocol Proxying

Proxy a Minecraft server on port 25565 with player access control:
```bash
gateway serve mc mc.example.com 25565 --allow Notch,Jeb
```

```bash
gateway serve mc mc.example.com 25565 --deny Hacker
```

### HTTP Redirects

Redirect HTTP and HTTPS requests from an old domain to a new URL:
```bash
gateway serve redirect old.example.com https://new.example.com
```

### Inspecting Status and Streaming Logs

Display active listeners, routes, and daemon status:
```bash
gateway status
```

Stream live daemon proxy logs:
```bash
gateway logs
```

### Multi-Site Management

Manage and switch between remote Gateway daemon instances:
```bash
# List configured remote sites
gateway site list

# Switch target active site
gateway site use staging

# Ping the active site daemon
gateway site ping
```

Client site endpoints are configured in `~/.config/gateway/config.yaml`.

## Configuration

Server daemon configuration is read from `/etc/gateway/server.yaml` (or `~/.config/gateway/server.yaml` in user mode):

```yaml
api:
  listen: "127.0.0.1:9090"
database: "/var/lib/gateway/gateway.db"
public: false
firewall:
  driver: "auto"
  protected_ports:
    - 22
    - 9090
log:
  level: "info"
acme:
  email: "admin@example.com"
  cloudflare_token: "your-dns-api-token"
```

Environment variables can also override configuration settings:
- `GATEWAY_CONFIG`: Custom path to `server.yaml`
- `GATEWAY_ACME_EMAIL`: ACME registration email address
- `CF_DNS_API_TOKEN`: Cloudflare API token for DNS-01 verification
- `GATEWAY_PUBLIC`: Set `true` to declare public exposure

## Support and Documentation

- **Bug Reports & Feature Requests**: Open an issue on [GitHub Issues](https://github.com/aidanhopper/gateway/issues).
- **Service Deployment Guide**: See [deploy/install.sh](deploy/install.sh) and [deploy/server.yaml](deploy/server.yaml) for deployment specs.

## Maintainers and Contributing

Maintained by Aidan Hopper ([@aidanhopper](https://github.com/aidanhopper)).

Contributions are welcome! Please review the [CONTRIBUTING.md](CONTRIBUTING.md) guide before submitting pull requests or issue reports.

## License

Gateway is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for full details.
