# Gateway Production Deployment Guide

This guide covers deploying Gateway as a client or production server.

## Installation Modes

### Option A: Install CLI Client Only (Laptop / Workstation)
To install only the CLI client without systemd service or server configuration:

```bash
# Non-root installation to ~/.local/bin/gateway
./deploy/install.sh --client
```
*Or using Makefile:*
```bash
make install-client
```

---

### Option B: Full Server Daemon Installation (Linux VPS)
To install the full server daemon, `/etc/gateway/server.yaml`, and systemd service:

```bash
sudo ./deploy/install.sh --server
```
*Or using Makefile:*
```bash
make install-server
```

The server installer performs the following actions:
1. Detects system architecture (`amd64`, `arm64`, etc.).
2. Installs executable binary to `/usr/local/bin/gateway`.
3. Creates `/etc/gateway/server.yaml` and `/var/lib/gateway/` data directory.
4. Installs systemd unit (`/etc/systemd/system/gateway.service`) with ambient capabilities (`CAP_NET_BIND_SERVICE`, `CAP_NET_ADMIN`).
5. Enables and starts the `gateway.service` background daemon.

---

## Systemd Service Management

Manage the running Gateway daemon with standard `systemctl` commands:

```bash
# Check daemon status
sudo systemctl status gateway

# Restart daemon
sudo systemctl restart gateway

# Stop daemon
sudo systemctl stop gateway

# View live systemd journal logs
sudo journalctl -u gateway -f
```

---

## Server Configuration (`/etc/gateway/server.yaml`)

The daemon configuration file is located at `/etc/gateway/server.yaml`:

```yaml
# Gateway Server Configuration
api:
  listen: "127.0.0.1:9090" # REST API listen address

database: "/var/lib/gateway/gateway.db" # SQLite database path

public: false # Set to true if target server is directly exposed to public internet

firewall:
  driver: "auto" # Firewall driver: auto, ufw, iptables, pf, firewalld, dry, noop
  protected_ports:
    - 22
    - 9090

log:
  level: "info" # info, warn, error
```

---

## Host Firewall Integration

Gateway automatically detects your operating system's firewall manager (`ufw`, `iptables`, `firewalld`, `pfctl`) and opens/closes ports dynamically as listeners bind or unbind.

To override the automatically detected firewall driver, update `firewall.driver` in `/etc/gateway/server.yaml`:
```yaml
firewall:
  driver: "ufw" # Force UFW driver
```

---

## Remote CLI Pairing & Authentication

### 1. Generate an API Auth Token on the Server
To allow remote CLI management from your local workstation:

```bash
sudo gateway token create my-laptop-key
```
*Outputs a secure bearer token.*

### 2. Configure Remote CLI on Your Workstation (`~/.config/gateway/config.yaml`)
Add your production server as a named site:

```yaml
active_site: "prod-server"
sites:
  prod-server:
    url: "https://gateway.yourdomain.com:9090"
    token: "<your-generated-bearer-token>"
```

Or switch active target site on the fly:
```bash
gateway site use prod-server
```

---

## Live System Log Streaming

Stream real-time daemon console logs remotely over SSE:

```bash
gateway site logs
```

Or stream traffic logs for active proxy routes:
```bash
gateway logs
```

---

## Health Check Probe

For uptime monitoring (Uptime Kuma, Datadog, AWS Route53), Gateway provides a lightweight health endpoint:

```bash
curl http://127.0.0.1:9090/api/v1/health
```

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "public": false,
  "listeners": 3,
  "routes": 5
}
```
