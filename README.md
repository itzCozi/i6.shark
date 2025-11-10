# i6.shark

An IPv6 proxy server that allows you to make HTTP requests from randomly generated IPv6 addresses in a /48 subnet. This project basically built the best proxy on earth, a /48 subnet has `1,208,925,819,614,629,174,706,176` (1.2 × 10²⁴) IPv6 addresses, which if you can't tell is a lot. Using a single subnet means those who really want to block you can block your ASN address, so be careful with that. This project is designed to be used for educational purposes only, and should not be used for any illegal activities (totally).

## Features

- Generates random IPv6 addresses based on your IPv6 prefix
- Full HTTP method support (GET, POST, PUT, DELETE, etc.)
- API key authentication for secure usage
- [Community Made Docker Support](https://github.com/SpencerDevs/complex-proxy/blob/main/Dockerfile)

## Requirements

- Go 1.20 or higher
- Linux/Unix system with IPv6 support (preferably Ubuntu latest)
- Root privileges (for port 80 binding and IPv6 manipulation)

## Usage

1. **Configure** constants in src/main.go (example for your VPS):
```go
const (
  SharedSecret          = "REPLACE_WITH_RANDOM_SECRET_32_CHARS"            // Secret between client & server
  Version               = "2.2"                                            // Version of the proxy
  IPv6Prefix            = "2a0a:8dc0:305a"                                 // Your /48 prefix
  IPv6Subnet            = "1000"                                           // Using /64 inside the /48
  Interface             = "ens3"                                           // Network interface on your system
  ListenPort            = 80                                               // Proxy server port
  ListenHost            = "0.0.0.0"                                        // Listen on all interfaces
  RequestTimeout        = 30 * time.Second                                 // Timeout for outbound proxied requests
  Debug                 = false                                            // Enable verbose debug logging
  DesiredPoolSize       = 50                                               // Target number of IPv6 addresses in the pool
  PoolManageInterval    = 1 * time.Second                                  // How often to check/maintain the pool
  PoolAddBatchSize      = 5                                                // Max number of IPs to try adding per cycle
  IPFlushInterval       = 1 * time.Hour                                    // Periodic full pool refresh (rebuild/flush)
  MaxRequestsPerIP      = 15                                               // Rotate an IP after this many proxied requests
  UnusedIPFlushInterval = 10 * time.Minute                                 // Remove IPs that have been unused for this long
  IPInactivityThreshold = 30 * time.Minute                                 // Mark an IP inactive after this idle duration
)
```

2. **Build** the application (Ubuntu 24.04):
```
go build -o i6shark ./src
```

3. **Run** as root (required for port 80 + IPv6 addr ops):
```
sudo ./i6shark
```
<sub>If this works then you can set it up as a systemd service for auto-start on boot.</sub>

4. **Systemd** (optional):
```
sudo tee /etc/systemd/system/i6shark.service >/dev/null <<'EOF'
[Unit]
Description=i6.shark IPv6 proxy
After=network-online.target
Wants=network-online.target
[Service]
WorkingDirectory=/workspaces/i6.shark
ExecStart=/workspaces/i6.shark/i6shark
Restart=always
RestartSec=3
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now i6shark
```
<sub>The proxy server should be able to run without interruption or maintenance it will upkeep it self.</sub>

> **Python Version:**  
> You may also use the python version though, *it is not recommended* as it is not as slower and not up to date.

## API Authentication

API tokens are generated using HMAC-SHA256 and a secret key the input for the key generation is the user-agent header. See the `validateAPIToken` function for implementation details.
