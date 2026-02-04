# i6.shark

An IPv6 proxy server that allows you to make HTTP requests from randomly generated IPv6 addresses in a /48 subnet. This project basically built the best proxy on earth, a /48 subnet has `1,208,925,819,614,629,174,706,176` (1.2 × 10²⁴) IPv6 addresses, which if you can't tell is a lot. Using a single subnet means those who really want to block you can block your ASN address, so be careful with that. This project is designed to be used for educational purposes only, and should not be used for any illegal activities (totally).

## Features

- **Random IPv6 Generation**: Creates random IPv6 addresses from your /48 prefix for each request
- **Full HTTP Method Support**: GET, POST, PUT, DELETE, and all other HTTP methods
- **HMAC-SHA256 Authentication**: Secure API key authentication using user-agent based tokens
- **Intelligent IP Pool Management**: 
  - Automatic IP rotation with configurable pool size
  - Smart IP lifecycle management (add, track usage, auto-flush)
  - Per-IP request counting with automatic rotation after max requests
  - Unused IP cleanup based on inactivity threshold
- **Advanced Request Handling**:
  - Custom header forwarding via JSON query parameter
  - Cloudflare and CDN header stripping for anonymity
  - Support for multiple URL parameter formats (`?url=`, `?destination=`, or path-based)
  - Optional fallback to system default IP with `?normal` parameter
- **Host Whitelisting**: Built-in domain whitelist for security (configurable in code)
- **Automatic Maintenance**:
  - Periodic IP pool flushing (hourly by default)
  - Subnet validation and cleanup
  - Connection pooling and keepalive optimization
- **High Performance**:
  - Concurrent request handling with buffer pooling
  - Configurable timeouts and connection limits
  - Efficient IPv6 address management via netlink
- **Debug Mode**: Detailed logging for troubleshooting and monitoring
- [Community Made Docker Support](https://github.com/SpencerDevs/complex-proxy/blob/main/Dockerfile)

## Requirements

- Go 1.20 or higher
- Linux/Unix system with IPv6 support (preferably Ubuntu)
- Root privileges (for port 80 binding and IPv6 manipulation)
- IPv6 /48 subnet allocation from your hosting provider

## Hosting Providers
- [Clouvider](https://clouvider.co.uk/) - All payments
- [BuyVM](https://buyvm.net/) - All payments
- [SoftShellWeb](https://softshellweb.com/) - All payments
- [Aeza](https://aeza.io/) - BTC only 11/11/25

## Usage

1. **Configure** constants in src/main.go (example for your VPS):
```go
const (
	SharedSecret          = "REPLACE_WITH_RANDOM_SECRET_32_CHARS" // Secret between client & server
	Version               = "2.3"                                 // Version of the script
	IPv6Prefix            = "xxxx:xxxx:xxxx"                      // Your /48 prefix
	IPv6Subnet            = "6000"                                // Using subnet 1000 within your /48
	Interface             = "ens3"                                // Detected interface from your system
	ListenPort            = 80                                    // Proxy server port
	ListenHost            = "0.0.0.0"                             // Listen on all interfaces
	RequestTimeout        = 30 * time.Second                      // Request timeout in seconds
	Debug                 = false                                 // Enable debug output
	RequireAuth           = true                                  // Require API-Token authentication
	DesiredPoolSize       = 50                                    // Target number of IPs in the pool (Increased for high concurrency)
	PoolManageInterval    = 1 * time.Second                       // Check/add very frequently with minimal blocking
	PoolAddBatchSize      = 5                                     // Larger batches for faster pool growth
	IPFlushInterval       = 1 * time.Hour                         // Flush all IPs every hour
	MaxRequestsPerIP      = 15                                    // Maximum requests allowed per IP before rotation
	UnusedIPFlushInterval = 10 * time.Minute                      // Check for unused IPs every 10 minutes
	IPInactivityThreshold = 30 * time.Minute                      // Remove IP if unused for this duration
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
WorkingDirectory=/opt/i6.shark
ExecStart=/opt/i6.shark/i6shark
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
