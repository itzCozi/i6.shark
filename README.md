# i6.shark

An IPv6 proxy server that allows you to make HTTP requests from randomly generated IPv6 addresses in a /48 subnet. This project basically built the best proxy on earth, a /48 subnet has `1,208,925,819,614,629,174,706,176` (1.2 × 10²⁴) IPv6 addresses, which if you can't tell is a lot. Using a single subnet means those who really want to block you can block your ASN address, so be careful with that. This project is designed to be used for educational purposes only, and should not be used for any illegal activities (totally).

## Features

- Generates random IPv6 addresses based on your IPv6 prefix
- API key authentication for secure usage
- Full HTTP method support (GET, POST, PUT, DELETE, etc.)

## Requirements

- Go 1.20 or higher
- Linux/Unix system with IPv6 support
- Root privileges (for port 80 binding and IPv6 manipulation)

## Configuration

Edit the constants at the top of the `main.go` file:

```go
const (
	SharedSecret       = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // Secret between client & server
	Version            = "2.2"                              // Version of the script
	IPv6Prefix         = "xxxx:xxxx:xxxx"                   // Your /48 prefix
	IPv6Subnet         = "1000"                             // Using subnet 1000 within your /48
	Interface          = "ens3"                             // Detected interface from your system
	ListenPort         = 80                                 // Proxy server port
	ListenHost         = "0.0.0.0"                          // Listen on all interfaces
	RequestTimeout     = 30 * time.Second                   // Request timeout in seconds
	Debug              = false                              // Enable debug output
	DesiredPoolSize    = 100                                // Target number of IPs in the pool
	PoolManageInterval = 5 * time.Second                    // Check/add less frequently (every 5 seconds)
	PoolAddBatchSize   = 5                                  // Try to add up to 5 IPs per cycle if needed
)
```

## Usage

1. Build the application:
```
go build -o i6shark
```

2. Run with root privileges:
```
sudo ./i6shark
```

3. Send requests through the proxy:
```
curl "http://localhost/?url=https://example.com" -H "API-Token: VALID_API_TOKEN"
```

> **Python Version:**  
> You may also use the python version though, *it is not recommended* as it is not as slower and not up to date.

## API Authentication

API tokens are generated using HMAC-SHA256 and a secret key the input for the key generation is the user-agent header. See the `validateAPIToken` function for implementation details.
