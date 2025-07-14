package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	SharedSecret          = "YCLKMuY0F3xhn.QFwLZ1zYG-6Y3GH_cc" // Secret between client & server
	Version               = "2.2"                              // Version of the script
	IPv6Prefix            = "2a01:e5c0:9513"                   // Your /48 prefix
	IPv6Subnet            = "6000"                             // Using subnet 1000 within your /48
	Interface             = "ens3"                             // Detected interface from your system
	ListenPort            = 80                                 // Proxy server port
	ListenHost            = "0.0.0.0"                          // Listen on all interfaces
	RequestTimeout        = 30 * time.Second                   // Request timeout in seconds
	Debug                 = false                              // Enable debug output
	DesiredPoolSize       = 50                                 // Target number of IPs in the pool (Increased for high concurrency)
	PoolManageInterval    = 1 * time.Second                    // Check/add very frequently with minimal blocking
	PoolAddBatchSize      = 5                                  // Larger batches for faster pool growth
	IPFlushInterval       = 1 * time.Hour                      // Flush all IPs every hour
	MaxRequestsPerIP      = 15                                 // Maximum requests allowed per IP before rotation
	UnusedIPFlushInterval = 10 * time.Minute                   // Check for unused IPs every 10 minutes
	IPInactivityThreshold = 30 * time.Minute                   // Remove IP if unused for this duration
)

// IPUsageTracker tracks usage statistics for each IP address
type IPUsageTracker struct {
	IP           string    // The IPv6 address
	RequestCount int       // Number of requests made with this IP
	LastUsed     time.Time // Last time this IP was used for a request
	Added        time.Time // When this IP was added to the pool
	InUseCount   int32     // Number of ongoing requests using this IP (atomic)
}

var requestCount int
var defaultClient *http.Client
var defaultTransport *http.Transport

var (
	ipPoolWithUsage []*IPUsageTracker
	poolMutex       sync.Mutex
	currentIPIndex  int
	urgentAddChan   = make(chan struct{}, 10) // Channel to signal urgent IP additions
)
var skipHeaders = map[string]bool{
	"transfer-encoding": true,
	"content-encoding":  true,
	"content-length":    true,
	"connection":        true,
	"keep-alive":        true,
	"server":            true,
}

// headersToStripBeforeForwarding defines request headers that should be removed
// from the incoming client request before forwarding it to the target server.
// Headers are stored in lowercase for case-insensitive matching.
var headersToStripBeforeForwarding = map[string]bool{
	"cf-connecting-ip":  true, // Reveals original client IP to Cloudflare
	"cf-ipcountry":      true, // Reveals client's country via Cloudflare
	"cf-ray":            true, // Cloudflare's request tracing ID
	"cf-visitor":        true, // Contains scheme used by client to connect to Cloudflare
	"cf-worker":         true, // Identifies the request came from a Cloudflare Worker
	"cf-ew-via":         true, // Indicates request routed via Cloudflare Edge Workers/services
	"x-forwarded-for":   true, // Standard header for identifying originating IP of a client connecting through proxies
	"x-forwarded-proto": true, // Standard header for identifying protocol client used to connect
	"cdn-loop":          true, // Indicates a CDN loop, often set by CDNs
	"true-client-ip":    true, // Alternative header for original client IP
	"x-real-ip":         true, // Common alternative for original client IP, often set by reverse proxies
}

func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// normalizeIPv6 ensures IPv6 addresses are in canonical form without leading zeros
func normalizeIPv6(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr // Return original if parsing fails
	}
	return ip.String()
}

func randomIPv6() string {
	hostPart1 := rand.Uint32()
	hostPart2 := rand.Uint32()

	// Generate IPv6 address without leading zeros in segments
	// Use %x instead of %04x to avoid leading zeros
	rawIP := fmt.Sprintf("%s:%s:%x:%x:%x:%x",
		IPv6Prefix,
		IPv6Subnet,
		(hostPart1>>16)&0xFFFF,
		hostPart1&0xFFFF,
		(hostPart2>>16)&0xFFFF,
		hostPart2&0xFFFF)

	ip := net.ParseIP(rawIP)
	if ip == nil {
		return fmt.Sprintf("%s:%s:%04x:%04x:%04x:%04x",
			IPv6Prefix,
			IPv6Subnet,
			(hostPart1>>16)&0xFFFF,
			hostPart1&0xFFFF,
			(hostPart2>>16)&0xFFFF,
			hostPart2&0xFFFF)
	}

	return ip.String()
}

func checkInterface() bool {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			fmt.Printf("WARNING: Interface %s not found.\n", Interface)
		} else {
			fmt.Printf("Error checking interface %s: %v\n", Interface, err)
		}
		links, listErr := netlink.LinkList()
		if listErr == nil {
			fmt.Println("Available interfaces:")
			for _, l := range links {
				fmt.Printf("  - %s\n", l.Attrs().Name)
			}
		}
		return false
	}
	if (link.Attrs().Flags & net.FlagUp) == 0 {
		fmt.Printf("WARNING: Interface %s is down.\n", Interface)
	}
	fmt.Printf("Interface %s found and appears up.\n", Interface)
	return true
}

func addIPv6ToInterface(ipv6 string) bool {
	// Add timeout to prevent blocking
	done := make(chan bool, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("addIPv6: Recovered from panic adding %s: %v\n", ipv6, r)
				done <- false
			}
		}()

		link, err := netlink.LinkByName(Interface)
		if err != nil {
			if Debug {
				fmt.Printf("addIPv6: Failed to find link %s: %v\n", Interface, err)
			}
			done <- false
			return
		}

		addr, err := netlink.ParseAddr(ipv6 + "/128")
		if err != nil {
			if Debug {
				fmt.Printf("addIPv6: Failed to parse address %s/128: %v\n", ipv6, err)
			}
			done <- false
			return
		}

		err = netlink.AddrAdd(link, addr)
		if err != nil {
			if err.Error() == "file exists" {
				if Debug {
					fmt.Printf("addIPv6: Address %s already exists on %s (ignored).\n", ipv6, Interface)
				}
				done <- true
				return
			} else {
				if Debug {
					fmt.Printf("addIPv6: Failed to add address %s to %s: %v\n", ipv6, Interface, err)
				}
				done <- false
				return
			}
		}

		if Debug {
			fmt.Printf("addIPv6: Successfully added %s to %s via netlink.\n", ipv6, Interface)
		}
		done <- true
	}()

	// Wait for completion
	select {
	case result := <-done:
		return result
	case <-time.After(2 * time.Second):
		fmt.Printf("addIPv6: Timeout adding %s to interface\n", ipv6)
		return false
	}
}

func removeIPv6FromInterface(ipv6 string) bool {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		fmt.Printf("removeIPv6: Failed to find link %s: %v\n", Interface, err)
		return false
	}

	addr, err := netlink.ParseAddr(ipv6 + "/128")
	if err != nil {
		fmt.Printf("removeIPv6: Failed to parse address %s/128: %v\n", ipv6, err)
		return false
	}

	// Retry logic for network operations
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		err = netlink.AddrDel(link, addr)
		if err == nil {
			if Debug {
				fmt.Printf("removeIPv6: Successfully removed %s from %s via netlink (attempt %d).\n",
					ipv6, Interface, attempt+1)
			}
			return true
		}

		// Check if address doesn't exist (not an error)
		if strings.Contains(err.Error(), "cannot assign requested address") ||
			strings.Contains(err.Error(), "no such file or directory") {
			if Debug {
				fmt.Printf("removeIPv6: Address %s not found on %s (already removed)\n", ipv6, Interface)
			}
			return true
		}

		if attempt == maxRetries-1 {
			fmt.Printf("removeIPv6: error removing address %s from %s after %d attempts: %v\n",
				ipv6, Interface, maxRetries, err)
		} else if Debug {
			fmt.Printf("removeIPv6: retry %d for %s: %v\n", attempt+1, ipv6, err)
		}

		// Small delay between retries
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}

	return false
}

// flushAllIPAddresses removes all IPv6 addresses from the interface that match our prefix pattern
func flushAllIPAddresses() {
	fmt.Println("Starting complete IPv6 address flush...")

	link, err := netlink.LinkByName(Interface)
	if err != nil {
		fmt.Printf("Error finding interface %s during flush: %v\n", Interface, err)
		return
	}

	addrs, err := netlink.AddrList(link, unix.AF_INET6)
	if err != nil {
		fmt.Printf("Error listing IPv6 addresses during flush: %v\n", err)
		return
	}

	var flushedCount int32
	var addressesToRemove []netlink.Addr

	for _, addr := range addrs {
		ipStr := addr.IP.String()
		// Remove any IP that starts with our prefix, regardless of subnet
		// This ensures we clean up old IPs from different subnets
		if strings.HasPrefix(ipStr, IPv6Prefix+":") && !strings.Contains(ipStr, "::") {
			addressesToRemove = append(addressesToRemove, addr)
			if Debug {
				fmt.Printf("Marked for removal: %s\n", ipStr)
			}
		}
	}

	fmt.Printf("Found %d IPv6 addresses to remove matching prefix %s:%s\n",
		len(addressesToRemove), IPv6Prefix, IPv6Subnet)

	// Remove addresses with limited concurrency to avoid overwhelming the system
	const maxConcurrent = 10
	semaphore := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, addr := range addressesToRemove {
		wg.Add(1)
		go func(address netlink.Addr) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Retry logic for network operations
			maxRetries := 3
			for attempt := 0; attempt < maxRetries; attempt++ {
				err := netlink.AddrDel(link, &address)
				if err == nil {
					atomic.AddInt32(&flushedCount, 1)
					if Debug {
						fmt.Printf("Successfully removed %s (attempt %d)\n", address.IP.String(), attempt+1)
					}
					break
				} else {
					if attempt == maxRetries-1 {
						fmt.Printf("Failed to remove %s after %d attempts: %v\n",
							address.IP.String(), maxRetries, err)
					} else if Debug {
						fmt.Printf("Retry %d for %s: %v\n", attempt+1, address.IP.String(), err)
					}
					// Small delay between retries
					time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
				}
			}
		}(addr)
	}

	wg.Wait()

	// Clear the IP pool
	poolMutex.Lock()
	oldSize := len(ipPoolWithUsage)
	ipPoolWithUsage = make([]*IPUsageTracker, 0, DesiredPoolSize)
	currentIPIndex = 0
	poolMutex.Unlock()

	fmt.Printf("IP flush complete: removed %d/%d addresses from interface, cleared %d IPs from pool\n",
		flushedCount, len(addressesToRemove), oldSize)
}

// periodicIPFlush runs a complete IP flush at regular intervals
func periodicIPFlush() {
	ticker := time.NewTicker(IPFlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Printf("Performing scheduled IP flush (interval: %s)\n", IPFlushInterval)
		flushAllIPAddresses()
	}
}

// flushUnusedIPs removes IPv6 addresses that haven't been used for a specified duration
func flushUnusedIPs() {
	poolMutex.Lock()
	defer poolMutex.Unlock()

	if len(ipPoolWithUsage) == 0 {
		return
	}

	now := time.Now()
	var ipsToRemove []string
	newPool := make([]*IPUsageTracker, 0, len(ipPoolWithUsage))

	for _, tracker := range ipPoolWithUsage {
		inUseCount := atomic.LoadInt32(&tracker.InUseCount)

		// Calculate how long the IP has been inactive
		var inactiveTime time.Duration
		if tracker.LastUsed.IsZero() {
			// Never used - check how long since it was added
			inactiveTime = now.Sub(tracker.Added)
		} else {
			// Used before - check how long since last use
			inactiveTime = now.Sub(tracker.LastUsed)
		}

		// Remove if inactive for too long, hasn't reached request limit, and not currently in use
		if inactiveTime > IPInactivityThreshold && tracker.RequestCount < MaxRequestsPerIP && inUseCount == 0 {
			ipsToRemove = append(ipsToRemove, tracker.IP)
			if Debug {
				fmt.Printf("Marking unused IP %s for removal (inactive for %s, used %d times)\n",
					tracker.IP, inactiveTime.Round(time.Minute), tracker.RequestCount)
			}
		} else {
			newPool = append(newPool, tracker)
			if inUseCount > 0 && Debug {
				fmt.Printf("Keeping inactive IP %s temporarily (%d ongoing requests)\n",
					tracker.IP, inUseCount)
			}
		}
	}

	ipPoolWithUsage = newPool

	// Reset index if it's out of bounds
	if currentIPIndex >= len(ipPoolWithUsage) && len(ipPoolWithUsage) > 0 {
		currentIPIndex = 0
	}

	// Remove unused IPs from interface (done outside the lock)
	if len(ipsToRemove) > 0 {
		poolMutex.Unlock() // Unlock temporarily for interface operations

		var wg sync.WaitGroup
		for _, unusedIP := range ipsToRemove {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				removeIPv6FromInterface(ip)
			}(unusedIP)
		}
		wg.Wait()

		fmt.Printf("Removed %d unused IPs from interface and pool\n", len(ipsToRemove))

		poolMutex.Lock() // Re-lock for the defer unlock
	}
}

// periodicUnusedIPFlush runs unused IP cleanup at regular intervals
func periodicUnusedIPFlush() {
	ticker := time.NewTicker(UnusedIPFlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		if Debug {
			fmt.Printf("Checking for unused IPs (inactive threshold: %s)\n", IPInactivityThreshold)
		}
		flushUnusedIPs()
	}
}

// cleanupWrongSubnetIPs removes any IPs that don't match the current subnet configuration
// normalizeIPPool ensures all IPs in the pool are in canonical form
func normalizeIPPool() {
	poolMutex.Lock()
	defer poolMutex.Unlock()

	normalizedCount := 0
	for _, tracker := range ipPoolWithUsage {
		originalIP := tracker.IP
		normalizedIP := normalizeIPv6(originalIP)
		if originalIP != normalizedIP {
			tracker.IP = normalizedIP
			normalizedCount++
			if Debug {
				fmt.Printf("Normalized IP: %s -> %s\n", originalIP, normalizedIP)
			}
		}
	}

	if normalizedCount > 0 {
		fmt.Printf("Normalized %d IPv6 addresses in pool to canonical form\n", normalizedCount)
	}
}

func cleanupWrongSubnetIPs() {
	fmt.Printf("Cleaning up IPs from wrong subnets (keeping only %s:%s:*)\n", IPv6Prefix, IPv6Subnet)

	link, err := netlink.LinkByName(Interface)
	if err != nil {
		fmt.Printf("Error finding interface %s during subnet cleanup: %v\n", Interface, err)
		return
	}

	addrs, err := netlink.AddrList(link, unix.AF_INET6)
	if err != nil {
		fmt.Printf("Error listing IPv6 addresses during subnet cleanup: %v\n", err)
		return
	}

	expectedPrefix := IPv6Prefix + ":" + IPv6Subnet + ":"
	var wrongSubnetIPs []netlink.Addr
	var correctSubnetCount int

	// Identify IPs that need to be removed
	for _, addr := range addrs {
		ipStr := addr.IP.String()
		if strings.HasPrefix(ipStr, IPv6Prefix+":") && !strings.Contains(ipStr, "::") {
			if !strings.HasPrefix(ipStr, expectedPrefix) {
				wrongSubnetIPs = append(wrongSubnetIPs, addr)
				fmt.Printf("Found wrong subnet IP: %s (expected prefix: %s)\n", ipStr, expectedPrefix)
			} else {
				correctSubnetCount++
			}
		}
	}

	// Remove wrong subnet IPs
	if len(wrongSubnetIPs) > 0 {
		var wg sync.WaitGroup
		var removedCount int32

		for _, addr := range wrongSubnetIPs {
			wg.Add(1)
			go func(address netlink.Addr) {
				defer wg.Done()
				err := netlink.AddrDel(link, &address)
				if err != nil {
					fmt.Printf("Failed to remove wrong subnet IP %s: %v\n", address.IP.String(), err)
				} else {
					atomic.AddInt32(&removedCount, 1)
				}
			}(addr)
		}

		wg.Wait()
		fmt.Printf("Subnet cleanup complete: removed %d wrong subnet IPs, kept %d correct subnet IPs\n",
			removedCount, correctSubnetCount)
	} else {
		fmt.Printf("Subnet cleanup: no wrong subnet IPs found, %d correct subnet IPs present\n", correctSubnetCount)
	}

	// Clean up the pool
	poolMutex.Lock()
	defer poolMutex.Unlock()

	newPool := make([]*IPUsageTracker, 0, len(ipPoolWithUsage))
	var poolCleaned int

	for _, tracker := range ipPoolWithUsage {
		if strings.HasPrefix(tracker.IP, expectedPrefix) {
			newPool = append(newPool, tracker)
		} else {
			poolCleaned++
			fmt.Printf("Removed wrong subnet IP from pool: %s\n", tracker.IP)
		}
	}

	ipPoolWithUsage = newPool
	if currentIPIndex >= len(ipPoolWithUsage) && len(ipPoolWithUsage) > 0 {
		currentIPIndex = 0
	}

	if poolCleaned > 0 {
		fmt.Printf("Cleaned %d wrong subnet IPs from pool\n", poolCleaned)
	}
}

func ensureURLHasScheme(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return "https://" + urlStr
	}
	return urlStr
}

func logRequest(r *http.Request) {
	requestCount++
	fmt.Printf("\nIncoming request #%d\n", requestCount)
}

func validateAPIToken(apiToken string, userAgent string) bool {
	key := []byte(userAgent)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(SharedSecret))
	expectedHash := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(apiToken), []byte(expectedHash))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	apiToken := r.Header.Get("API-Token")
	userAgent := r.Header.Get("User-Agent")

	if !validateAPIToken(apiToken, userAgent) {
		http.Error(w, "Unauthorized: i6.shark detected invalid API-Token header.", http.StatusUnauthorized)
		return
	}

	logRequest(r)

	if Debug {
		fmt.Printf("Raw query string: %s\n", r.URL.RawQuery)
		fmt.Println("Incoming request headers received by proxy:")
		for name, values := range r.Header {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", name, value)
			}
		}
	}

	targetURL := r.URL.Query().Get("url")

	if targetURL != "" {
		parsedURL, err := url.Parse(ensureURLHasScheme(targetURL))
		if err != nil || parsedURL.Host == "" {
			http.Error(w, "Invalid URL format", http.StatusBadRequest)
			return
		}

		hostname := parsedURL.Host
		allowedHosts := []string{"rest.opensubtitles.org", "dl.opensubtitles.org", "subdl.com", "dl.subdl.com", "subf2m.co"}
		isAllowed := false

		for _, allowed := range allowedHosts {
			if hostname == allowed || strings.HasSuffix(hostname, "."+allowed) {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			fmt.Printf("Rejected request to unauthorized hostname: %s\n", hostname)
			http.Error(w, "Access to this host is not allowed", http.StatusForbidden)
			return
		}
	}

	if Debug {
		fmt.Printf("Raw 'url' parameter (decoded): %#v\n", targetURL)
	}
	targetURL = strings.TrimSpace(targetURL)
	if Debug {
		fmt.Printf("Trimmed 'url' parameter: %#v\n", targetURL)
	}
	headersJSON := r.URL.Query().Get("headers")
	useNormalParam := r.URL.Query().Has("normal")

	if targetURL == "" {
		fmt.Fprintf(w, "i6.shark is working as expected (v%s). IP check skipped.", Version)
		return
	}

	targetURL = ensureURLHasScheme(targetURL)
	parsedURL, err := url.Parse(targetURL)
	if Debug {
		if err != nil {
			fmt.Printf("Error parsing trimmed & schemed URL '%s': %v\n", targetURL, err)
		} else {
			fmt.Printf("Successfully parsed trimmed & schemed URL: %s (Host: %s)\n", parsedURL.String(), parsedURL.Host)
		}
	}
	if err != nil || parsedURL.Host == "" {
		errMsg := fmt.Sprintf("Invalid URL (parsing failed or host empty): %s. Original error: %v", targetURL, err)
		if err == nil && parsedURL.Host == "" {
			errMsg = fmt.Sprintf("Invalid URL (empty host after parsing): %s", targetURL)
		}
		fmt.Printf("%s\n", errMsg)
		http.Error(w, fmt.Sprintf("Invalid URL: %s.", targetURL), http.StatusBadRequest)
		return
	}
	hostname := parsedURL.Host

	var sourceIP string
	var sourceNetIP net.IP
	useSpecificIP := true

	if useNormalParam {
		sourceIP = "System default (requested)"
		useSpecificIP = false
		fmt.Println("Using system default IP as requested by 'normal' parameter.")
	} else {
		var poolErr error
		sourceIP, poolErr = getNextIPFromPool()
		if poolErr != nil {
			if strings.Contains(poolErr.Error(), "pool busy") {
				if Debug {
					fmt.Printf("Pool busy, using system default IP for this request\n")
				}
			} else {
				fmt.Printf("Warning: IP Pool error, falling back to system default IP. Error: %v\n", poolErr)
			}
			sourceIP = "System default (fallback)"
			useSpecificIP = false
		} else {
			sourceNetIP = net.ParseIP(sourceIP)
			if sourceNetIP == nil {
				fmt.Printf("ERROR: Failed to parse IP from pool: %s. Falling back.\n", sourceIP)
				sourceIP = "System default (fallback)"
				useSpecificIP = false
			} else {
				if Debug {
					fmt.Printf("Using IP from pool: %s\n", sourceIP)
				}
			}
		}
	}

	forwardedHeaders := make(http.Header)
	// Copy headers from original client request, stripping unwanted ones
	for name, values := range r.Header {
		lowerName := strings.ToLower(name)

		// The http.Client will set the Host header correctly based on outRequest.URL.Host.
		// We should not blindly copy the Host header from the incoming client request.
		if lowerName == "host" {
			continue
		}

		// Strip headers defined in the headersToStripBeforeForwarding map
		if headersToStripBeforeForwarding[lowerName] {
			if Debug {
				fmt.Printf("Stripping incoming header before forwarding: %s: %v\n", name, values)
			}
			continue
		}
		forwardedHeaders[name] = values
	}

	// Apply custom headers from 'headers' query parameter if provided.
	// This happens AFTER stripping, so user-provided headers via query take precedence.
	if headersJSON != "" {
		var customHeaders map[string]string
		err := json.Unmarshal([]byte(headersJSON), &customHeaders)
		if err == nil {
			for name, value := range customHeaders {
				forwardedHeaders.Set(name, value) // Set (or overwrite) in the forwardedHeaders
			}
			if Debug {
				fmt.Printf("Applied custom headers from query: %v\n", customHeaders)
			}
		} else {
			fmt.Printf("Warning: Failed to parse 'headers' JSON query parameter: %v. Ignoring.\n", err)
		}
	}

	var client *http.Client

	if useSpecificIP {
		// Create a custom dialer with socket reuse options
		dialer := &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: sourceNetIP, Port: 0},
			Timeout:   RequestTimeout,
			KeepAlive: 30 * time.Second,
		}

		// Create transport with optimized settings for high concurrency
		specificTransport := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     false,            // Disable HTTP/2 to reduce connection complexity
			MaxIdleConns:          100,              // Increase idle connection pool
			MaxIdleConnsPerHost:   20,               // Increase per-host idle connections
			MaxConnsPerHost:       50,               // Limit concurrent connections per host
			IdleConnTimeout:       30 * time.Second, // Shorter idle timeout
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     false, // Keep connections alive for reuse
		}
		client = &http.Client{
			Transport: specificTransport,
			Timeout:   RequestTimeout,
		}
		fmt.Printf("Using specific transport/client with LocalAddr: %s\n", sourceIP)
	} else {
		client = defaultClient
		fmt.Printf("Using shared default client (Source IP: %s)\n", sourceIP)
	}

	outRequest, err := http.NewRequest(r.Method, targetURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" || r.Method == "PUT" {
		// We still need to read the incoming body to potentially send it.
		// Note: For very large uploads, this still reads into memory.
		// True streaming requires http.Request.GetBody, which is more complex.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error reading request body: %v", err), http.StatusInternalServerError)
			return
		}
		outRequest.Body = io.NopCloser(bytes.NewReader(body))
		outRequest.ContentLength = int64(len(body))
	} else {
		outRequest.Body = nil
	}

	outRequest.Header = forwardedHeaders // Use the processed forwardedHeaders

	if Debug {
		fmt.Println("Outgoing request headers being sent by proxy to target:")
		for name, values := range outRequest.Header {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", name, value)
			}
		}
	}

	fmt.Printf("Connecting to %s using source IP %s (via %s)...\n",
		targetURL, sourceIP,
		func() string {
			if useSpecificIP {
				return "specific dialer"
			} else if useNormalParam {
				return "default (requested)"
			} else {
				return "default (fallback)"
			}
		}())

	// Track IP usage for ongoing requests
	if useSpecificIP {
		defer func() {
			// Find the IP in the pool and decrement its usage count
			poolMutex.Lock()
			defer poolMutex.Unlock()

			normalizedIP := normalizeIPv6(sourceIP)
			for _, tracker := range ipPoolWithUsage {
				if normalizeIPv6(tracker.IP) == normalizedIP {
					atomic.AddInt32(&tracker.InUseCount, -1)
					if Debug {
						fmt.Printf("Decremented usage for IP %s (now in-use: %d)\n",
							normalizedIP, atomic.LoadInt32(&tracker.InUseCount))
					}
					break
				}
			}
		}()
	}

	resp, err := client.Do(outRequest)

	if err != nil {
		fmt.Printf("ERROR using source IP %s for %s: %v\n", sourceIP, targetURL, err)

		// If we get a bind error and we're using a specific IP, it might be due to port exhaustion
		// Try to add more IPs to the pool urgently
		if useSpecificIP && strings.Contains(err.Error(), "bind: cannot assign requested address") {
			select {
			case urgentAddChan <- struct{}{}:
				fmt.Printf("Signaled urgent IP pool expansion due to bind error\n")
			default:
				// Channel full, signal already sent
			}
		}

		if useSpecificIP {
			fmt.Println("Attempting to get interface addresses via netlink during error...")
			link, linkErr := netlink.LinkByName(Interface)
			if linkErr != nil {
				fmt.Printf("  Error getting link %s: %v\n", Interface, linkErr)
			} else {
				addrs, addrErr := netlink.AddrList(link, unix.AF_INET6)
				if addrErr != nil {
					fmt.Printf("  Error listing addresses for %s: %v\n", Interface, addrErr)
				} else {
					foundInNetlink := false
					fmt.Printf("  Current IPv6 addresses on %s at time of error:\n", Interface)
					for _, addr := range addrs {
						fmt.Printf("    - %s (Flags: %d)\n", addr.IPNet.String(), addr.Flags)
						if addr.IP.Equal(sourceNetIP) {
							foundInNetlink = true
						}
					}
					if !foundInNetlink {
						fmt.Printf("  WARNING: Failing source IP %s was NOT found in netlink AddrList at time of error!\n", sourceIP)
					}
				}
			}

			if opError, ok := err.(*net.OpError); ok {
				if sysErr, ok := opError.Err.(*os.SyscallError); ok && (sysErr.Err.Error() == "invalid argument" || sysErr.Err.Error() == "can't assign requested address" || strings.Contains(sysErr.Err.Error(), "no suitable address found")) {
					fmt.Printf("Network Error likely due to unusable source IP %s on interface %s.\n", sourceIP, Interface)

					poolMutex.Lock()
					for i, tracker := range ipPoolWithUsage {
						if tracker.IP == sourceIP {
							ipPoolWithUsage = append(ipPoolWithUsage[:i], ipPoolWithUsage[i+1:]...)
							fmt.Printf("Removed bad IP %s from the pool (was used %d times).\n",
								sourceIP, tracker.RequestCount)

							// Reset index if it's out of bounds
							if currentIPIndex >= len(ipPoolWithUsage) && len(ipPoolWithUsage) > 0 {
								currentIPIndex = 0
							}
							break
						}
					}
					poolMutex.Unlock()

					http.Error(w, fmt.Sprintf("Proxy Network Error using %s: %v", sourceIP, err), http.StatusBadGateway)
					return
				}
			}
		}

		if os.IsTimeout(err) || strings.Contains(err.Error(), "timeout") {
			http.Error(w, fmt.Sprintf("Request timed out connecting to %s using source IP %s.", hostname, sourceIP), http.StatusGatewayTimeout)
		} else if strings.Contains(err.Error(), "connection") {
			http.Error(w, fmt.Sprintf("Connection error to %s using source IP %s: %v.", hostname, sourceIP, err), http.StatusBadGateway)
		} else {
			http.Error(w, fmt.Sprintf("Error proxying request using source IP %s: %v.", sourceIP, err), http.StatusInternalServerError)
		}
		return
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		if !skipHeaders[strings.ToLower(name)] {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
	}

	var reader io.Reader = resp.Body
	contentEncoding := resp.Header.Get("Content-Encoding")

	if strings.Contains(contentEncoding, "br") {
		reader = brotli.NewReader(resp.Body)
		w.Header().Del("Content-Encoding")
		w.Header().Del("Content-Length")
		if Debug {
			fmt.Println("Decompressing Brotli response stream")
		}
	} else if strings.Contains(contentEncoding, "gzip") {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			fmt.Printf("ERROR: Failed to create gzip reader: %v. Attempting to stream raw body.\n", err)
		} else {
			reader = gzipReader
			defer gzipReader.Close()
			w.Header().Del("Content-Encoding")
			w.Header().Del("Content-Length")
			if Debug {
				fmt.Println("Decompressing Gzip response stream")
			}
		}
	}

	if Debug {
		fmt.Println("Response headers being sent to client:")
		for name, values := range w.Header() {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", name, value)
			}
		}
	}

	w.WriteHeader(resp.StatusCode)

	copiedBytes, err := io.Copy(w, reader)
	if err != nil {
		// Error copying response body (e.g., client closed connection)
		// Can't send HTTP error anymore as headers/status are already sent.
		fmt.Printf("Error streaming response body to client: %v\n", err)
	} else {
		if Debug {
			fmt.Printf("Successfully streamed %d bytes to client.\n", copiedBytes)
		}
	}
}

func getNextIPFromPool() (string, error) {
	// Use a very short timeout to avoid blocking requests
	if !poolMutex.TryLock() {
		// If we can't get the lock immediately, return an error to use default IP
		return "", errors.New("pool busy, using default IP")
	}
	defer poolMutex.Unlock()

	if len(ipPoolWithUsage) == 0 {
		return "", errors.New("IP pool is empty")
	}

	// First, try to find an IP that hasn't exceeded request limit AND is not currently in use
	startIndex := currentIPIndex
	for attempts := 0; attempts < len(ipPoolWithUsage); attempts++ {
		tracker := ipPoolWithUsage[currentIPIndex]

		// Check if this IP can still be used (hasn't exceeded MaxRequestsPerIP AND not currently in use)
		if tracker.RequestCount < MaxRequestsPerIP {
			// Try to atomically claim this IP (only succeed if InUseCount was 0)
			if atomic.CompareAndSwapInt32(&tracker.InUseCount, 0, 1) {
				// Successfully claimed the IP - update tracking under mutex protection
				tracker.RequestCount++
				tracker.LastUsed = time.Now()

				ip := normalizeIPv6(tracker.IP)

				// Move to next IP for round-robin distribution
				currentIPIndex = (currentIPIndex + 1) % len(ipPoolWithUsage)

				if Debug {
					fmt.Printf("Selected fresh IP %s (usage: %d/%d, in-use: %d, last used: %s)\n",
						ip, tracker.RequestCount, MaxRequestsPerIP, atomic.LoadInt32(&tracker.InUseCount), tracker.LastUsed.Format("15:04:05"))
				}

				return ip, nil
			}
		}

		// This IP has reached its limit or is in use, try the next one
		currentIPIndex = (currentIPIndex + 1) % len(ipPoolWithUsage)

		if currentIPIndex == startIndex {
			break
		}
	}

	// If no fresh IPs are available, try to find an exhausted IP that's not currently in use
	for attempts := 0; attempts < len(ipPoolWithUsage); attempts++ {
		tracker := ipPoolWithUsage[currentIPIndex]

		// Try to atomically claim this exhausted IP (only succeed if InUseCount was 0)
		if atomic.CompareAndSwapInt32(&tracker.InUseCount, 0, 1) {
			// Successfully claimed the exhausted IP - update tracking under mutex protection
			tracker.RequestCount++
			tracker.LastUsed = time.Now()

			ip := normalizeIPv6(tracker.IP)

			// Move to next IP for round-robin distribution
			currentIPIndex = (currentIPIndex + 1) % len(ipPoolWithUsage)

			if Debug {
				fmt.Printf("WARNING: Using exhausted IP %s (usage: %d/%d, in-use: %d) - all fresh IPs exhausted\n",
					ip, tracker.RequestCount, MaxRequestsPerIP, atomic.LoadInt32(&tracker.InUseCount))
			}

			return ip, nil
		}

		currentIPIndex = (currentIPIndex + 1) % len(ipPoolWithUsage)
	}

	// If ALL IPs are currently in use, we have no choice but to return an error
	// This prevents the "bind: cannot assign requested address" errors
	return "", errors.New("all IPs currently in use - try again")
}

func manageIPPool() {
	fmt.Println("Starting enhanced IP pool manager with usage tracking...")
	ticker := time.NewTicker(PoolManageInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Regular pool management
		case <-urgentAddChan:
			// Urgent IP addition requested due to bind errors
			fmt.Println("Processing urgent IP addition request...")
		}
		// Quick snapshot of pool state without holding lock for long
		var currentSize, availableIPs, exhaustedIPs int
		var needsUrgentAddition bool

		func() {
			poolMutex.Lock()
			defer poolMutex.Unlock()
			currentSize = len(ipPoolWithUsage)

			for _, tracker := range ipPoolWithUsage {
				if tracker.RequestCount < MaxRequestsPerIP {
					availableIPs++
				} else {
					exhaustedIPs++
				}
			}

			// Define minimum fresh IPs required for service continuity
			minFreshIPsRequired := minInt(10, DesiredPoolSize/10)
			needsUrgentAddition = exhaustedIPs > 0 && availableIPs < minFreshIPsRequired

			// Don't remove exhausted IPs here - they'll be removed when new batch is ready
			// This ensures we always have IPs available for requests
			if Debug && exhaustedIPs > 0 {
				fmt.Printf("Keeping %d exhausted IPs until new batch is ready (available: %d)\n",
					exhaustedIPs, availableIPs)
			}
		}()

		// Old IP removal is now handled when new batches are ready

		// Determine how many IPs to add
		needToAdd := currentSize < DesiredPoolSize
		batchTarget := minInt(PoolAddBatchSize, DesiredPoolSize-currentSize)

		if needsUrgentAddition {
			minFreshIPsRequired := minInt(10, DesiredPoolSize/10)
			urgentAddCount := minInt(PoolAddBatchSize*2, minFreshIPsRequired-availableIPs+5)
			batchTarget = minInt(urgentAddCount, DesiredPoolSize-currentSize)
			needToAdd = batchTarget > 0
			if Debug {
				fmt.Printf("Urgent IP addition: need %d more IPs (exhausted: %d, available: %d)\n",
					batchTarget, exhaustedIPs, availableIPs)
			}
		}

		// Add new IPs if needed (outside lock)
		if needToAdd && batchTarget > 0 {
			go func(target int) {
				// Add timeout for the entire batch operation
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				var wg sync.WaitGroup
				newTrackers := make(chan *IPUsageTracker, target)

				// Use a semaphore to limit concurrent IP additions
				sem := make(chan struct{}, 3) // Max 3 concurrent IP additions

				for i := 0; i < target; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()

						// Acquire semaphore
						select {
						case sem <- struct{}{}:
							defer func() { <-sem }()
						case <-ctx.Done():
							return // Context cancelled
						}

						newIP := randomIPv6()

						// Add IP with context timeout
						success := make(chan bool, 1)
						go func() {
							success <- addIPv6ToInterface(newIP)
						}()

						select {
						case ok := <-success:
							if ok {
								tracker := &IPUsageTracker{
									IP:           normalizeIPv6(newIP),
									RequestCount: 0,
									LastUsed:     time.Time{}, // Zero time indicates never used
									Added:        time.Now(),
								}
								select {
								case newTrackers <- tracker:
								case <-ctx.Done():
									return
								default:
									// Channel full, skip this tracker
								}
							}
						case <-ctx.Done():
							return // Context timeout
						}
					}()
				}

				go func() {
					wg.Wait()
					close(newTrackers)
				}()

				addedTrackers := make([]*IPUsageTracker, 0, target)

				// Collect results with timeout
				done := make(chan struct{})
				go func() {
					defer close(done)
					for tracker := range newTrackers {
						addedTrackers = append(addedTrackers, tracker)
					}
				}()

				select {
				case <-done:
					// Collection completed normally
				case <-time.After(15 * time.Second):
					// Timeout collecting results
					fmt.Printf("Timeout collecting new IP trackers, proceeding with %d collected\n", len(addedTrackers))
				}

				if len(addedTrackers) > 0 {
					var oldIPsToFlush []string

					func() {
						poolMutex.Lock()
						defer poolMutex.Unlock()

						newPool := make([]*IPUsageTracker, 0, len(ipPoolWithUsage)+len(addedTrackers))
						expectedPrefix := IPv6Prefix + ":" + IPv6Subnet + ":"

						// Keep only fresh IPs from the correct subnet and add new ones
						for _, tracker := range ipPoolWithUsage {
							inUseCount := atomic.LoadInt32(&tracker.InUseCount)

							// Remove IPs that don't match current subnet configuration
							if !strings.HasPrefix(tracker.IP, expectedPrefix) {
								if inUseCount == 0 {
									oldIPsToFlush = append(oldIPsToFlush, tracker.IP)
									if Debug {
										fmt.Printf("Flushing IP from wrong subnet %s - expected prefix %s\n",
											tracker.IP, expectedPrefix)
									}
								} else {
									// Keep IP temporarily since it's in use
									newPool = append(newPool, tracker)
									if Debug {
										fmt.Printf("Keeping wrong subnet IP %s temporarily (%d ongoing requests)\n",
											tracker.IP, inUseCount)
									}
								}
							} else if tracker.RequestCount >= MaxRequestsPerIP {
								if inUseCount == 0 {
									oldIPsToFlush = append(oldIPsToFlush, tracker.IP)
									if Debug {
										fmt.Printf("Flushing old exhausted IP %s (used %d times) - new batch ready\n",
											tracker.IP, tracker.RequestCount)
									}
								} else {
									newPool = append(newPool, tracker)
									if Debug {
										fmt.Printf("Keeping exhausted IP %s temporarily (%d ongoing requests)\n",
											tracker.IP, inUseCount)
									}
								}
							} else {
								newPool = append(newPool, tracker)
							}
						}

						// Add new trackers
						newPool = append(newPool, addedTrackers...)
						ipPoolWithUsage = newPool

						// Reset index if needed
						if currentIPIndex >= len(ipPoolWithUsage) && len(ipPoolWithUsage) > 0 {
							currentIPIndex = 0
						}
					}()

					// Remove old IPs from interface (outside lock)
					if len(oldIPsToFlush) > 0 {
						go func(toFlush []string) {
							var wg sync.WaitGroup
							for _, oldIP := range toFlush {
								wg.Add(1)
								go func(ip string) {
									defer wg.Done()
									removeIPv6FromInterface(ip)
								}(oldIP)
							}
							wg.Wait()
							fmt.Printf("Flushed %d old IPs when new batch of %d became ready\n",
								len(toFlush), len(addedTrackers))
						}(oldIPsToFlush)
					}

					fmt.Printf("Added %d new IPs to pool, flushed %d old IPs. Pool size now: %d\n",
						len(addedTrackers), len(oldIPsToFlush), currentSize+len(addedTrackers)-len(oldIPsToFlush))
				}
			}(batchTarget)
		}

		// Quick stats logging (minimal lock time)
		if Debug {
			func() {
				poolMutex.Lock()
				defer poolMutex.Unlock()

				totalIPs := len(ipPoolWithUsage)
				freshIPs := 0
				for _, tracker := range ipPoolWithUsage {
					if tracker.RequestCount < MaxRequestsPerIP {
						freshIPs++
					}
				}

				if totalIPs > 0 {
					exhaustedCount := totalIPs - freshIPs
					status := "normal"
					if exhaustedCount > 0 && freshIPs < minInt(10, DesiredPoolSize/10) {
						status = "using exhausted IPs"
					}
					fmt.Printf("Pool stats: %d total IPs, %d fresh, %d exhausted (%s)\n",
						totalIPs, freshIPs, exhaustedCount, status)
				}
			}()
		}
	} // End of select loop
}

func checkPrivileges() bool {
	if os.Geteuid() != 0 && ListenPort < 1024 {
		fmt.Println("ERROR: This program requires root privileges to bind to port 80 and add IPv6 addresses. Run with sudo or change ListenPort to a value above 1024.")
		return false
	}
	return true
}

func onStartup() bool {
	if !checkPrivileges() {
		return false
	}

	if !checkInterface() {
		fmt.Println("WARNING: Interface check failed, but continuing...")
	}

	fmt.Println("Clearing all existing IPv6 addresses on startup...")

	// Add a small delay to ensure interface is ready
	time.Sleep(100 * time.Millisecond)

	// Flush in a separate goroutine to avoid blocking startup if there are issues
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("Recovered from panic during startup flush: %v\n", r)
			}
		}()
		flushAllIPAddresses()
	}()

	// Wait a moment for flush to start
	time.Sleep(500 * time.Millisecond)

	testIP := randomIPv6()
	if !addIPv6ToInterface(testIP) {
		fmt.Println("WARNING: Failed to add IPv6 address for testing. Some features may not work.")
	}

	fmt.Println("Startup checks completed")
	return true
}

func main() {
	// Initialize enhanced IP pool with usage tracking
	ipPoolWithUsage = make([]*IPUsageTracker, 0, DesiredPoolSize)
	currentIPIndex = 0

	defaultTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   RequestTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	defaultClient = &http.Client{
		Transport: defaultTransport,
		Timeout:   RequestTimeout,
	}

	if !onStartup() {
		os.Exit(1)
	}

	// Start background processes with delays to prevent startup congestion
	go func() {
		time.Sleep(2 * time.Second) // Wait for server to be ready
		cleanupWrongSubnetIPs()
		normalizeIPPool()
		manageIPPool()
	}()

	go func() {
		time.Sleep(5 * time.Second) // Start periodic flush later
		periodicIPFlush()
	}()

	go func() {
		time.Sleep(3 * time.Second) // Start unused IP flush
		periodicUnusedIPFlush()
	}()

	http.HandleFunc("/", handleRequest)

	listenAddr := fmt.Sprintf("%s:%d", ListenHost, ListenPort)
	fmt.Printf("Starting i6.shark server on %s\n", listenAddr)
	err := http.ListenAndServe(listenAddr, nil)
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
