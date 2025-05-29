package main

import (
	"bytes"
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
	"time"

	"compress/gzip" // <-- ADD THIS LINE if it's missing

	"github.com/andybalholm/brotli"
	"github.com/vishvananda/netlink"
)

const (
	SharedSecret       = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // Secret between client & server
	Version            = "2.2"                              // Version of the script
	IPv6Prefix         = "xxxx:xxxx:xxxx"                   // Your /48 prefix
	IPv6Subnet         = "6000"                             // Using subnet 1000 within your /48
	Interface          = "xxxx"                             // Detected interface from your system
	ListenPort         = 80                                 // Proxy server port
	ListenHost         = "0.0.0.0"                          // Listen on all interfaces
	RequestTimeout     = 30 * time.Second                   // Request timeout in seconds
	Debug              = false                              // Enable debug output
	DesiredPoolSize    = 6000                               // Target number of IPs in the pool (Reduced for testing)
	PoolManageInterval = 5 * time.Second                    // Check/add less frequently (every 5 seconds)
	PoolAddBatchSize   = 15                                 // Try to add up to 5 IPs per cycle if needed
)

var requestCount int
var defaultClient *http.Client
var defaultTransport *http.Transport

var (
	ipPool         []string
	poolMutex      sync.Mutex
	currentIPIndex int
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

func randomIPv6() string {
	hostPart1 := rand.Uint32()
	hostPart2 := rand.Uint32()

	return fmt.Sprintf("%s:%s:%04x:%04x:%04x:%04x",
		IPv6Prefix,
		IPv6Subnet,
		(hostPart1>>16)&0xFFFF,
		hostPart1&0xFFFF,
		(hostPart2>>16)&0xFFFF,
		hostPart2&0xFFFF)
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
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		fmt.Printf("addIPv6: Failed to find link %s: %v\n", Interface, err)
		return false
	}

	addr, err := netlink.ParseAddr(ipv6 + "/128")
	if err != nil {
		fmt.Printf("addIPv6: Failed to parse address %s/128: %v\n", ipv6, err)
		return false
	}

	err = netlink.AddrAdd(link, addr)
	if err != nil {
		if err.Error() == "file exists" {
			if Debug {
				fmt.Printf("addIPv6: Address %s already exists on %s (ignored).\n", ipv6, Interface)
			}
			return true
		} else {
			fmt.Printf("addIPv6: Failed to add address %s to %s: %v\n", ipv6, Interface, err)
			return false
		}
	}

	if Debug {
		fmt.Printf("addIPv6: Successfully added %s to %s via netlink.\n", ipv6, Interface)
	}
	return true
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

	err = netlink.AddrDel(link, addr)
	if err != nil {
		fmt.Printf("removeIPv6: error removing address %s from %s: %v\n", ipv6, Interface, err)
		return false
	}

	if Debug {
		fmt.Printf("removeIPv6: Successfully removed %s from %s via netlink.\n", ipv6, Interface)
	}
	return true
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
		allowedHosts := []string{"rest.opensubtitles.org", "dl.opensubtitles.org", "subdl.com"}
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
			fmt.Printf("Warning: IP Pool empty or error, falling back to system default IP. Error: %v\n", poolErr)
			sourceIP = "System default (fallback)"
			useSpecificIP = false
		} else {
			sourceNetIP = net.ParseIP(sourceIP)
			if sourceNetIP == nil {
				fmt.Printf("ERROR: Failed to parse IP from pool: %s. Falling back.\n", sourceIP)
				sourceIP = "System default (fallback)"
				useSpecificIP = false
			} else {
				fmt.Printf("Using IP from pool: %s\n", sourceIP)
			}
		}
	}

	// Prepare headers for the outgoing request
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
		// If not stripped, copy the header and its values
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
		specificTransport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{IP: sourceNetIP, Port: 0},
				Timeout:   RequestTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			MaxIdleConnsPerHost:   5,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
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
	resp, err := client.Do(outRequest)

	if err != nil {
		fmt.Printf("ERROR using source IP %s for %s: %v\n", sourceIP, targetURL, err)

		if useSpecificIP {
			fmt.Println("Attempting to get interface addresses via netlink during error...")
			link, linkErr := netlink.LinkByName(Interface)
			if linkErr != nil {
				fmt.Printf("  Error getting link %s: %v\n", Interface, linkErr)
			} else {
				addrs, addrErr := netlink.AddrList(link, netlink.FAMILY_V6)
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
					for i, ip := range ipPool {
						if ip == sourceIP {
							ipPool = append(ipPool[:i], ipPool[i+1:]...)
							fmt.Printf("Removed bad IP %s from the pool.\n", sourceIP)
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
	poolMutex.Lock()
	defer poolMutex.Unlock()

	if len(ipPool) == 0 {
		return "", errors.New("IP pool is empty")
	}

	for i := 0; i < len(ipPool); i++ {
		index := currentIPIndex
		currentIPIndex = (currentIPIndex + 1) % len(ipPool)

		if net.ParseIP(ipPool[index]) != nil {
			return ipPool[index], nil
		}

		fmt.Printf("Invalid IP found in pool: %s. Skipping...\n", ipPool[index])
	}

	return "", errors.New("no valid IPs in pool")
}

func manageIPPool() {
	fmt.Println("Starting IP pool manager...")
	ticker := time.NewTicker(PoolManageInterval)
	defer ticker.Stop()

	for range ticker.C {
		poolMutex.Lock()
		currentSize := len(ipPool)
		needToAdd := currentSize < DesiredPoolSize
		batchTarget := minInt(PoolAddBatchSize, DesiredPoolSize-currentSize)
		shouldReplace := currentSize >= DesiredPoolSize
		var ipsToRemove []string

		if shouldReplace {
			numToRemove := 1
			if numToRemove > currentSize {
				numToRemove = currentSize
			}

			ipsToRemove = make([]string, numToRemove)
			copy(ipsToRemove, ipPool[:numToRemove])
			ipPool = ipPool[numToRemove:]
			currentSize -= numToRemove

			if currentIPIndex >= currentSize && currentSize > 0 {
				currentIPIndex = 0
			}
		}
		poolMutex.Unlock()

		if len(ipsToRemove) > 0 {
			var wg sync.WaitGroup
			for _, oldestIP := range ipsToRemove {
				if oldestIP != "" {
					wg.Add(1)
					go func(ip string) {
						defer wg.Done()
						removeIPv6FromInterface(ip)
					}(oldestIP)
				}
			}
			wg.Wait()
		}

		if needToAdd && batchTarget > 0 {
			var wg sync.WaitGroup
			newIPs := make(chan string, batchTarget)

			for i := 0; i < batchTarget; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					newIP := randomIPv6()
					if addIPv6ToInterface(newIP) {
						newIPs <- newIP
					}
				}()
			}

			go func() {
				wg.Wait()
				close(newIPs)
			}()

			addedIPs := make([]string, 0, batchTarget)
			for ip := range newIPs {
				addedIPs = append(addedIPs, ip)
			}

			if len(addedIPs) > 0 {
				poolMutex.Lock()
				ipPool = append(ipPool, addedIPs...)
				fmt.Printf("Added %d IPs to pool. Pool size now: %d\n", len(addedIPs), len(ipPool))
				poolMutex.Unlock()
			}
		}
	}
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

	checkInterface()
	testIP := randomIPv6()
	if !addIPv6ToInterface(testIP) {
		fmt.Println("WARNING: Failed to add IPv6 address for testing. Some features may not work.")
	}

	fmt.Println("Startup checks completed")
	return true
}

func main() {
	ipPool = make([]string, 0, DesiredPoolSize)
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

	go manageIPPool()
	http.HandleFunc("/", handleRequest)

	listenAddr := fmt.Sprintf("%s:%d", ListenHost, ListenPort)
	fmt.Printf("Starting i6.shark server on %s\n", listenAddr)
	err := http.ListenAndServe(listenAddr, nil)
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
