package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
)

// netlink uses syscall.AF_INET6 internally, we use the constant directly
const FAMILY_V6 = 10 // AF_INET6

const (
	SharedSecret          = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // Secret between client & server
	Version               = "3.0"                              // Version of the script
	IPv6Prefix            = "xxxx:xxxx:xxxx"                   // Your /48 prefix
	IPv6Subnet            = "6000"                             // Using subnet 1000 within your /48
	Interface             = "ens3"                             // Detected interface from your system
	ListenPort            = 80                                 // Proxy server port
	ListenHost            = "0.0.0.0"                          // Listen on all interfaces
	RequestTimeout        = 30 * time.Second                   // Request timeout in seconds
	Debug                 = false                              // Enable debug output
	DesiredPoolSize       = 250                                // Target number of IPs in the pool
	PoolManageInterval    = 500 * time.Millisecond             // Check pool frequently
	PoolAddBatchSize      = 25                                 // Larger batches for faster pool growth
	IPFlushInterval       = 1 * time.Hour                      // Flush all IPs every hour
	MaxRequestsPerIP      = 100                                // Maximum requests allowed per IP before rotation
	UnusedIPFlushInterval = 10 * time.Minute                   // Check for unused IPs every 10 minutes
	IPInactivityThreshold = 30 * time.Minute                   // Remove IP if unused for this duration
	MaxConcurrentPerIP    = 15                                 // Maximum concurrent requests per IP
)

// IPUsageTracker tracks usage statistics for each IP address
type IPUsageTracker struct {
	IP           string          // The IPv6 address
	requestCount atomic.Int32    // Number of requests made with this IP
	lastUsed     atomic.Int64    // Last time this IP was used (Unix nano)
	Added        time.Time       // When this IP was added to the pool
	inUseCount   atomic.Int32    // Number of ongoing requests using this IP
	transport    *http.Transport // Cached transport for this IP - CRITICAL for performance
	client       *http.Client    // Cached client for this IP
}

func (t *IPUsageTracker) GetRequestCount() int32 { return t.requestCount.Load() }
func (t *IPUsageTracker) GetInUseCount() int32   { return t.inUseCount.Load() }
func (t *IPUsageTracker) GetLastUsed() time.Time { return time.Unix(0, t.lastUsed.Load()) }
func (t *IPUsageTracker) IncrementRequestCount() { t.requestCount.Add(1) }
func (t *IPUsageTracker) UpdateLastUsed()        { t.lastUsed.Store(time.Now().UnixNano()) }
func (t *IPUsageTracker) AcquireUse() bool       { return t.inUseCount.Add(1) <= MaxConcurrentPerIP }
func (t *IPUsageTracker) ReleaseUse()            { t.inUseCount.Add(-1) }

var (
	requestCount   atomic.Int64
	defaultClient  *http.Client
	ipPool         atomic.Pointer[[]*IPUsageTracker] // Lock-free pool access for reads
	poolWriteMutex sync.Mutex                        // Only used for pool modifications
	currentIndex   atomic.Uint32                     // Lock-free round-robin index
	urgentAddChan  = make(chan struct{}, 10)
)

var skipHeaders = map[string]bool{
	"transfer-encoding": true,
	"connection":        true,
	"keep-alive":        true,
	"server":            true,
}

// bufferPool is used to reduce allocations when copying response bodies
var bufferPool = sync.Pool{New: func() interface{} {
	b := make([]byte, 64*1024) // 64KB buffer for better throughput
	return &b
}}

var headersToStripBeforeForwarding = map[string]bool{
	"cf-connecting-ip":  true,
	"cf-ipcountry":      true,
	"cf-ray":            true,
	"cf-visitor":        true,
	"cf-worker":         true,
	"cf-ew-via":         true,
	"x-forwarded-for":   true,
	"x-forwarded-proto": true,
	"cdn-loop":          true,
	"true-client-ip":    true,
	"x-real-ip":         true,
}

// createTransportForIP creates a transport for a specific source IP
func createTransportForIP(sourceIP net.IP) *http.Transport {
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: sourceIP, Port: 0},
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,            // HTTP/1.1 is faster for proxying
		MaxIdleConns:          100,              // Pool connections
		MaxIdleConnsPerHost:   10,               // Per-host pool
		MaxConnsPerHost:       0,                // No limit per host
		IdleConnTimeout:       90 * time.Second, // Keep connections alive
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: RequestTimeout,
		DisableKeepAlives:     false,
		DisableCompression:    true, // Let target handle compression
	}
}

// createIPTracker creates a new IP tracker with cached transport
func createIPTracker(ip string) *IPUsageTracker {
	parsedIP := net.ParseIP(ip)
	transport := createTransportForIP(parsedIP)
	tracker := &IPUsageTracker{
		IP:        ip,
		Added:     time.Now(),
		transport: transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   RequestTimeout,
		},
	}
	return tracker
}

func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func normalizeIPv6(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	return ip.String()
}

func randomIPv6() string {
	hostPart1 := rand.Uint32()
	hostPart2 := rand.Uint32()

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
		return false
	}
	if (link.Attrs().Flags & net.FlagUp) == 0 {
		return false
	}
	return true
}

func addIPv6ToInterface(ipv6 string) bool {
	done := make(chan bool, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- false
			}
		}()

		link, err := netlink.LinkByName(Interface)
		if err != nil {
			done <- false
			return
		}

		addr, err := netlink.ParseAddr(ipv6 + "/128")
		if err != nil {
			done <- false
			return
		}

		err = netlink.AddrAdd(link, addr)
		if err != nil {
			if err.Error() == "file exists" {
				done <- true
				return
			}
			done <- false
			return
		}
		done <- true
	}()

	select {
	case result := <-done:
		return result
	case <-time.After(2 * time.Second):
		return false
	}
}

func removeIPv6FromInterface(ipv6 string) bool {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		return false
	}

	addr, err := netlink.ParseAddr(ipv6 + "/128")
	if err != nil {
		return false
	}

	for attempt := 0; attempt < 3; attempt++ {
		err = netlink.AddrDel(link, addr)
		if err == nil {
			return true
		}
		if strings.Contains(err.Error(), "cannot assign requested address") ||
			strings.Contains(err.Error(), "no such file or directory") {
			return true
		}
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	return false
}

func flushAllIPAddresses() {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		return
	}

	addrs, err := netlink.AddrList(link, FAMILY_V6)
	if err != nil {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // Limit concurrent operations

	for _, addr := range addrs {
		ipStr := addr.IP.String()
		if strings.HasPrefix(ipStr, IPv6Prefix+":") && !strings.Contains(ipStr, "::") {
			wg.Add(1)
			go func(address netlink.Addr) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				netlink.AddrDel(link, &address)
			}(addr)
		}
	}

	wg.Wait()

	// Clear the IP pool
	poolWriteMutex.Lock()
	newPool := make([]*IPUsageTracker, 0, DesiredPoolSize)
	ipPool.Store(&newPool)
	currentIndex.Store(0)
	poolWriteMutex.Unlock()
}

func periodicIPFlush() {
	ticker := time.NewTicker(IPFlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		flushAllIPAddresses()
	}
}

func flushUnusedIPs() {
	poolWriteMutex.Lock()
	defer poolWriteMutex.Unlock()

	pool := ipPool.Load()
	if pool == nil || len(*pool) == 0 {
		return
	}

	now := time.Now()
	var ipsToRemove []string
	newPool := make([]*IPUsageTracker, 0, len(*pool))

	for _, tracker := range *pool {
		if tracker.GetInUseCount() > 0 {
			newPool = append(newPool, tracker)
			continue
		}

		lastUsed := tracker.GetLastUsed()
		var inactiveTime time.Duration
		if lastUsed.IsZero() || lastUsed.Unix() == 0 {
			inactiveTime = now.Sub(tracker.Added)
		} else {
			inactiveTime = now.Sub(lastUsed)
		}

		if inactiveTime > IPInactivityThreshold && tracker.GetRequestCount() < MaxRequestsPerIP {
			ipsToRemove = append(ipsToRemove, tracker.IP)
			// Close transport to release resources
			tracker.transport.CloseIdleConnections()
		} else {
			newPool = append(newPool, tracker)
		}
	}

	ipPool.Store(&newPool)

	// Remove from interface in background
	if len(ipsToRemove) > 0 {
		go func(toRemove []string) {
			for _, ip := range toRemove {
				removeIPv6FromInterface(ip)
			}
		}(ipsToRemove)
	}
}

func periodicUnusedIPFlush() {
	ticker := time.NewTicker(UnusedIPFlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		flushUnusedIPs()
	}
}

func cleanupWrongSubnetIPs() {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		return
	}

	addrs, err := netlink.AddrList(link, FAMILY_V6)
	if err != nil {
		return
	}

	expectedPrefix := IPv6Prefix + ":" + IPv6Subnet + ":"
	var wg sync.WaitGroup

	for _, addr := range addrs {
		ipStr := addr.IP.String()
		if strings.HasPrefix(ipStr, IPv6Prefix+":") && !strings.Contains(ipStr, "::") {
			if !strings.HasPrefix(ipStr, expectedPrefix) {
				wg.Add(1)
				go func(address netlink.Addr) {
					defer wg.Done()
					netlink.AddrDel(link, &address)
				}(addr)
			}
		}
	}

	wg.Wait()
}

func ensureURLHasScheme(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return "https://" + urlStr
	}
	return urlStr
}

func logRequest(r *http.Request) {
	count := requestCount.Add(1)
	if Debug {
		fmt.Printf("\nIncoming request #%d\n", count)
	}
}

func validateAPIToken(apiToken string, userAgent string) bool {
	key := []byte(userAgent)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(SharedSecret))
	expectedHash := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(apiToken), []byte(expectedHash))
}

// getNextIPFromPool returns an IP tracker using lock-free access
func getNextIPFromPool() (*IPUsageTracker, error) {
	pool := ipPool.Load()
	if pool == nil || len(*pool) == 0 {
		return nil, fmt.Errorf("IP pool is empty")
	}

	poolLen := uint32(len(*pool))
	startIdx := currentIndex.Add(1) % poolLen

	// Fast path: find an available IP with atomic operations only
	for attempts := uint32(0); attempts < poolLen*2; attempts++ {
		idx := (startIdx + attempts) % poolLen
		tracker := (*pool)[idx]

		// Check if IP can handle more requests
		if tracker.GetRequestCount() >= MaxRequestsPerIP {
			continue
		}

		// Try to acquire usage slot
		if !tracker.AcquireUse() {
			// Too many concurrent users, release and try next
			tracker.ReleaseUse()
			continue
		}

		// Successfully acquired
		tracker.IncrementRequestCount()
		tracker.UpdateLastUsed()

		if Debug {
			fmt.Printf("Using IP %s (usage: %d, concurrent: %d)\n",
				tracker.IP, tracker.GetRequestCount(), tracker.GetInUseCount())
		}

		return tracker, nil
	}

	// All IPs exhausted or busy - try any available IP
	for attempts := uint32(0); attempts < poolLen; attempts++ {
		idx := (startIdx + attempts) % poolLen
		tracker := (*pool)[idx]

		if tracker.AcquireUse() {
			tracker.IncrementRequestCount()
			tracker.UpdateLastUsed()
			return tracker, nil
		}
	}

	return nil, fmt.Errorf("all IPs busy")
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	apiToken := r.Header.Get("API-Token")
	userAgent := r.Header.Get("User-Agent")

	if !validateAPIToken(apiToken, userAgent) {
		http.Error(w, "Unauthorized: i6.shark detected invalid API-Token header.", http.StatusUnauthorized)
		return
	}

	logRequest(r)

	targetURL := strings.TrimSpace(r.URL.Query().Get("url"))
	headersJSON := r.URL.Query().Get("headers")
	useNormalParam := r.URL.Query().Has("normal")

	if targetURL == "" {
		fmt.Fprintf(w, "i6.shark is working as expected (v%s).", Version)
		return
	}

	targetURL = ensureURLHasScheme(targetURL)
	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Host == "" {
		http.Error(w, fmt.Sprintf("Invalid URL: %s.", targetURL), http.StatusBadRequest)
		return
	}

	var tracker *IPUsageTracker
	var client *http.Client

	if useNormalParam {
		client = defaultClient
		if Debug {
			fmt.Println("Using system default IP as requested")
		}
	} else {
		var poolErr error
		tracker, poolErr = getNextIPFromPool()
		if poolErr != nil {
			client = defaultClient
			if Debug {
				fmt.Printf("Pool error, using default: %v\n", poolErr)
			}
		} else {
			client = tracker.client // Use cached client with pre-configured transport
			defer tracker.ReleaseUse()
		}
	}

	// Build forwarded headers efficiently
	forwardedHeaders := make(http.Header, len(r.Header))
	for name, values := range r.Header {
		lowerName := strings.ToLower(name)
		if lowerName == "host" || headersToStripBeforeForwarding[lowerName] {
			continue
		}
		forwardedHeaders[name] = values
	}

	// Apply custom headers
	if headersJSON != "" {
		var customHeaders map[string]string
		if json.Unmarshal([]byte(headersJSON), &customHeaders) == nil {
			for name, value := range customHeaders {
				forwardedHeaders.Set(name, value)
			}
		}
	}

	outRequest, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
		return
	}

	// Stream request body directly
	if r.Body != nil && r.Body != http.NoBody && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
		outRequest.Body = r.Body
		outRequest.ContentLength = r.ContentLength
	} else {
		outRequest.Body = http.NoBody
		outRequest.ContentLength = 0
	}

	outRequest.Header = forwardedHeaders

	resp, err := client.Do(outRequest)
	if err != nil {
		if os.IsTimeout(err) || strings.Contains(err.Error(), "timeout") {
			http.Error(w, fmt.Sprintf("Request timed out connecting to %s.", parsedURL.Host), http.StatusGatewayTimeout)
		} else if strings.Contains(err.Error(), "connection") {
			http.Error(w, fmt.Sprintf("Connection error to %s: %v.", parsedURL.Host, err), http.StatusBadGateway)
		} else {
			http.Error(w, fmt.Sprintf("Error proxying request: %v.", err), http.StatusInternalServerError)
		}

		// Signal for more IPs if bind error
		if strings.Contains(err.Error(), "bind: cannot assign requested address") {
			select {
			case urgentAddChan <- struct{}{}:
			default:
			}
		}
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for name, values := range resp.Header {
		if !skipHeaders[strings.ToLower(name)] {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Use pooled buffer for efficient streaming
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	io.CopyBuffer(w, resp.Body, *bufPtr)
}

func manageIPPool() {
	ticker := time.NewTicker(PoolManageInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-urgentAddChan:
		}

		pool := ipPool.Load()
		currentSize := 0
		availableIPs := 0
		if pool != nil {
			currentSize = len(*pool)
			for _, t := range *pool {
				if t.GetRequestCount() < MaxRequestsPerIP && t.GetInUseCount() < MaxConcurrentPerIP {
					availableIPs++
				}
			}
		}

		// Determine how many IPs to add
		needToAdd := currentSize < DesiredPoolSize || availableIPs < DesiredPoolSize/4
		batchTarget := minInt(PoolAddBatchSize, DesiredPoolSize-currentSize)
		if availableIPs < 20 {
			batchTarget = minInt(PoolAddBatchSize*2, DesiredPoolSize-currentSize+20)
		}

		if needToAdd && batchTarget > 0 {
			go func(target int) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()

				var wg sync.WaitGroup
				newTrackers := make(chan *IPUsageTracker, target)
				sem := make(chan struct{}, 5) // Limit concurrent IP additions

				for i := 0; i < target; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()

						select {
						case sem <- struct{}{}:
							defer func() { <-sem }()
						case <-ctx.Done():
							return
						}

						newIP := randomIPv6()
						if addIPv6ToInterface(newIP) {
							tracker := createIPTracker(normalizeIPv6(newIP))
							select {
							case newTrackers <- tracker:
							case <-ctx.Done():
							default:
							}
						}
					}()
				}

				go func() {
					wg.Wait()
					close(newTrackers)
				}()

				addedTrackers := make([]*IPUsageTracker, 0, target)
				for tracker := range newTrackers {
					addedTrackers = append(addedTrackers, tracker)
				}

				if len(addedTrackers) > 0 {
					poolWriteMutex.Lock()

					currentPool := ipPool.Load()
					var newPool []*IPUsageTracker
					if currentPool != nil {
						newPool = make([]*IPUsageTracker, 0, len(*currentPool)+len(addedTrackers))

						expectedPrefix := IPv6Prefix + ":" + IPv6Subnet + ":"
						var toFlush []string

						// Keep valid IPs, remove exhausted ones
						for _, t := range *currentPool {
							if !strings.HasPrefix(t.IP, expectedPrefix) {
								if t.GetInUseCount() == 0 {
									toFlush = append(toFlush, t.IP)
									t.transport.CloseIdleConnections()
								} else {
									newPool = append(newPool, t)
								}
							} else if t.GetRequestCount() >= MaxRequestsPerIP {
								if t.GetInUseCount() == 0 {
									toFlush = append(toFlush, t.IP)
									t.transport.CloseIdleConnections()
								} else {
									newPool = append(newPool, t)
								}
							} else {
								newPool = append(newPool, t)
							}
						}

						// Flush old IPs in background
						if len(toFlush) > 0 {
							go func(ips []string) {
								for _, ip := range ips {
									removeIPv6FromInterface(ip)
								}
							}(toFlush)
						}
					} else {
						newPool = make([]*IPUsageTracker, 0, len(addedTrackers))
					}

					newPool = append(newPool, addedTrackers...)
					ipPool.Store(&newPool)
					poolWriteMutex.Unlock()
				}
			}(batchTarget)
		}
	}
}

func checkPrivileges() bool {
	if os.Geteuid() != 0 && ListenPort < 1024 {
		log.Fatal("ERROR: Root privileges required for port 80")
		return false
	}
	return true
}

func onStartup() bool {
	if !checkPrivileges() {
		return false
	}

	checkInterface()

	time.Sleep(100 * time.Millisecond)
	go flushAllIPAddresses()
	time.Sleep(500 * time.Millisecond)

	testIP := randomIPv6()
	addIPv6ToInterface(testIP)

	return true
}

func main() {
	// Initialize the pool
	emptyPool := make([]*IPUsageTracker, 0, DesiredPoolSize)
	ipPool.Store(&emptyPool)

	// Create default transport
	defaultTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: RequestTimeout,
		DisableKeepAlives:     false,
		DisableCompression:    true,
	}
	defaultClient = &http.Client{
		Transport: defaultTransport,
		Timeout:   RequestTimeout,
	}

	if !onStartup() {
		os.Exit(1)
	}

	// Start background processes
	go func() {
		time.Sleep(1 * time.Second)
		cleanupWrongSubnetIPs()
		manageIPPool()
	}()

	go func() {
		time.Sleep(5 * time.Second)
		periodicIPFlush()
	}()

	go func() {
		time.Sleep(3 * time.Second)
		periodicUnusedIPFlush()
	}()

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", ListenHost, ListenPort),
		Handler:           http.HandlerFunc(handleRequest),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	fmt.Printf("Starting i6.shark server v%s on %s\n", Version, server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
