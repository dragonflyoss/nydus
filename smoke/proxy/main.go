// HTTP tunneling proxy server with failure simulation
// Usage: go run ./smoke/proxy
//
// Failure simulation (via query params or X-Test-Status header):
//   ?status=429  → HTTP 429 Too Many Requests
//   ?status=403  → HTTP 403 Forbidden
//   ?status=500  → HTTP 500 Internal Server Error
//   ?timeout=5s  → Delay response by 5 seconds

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// InjectionRule defines a dynamic error injection configuration.
// Set via POST /_test/inject, cleared via DELETE /_test/inject.
type InjectionRule struct {
	Status  int    `json:"status,omitempty"`
	Timeout string `json:"timeout,omitempty"`
	Count   int    `json:"count"`
}

// ProxyStats reports proxy request counters and current injection state.
type ProxyStats struct {
	TotalRequests    int64          `json:"total_requests"`
	InjectedRequests int64          `json:"injected_requests"`
	CurrentRule      *InjectionRule `json:"current_rule"`
}

var (
	injectionMu   sync.Mutex
	injectionRule *InjectionRule

	totalRequests    int64
	injectedRequests int64
)

func handleControlAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/_test/inject" && r.Method == http.MethodPost:
		var rule InjectionRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		injectionMu.Lock()
		injectionRule = &rule
		injectionMu.Unlock()
		log.Printf("Injection rule set: status=%d timeout=%s count=%d",
			rule.Status, rule.Timeout, rule.Count)
		w.WriteHeader(http.StatusOK)

	case r.URL.Path == "/_test/inject" && r.Method == http.MethodDelete:
		injectionMu.Lock()
		injectionRule = nil
		injectionMu.Unlock()
		log.Println("Injection rule cleared")
		w.WriteHeader(http.StatusOK)

	case r.URL.Path == "/_test/stats" && r.Method == http.MethodGet:
		injectionMu.Lock()
		var ruleCopy *InjectionRule
		if injectionRule != nil {
			rc := *injectionRule
			ruleCopy = &rc
		}
		stats := ProxyStats{
			TotalRequests:    atomic.LoadInt64(&totalRequests),
			InjectedRequests: atomic.LoadInt64(&injectedRequests),
			CurrentRule:      ruleCopy,
		}
		injectionMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)

	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// maybeInjectError applies the global injection rule if active.
// Returns true if an error response was sent (request handled).
func maybeInjectError(w http.ResponseWriter, r *http.Request) bool {
	injectionMu.Lock()
	rule := injectionRule
	if rule == nil {
		injectionMu.Unlock()
		return false
	}
	// Only inject errors for Dragonfly pipeline requests.
	// When nydusd sets disable_proxy=true, it strips Dragonfly headers
	// but still routes through the HTTP proxy at the Connection level.
	// Real dfdaemon forwards non-Dragonfly requests normally; we must too.
	if r.Header.Get("X-Dragonfly-Use-P2P") == "" {
		injectionMu.Unlock()
		return false
	}
	// Copy the rule so we can release the lock before sleeping
	ruleCopy := *rule
	// Decrement count
	if rule.Count > 0 {
		rule.Count--
		if rule.Count == 0 {
			injectionRule = nil
		}
	}
	injectionMu.Unlock()

	// Apply timeout delay
	if ruleCopy.Timeout != "" {
		duration, err := time.ParseDuration(ruleCopy.Timeout)
		if err == nil {
			log.Printf("Injection: delaying %s", duration)
			time.Sleep(duration)
		}
	}

	// If no status code, just delayed — forward normally
	if ruleCopy.Status == 0 {
		return false
	}

	// Return error response with Dragonfly error type header
	atomic.AddInt64(&injectedRequests, 1)
	log.Printf("Injection: returning status %d", ruleCopy.Status)
	w.Header().Set("X-Dragonfly-Error-Type", "proxy")
	w.WriteHeader(ruleCopy.Status)
	fmt.Fprintf(w, "simulated error: %d %s", ruleCopy.Status, http.StatusText(ruleCopy.Status))
	return true
}

func main() {
	server := &http.Server{
		Addr: ":4001",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&totalRequests, 1)

			// Control API (direct requests, not proxy traffic)
			if strings.HasPrefix(r.URL.Path, "/_test/") {
				handleControlAPI(w, r)
				return
			}

			fmt.Printf("Handling: %s\n", r.URL.String())

			// Per-request simulation (query params, X-Test-Status header)
			if handled := handleFailureSimulation(w, r); handled {
				return
			}

			// Dynamic injection from control API
			if handled := maybeInjectError(w, r); handled {
				return
			}

			if r.Method == http.MethodConnect {
				httpsProxy(w, r)
			} else {
				httpProxy(w, r)
			}
		}),
	}

	log.Println("Starting proxy server on :4001")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Server error:", err)
	}
}

// handleFailureSimulation checks for failure simulation params and returns
// true if a simulated failure response was sent.
func handleFailureSimulation(w http.ResponseWriter, r *http.Request) bool {
	// Check for timeout simulation
	if timeoutStr := r.URL.Query().Get("timeout"); timeoutStr != "" {
		duration, err := time.ParseDuration(timeoutStr)
		if err != nil {
			http.Error(w, "invalid timeout duration", http.StatusBadRequest)
			return true
		}
		log.Printf("Simulating timeout: %s", duration)
		time.Sleep(duration)
		return false
	}

	// Check for status code simulation (query param or header)
	statusStr := r.URL.Query().Get("status")
	if statusStr == "" {
		statusStr = r.Header.Get("X-Test-Status")
	}
	if statusStr == "" {
		return false
	}

	statusCode, err := strconv.Atoi(statusStr)
	if err != nil {
		http.Error(w, "invalid status code", http.StatusBadRequest)
		return true
	}

	log.Printf("Simulating status: %d", statusCode)
	w.Header().Set("X-Dragonfly-Error-Type", "proxy")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, "simulated error: %d %s", statusCode, http.StatusText(statusCode))
	return true
}

func httpsProxy(w http.ResponseWriter, r *http.Request) {
	destAddr := r.URL.Host

	log.Println("Tunneling established", destAddr)

	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer func() {
		_ = destConn.Close()
	}()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer func() {
		_ = clientConn.Close()
	}()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go transfer(destConn, clientConn)
	transfer(clientConn, destConn)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func httpProxy(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}

	// http: Request.RequestURI can't be set in client requests.
	r.RequestURI = ""

	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		log.Println("ServeHTTP:", err)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	log.Println(r.RemoteAddr, " ", resp.Status)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer func() {
		_ = destination.Close()
	}()
	defer func() {
		_ = source.Close()
	}()
	_, _ = io.Copy(destination, source)
}
