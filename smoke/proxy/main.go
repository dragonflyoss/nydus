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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

func main() {
	server := &http.Server{
		Addr: ":4001",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("Handling: %s\n", r.URL.String())

			// Check for failure simulation
			if handled := handleFailureSimulation(w, r); handled {
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
