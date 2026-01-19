// HTTP tunneling proxy server implementation
// Usage: go run ./smoke/proxy

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	server := &http.Server{
		Addr: ":4001",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("Handling: %s\n", r.URL.String())

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

func httpsProxy(w http.ResponseWriter, r *http.Request) {
	destAddr := r.URL.Host

	log.Println("Tunneling established", destAddr)

	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

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
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

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
	// http://golang.org/src/pkg/net/http/client.go
	r.RequestURI = ""

	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		log.Fatal("ServeHTTP:", err)
	}
	defer resp.Body.Close()

	log.Println(r.RemoteAddr, " ", resp.Status)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}
