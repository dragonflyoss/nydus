package registry

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fault is one misbehavior applied to the requests it matches. Several
// effects may be combined; they apply in field order.
type Fault struct {
	// Match selects requests; nil matches every blob GET.
	Match func(*http.Request) bool
	// Times bounds how many requests the fault hits; 0 is unlimited.
	Times int
	// Delay stalls the request before it is answered.
	Delay time.Duration
	// Status answers with this status and no body instead of the registry.
	Status int
	// IgnoreRange drops the Range header, so the registry answers 200 with
	// the whole blob, as some registries and proxies do.
	IgnoreRange bool
	// CutAfter aborts the connection once this many body bytes were sent.
	CutAfter int64
	// FlipBit flips the lowest bit of the body byte at *FlipBit.
	FlipBit *int64
	// Headers overrides response headers; an empty value removes a header.
	Headers map[string]string
	// ShortBody sends at most this many bytes with a matching Content-Length,
	// producing a complete HTTP response that is too short for the requested range.
	ShortBody int64
}

// Request is a request the registry saw.
type Request struct {
	Method string
	Path   string
	Range  string
	Status int
	// Faulted reports whether a fault hit the request.
	Faulted bool
}

// Faults holds the faults currently injected and the requests seen.
type Faults struct {
	mu       sync.Mutex
	faults   []*active
	requests []Request
	// hits counts the requests a fault hit, at the moment it hit: a
	// request is only recorded once answered, which for a delayed one can
	// be after the reader gave up on it.
	hits int
}

type active struct {
	Fault
	hits int
}

// Set replaces the injected faults.
func (f *Faults) Set(faults ...Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = f.faults[:0]
	for _, fault := range faults {
		f.faults = append(f.faults, &active{Fault: fault})
	}
}

// Clear removes every fault.
func (f *Faults) Clear() { f.Set() }

// Requests returns the requests seen so far.
func (f *Faults) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// Hits returns how many requests a fault hit.
func (f *Faults) Hits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

// IsBlobGet matches a GET of a blob.
func IsBlobGet(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/sha256:")
}

// BlobGet matches a GET of the blob with the given hex digest.
func BlobGet(digest string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		return IsBlobGet(r) && strings.HasSuffix(r.URL.Path, "/blobs/sha256:"+digest)
	}
}

// pick returns the fault that hits r, if any, counting the hit.
func (f *Faults) pick(r *http.Request) *Fault {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.faults {
		match := a.Match
		if match == nil {
			match = IsBlobGet
		}
		if (a.Times == 0 || a.hits < a.Times) && match(r) {
			a.hits++
			f.hits++
			fault := a.Fault
			return &fault
		}
	}
	return nil
}

func (f *Faults) record(r Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
}

// Wrap records requests and injects faults before forwarding to next.
func (f *Faults) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fault := f.pick(r)
		rec := &recorder{ResponseWriter: w, status: http.StatusOK, flipAt: -1}
		defer func() {
			f.record(Request{
				Method:  r.Method,
				Path:    r.URL.Path,
				Range:   r.Header.Get("Range"),
				Status:  rec.status,
				Faulted: fault != nil,
			})
		}()
		if fault == nil {
			next.ServeHTTP(rec, r)
			return
		}
		if fault.Delay > 0 {
			select {
			case <-time.After(fault.Delay):
			case <-r.Context().Done():
				return
			}
		}
		if fault.Status != 0 {
			rec.WriteHeader(fault.Status)
			return
		}
		if fault.IgnoreRange {
			r = r.Clone(r.Context())
			r.Header.Del("Range")
		}
		rec.cutAfter = fault.CutAfter
		rec.headers = fault.Headers
		rec.shortBody = fault.ShortBody
		if fault.FlipBit != nil {
			rec.flipAt = *fault.FlipBit
		}
		next.ServeHTTP(rec, r)
	})
}

// recorder tracks the status and body offset of a response and applies the
// body faults as the registry writes it.
type recorder struct {
	http.ResponseWriter
	status   int
	written  int64
	cutAfter int64
	// flipAt is the body offset whose lowest bit is flipped; -1 is none.
	flipAt    int64
	headers   map[string]string
	shortBody int64
	started   bool
}

func (r *recorder) WriteHeader(status int) {
	if r.started {
		return
	}
	r.started = true
	r.status = status
	for key, value := range r.headers {
		if value == "" {
			r.Header().Del(key)
		} else {
			r.Header().Set(key, value)
		}
	}
	if r.shortBody > 0 {
		r.Header().Set("Content-Length", strconv.FormatInt(r.shortBody, 10))
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(p []byte) (int, error) {
	if !r.started {
		r.WriteHeader(http.StatusOK)
	}
	if r.shortBody > 0 {
		count := min(int64(len(p)), max(0, r.shortBody-r.written))
		n, err := r.ResponseWriter.Write(p[:count])
		r.written += int64(n)
		if err != nil {
			return n, err
		}
		return len(p), nil
	}
	if r.flipAt >= r.written && r.flipAt < r.written+int64(len(p)) {
		p = append([]byte(nil), p...)
		p[r.flipAt-r.written] ^= 1
	}
	if r.cutAfter > 0 && r.written+int64(len(p)) > r.cutAfter {
		n, _ := r.ResponseWriter.Write(p[:r.cutAfter-r.written])
		r.written += int64(n)
		if fl, ok := r.ResponseWriter.(http.Flusher); ok {
			fl.Flush()
		}
		// net/http aborts the connection without logging on this panic.
		panic(http.ErrAbortHandler)
	}
	n, err := r.ResponseWriter.Write(p)
	r.written += int64(n)
	return n, err
}
