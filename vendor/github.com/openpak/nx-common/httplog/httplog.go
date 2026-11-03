// Package httplog writes one access line per HTTP request:
//
//	[prefix] http <method> <host> <path> -> <status> <duration>ms
//
// The query string, headers, cookies and bodies are never logged: they carry tokens, ids and
// device certificates. The status writer keeps http.Flusher, http.Hijacker and http.Pusher
// working (HTTP/2 push, websockets, streaming), and exposes Unwrap for http.ResponseController.
package httplog

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Options tunes Wrap. The zero value logs the raw path and no user agent.
type Options struct {
	// Path rewrites the path before it is logged (id masking). nil logs it as is.
	Path func(path string) string
	// UserAgent, when set, appends ` ua=%q` of its result. Give it a redacting function.
	UserAgent func(ua string) string
	// Skip reports paths that are not logged (health checks, noisy polling). nil skips /healthz.
	Skip func(path string) bool
}

// Wrap logs every request served by next, once, after it finishes.
func Wrap(prefix string, o Options, next http.Handler) http.Handler {
	if o.Skip == nil {
		o.Skip = func(p string) bool { return p == "/healthz" }
	}
	if prefix != "" && !strings.HasSuffix(prefix, " ") {
		prefix += " "
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o.Skip(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			p := r.URL.Path
			if o.Path != nil {
				p = o.Path(p)
			}
			ua := ""
			if o.UserAgent != nil {
				ua = " ua=" + quote(o.UserAgent(r.UserAgent()))
			}
			log.Printf("%shttp %s %s %s -> %d %dms%s", prefix, r.Method, r.Host, clean(p), sw.status, time.Since(start).Milliseconds(), ua)
		}()
		next.ServeHTTP(sw, r)
	})
}

// clean keeps a path on one line, whatever the client sent.
func clean(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		return strings.NewReplacer("\r", "?", "\n", "?").Replace(s)
	}
	return s
}

func quote(s string) string { return `"` + strings.ReplaceAll(clean(s), `"`, `'`) + `"` }

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	// 1xx informational headers do not end the response.
	if !s.wrote && (code < 100 || code > 199 || code == http.StatusSwitchingProtocols) {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) Flush() {
	s.wrote = true
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		s.status, s.wrote = http.StatusSwitchingProtocols, true
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (s *statusWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := s.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
