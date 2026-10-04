// Package nxhttp holds the few HTTP helpers every Switch-facing OpenPak service answers with:
// the JSON reply a console accepts, the host a request named, and the full-request dump that
// is how an unknown route gets learned. They are the nx-baas originals, unchanged, so a reply
// from a split-out service is byte for byte what the monolith sent.
package nxhttp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// Getenv is os.Getenv with a default for the empty value.
func Getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// WriteJSON answers an object. The Pragma and Vary headers beside no-cache were captured from
// a reference reply; the console accepted ours with them.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Vary", "Accept-Encoding,Origin")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// WriteJSONValue is WriteJSON for a reply whose top level is not an object.
func WriteJSONValue(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	fmt.Fprint(w, string(b))
}

// HostOf is the request's host without a port.
func HostOf(r *http.Request) string {
	h := r.Host
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

// Dump logs a request in full: method, host, path, headers (a long Authorization cut to its
// first 40 characters) and body, plus a hex copy of a body that is neither JSON nor a form.
// prefix is the service's log tag, "[nx-shop]" and the like.
func Dump(prefix string, r *http.Request, body []byte, tag string) {
	var hdr strings.Builder
	for k, v := range r.Header {
		if k == "Authorization" && len(v) > 0 && len(v[0]) > 40 {
			fmt.Fprintf(&hdr, " %s: %s...;", k, v[0][:40])
			continue
		}
		fmt.Fprintf(&hdr, " %s: %s;", k, strings.Join(v, ","))
	}
	log.Printf("%s %s %s %s%s?%s hdr{%s} body(%d)=%q", prefix, tag, r.Method, HostOf(r), r.URL.Path, r.URL.RawQuery, hdr.String(), len(body), body)
	if len(body) > 0 && !json.Valid(body) && !strings.Contains(r.Header.Get("Content-Type"), "form") {
		log.Printf("%s %s body hex: %s", prefix, tag, hex.EncodeToString(body))
	}
}

// Misrouted answers a request for a hostname this service does not own: 421 Misdirected
// Request, logged, never a silent fallthrough into another family's handler. It is what a
// stale Traefik router or a forgotten proxy looks like from the inside.
func Misrouted(prefix string, w http.ResponseWriter, r *http.Request) {
	log.Printf("%s !! MISROUTED %s %s%s: this service does not own that hostname", prefix, r.Method, HostOf(r), r.URL.Path)
	WriteJSON(w, http.StatusMisdirectedRequest, map[string]any{"status": 421, "title": "misdirected request"})
}
