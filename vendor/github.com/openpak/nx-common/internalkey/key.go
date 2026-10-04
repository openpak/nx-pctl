// Package internalkey is the X-Internal-Key scheme every OpenPak internal route uses: one
// shared secret (NX_INTERNAL_KEY, or OPENPAK_INTERNAL_KEY) in one header, compared in
// constant time. Strict refuses everyone when no key is configured; Lenient lets everyone in,
// which is what nx-baas's older game-API routes have always done on a dev box.
package internalkey

import (
	"crypto/hmac"
	"net/http"
	"os"
)

// Header carries the key.
const Header = "X-Internal-Key"

// Key is the configured secret, "" when there is none.
func Key() string {
	if k := os.Getenv("NX_INTERNAL_KEY"); k != "" {
		return k
	}
	return os.Getenv("OPENPAK_INTERNAL_KEY")
}

// Strict reports whether r carries the configured key. No key configured means no caller.
func Strict(r *http.Request) bool {
	k := Key()
	return k != "" && hmac.Equal([]byte(k), []byte(r.Header.Get(Header)))
}

// Lenient is Strict, except that with no key configured every caller is let in.
func Lenient(r *http.Request) bool {
	k := Key()
	return k == "" || hmac.Equal([]byte(k), []byte(r.Header.Get(Header)))
}

// Guard wraps a handler with Strict, answering 401 (or 503 when no key is configured, so a
// misconfigured deployment says so rather than looking like a wrong key).
func Guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Key() == "" {
			http.Error(w, `{"error":"internal_key_not_configured"}`, http.StatusServiceUnavailable)
			return
		}
		if !Strict(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}
