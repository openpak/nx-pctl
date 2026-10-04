package main

// The helpers moon.go was written against in nx-baas, under the same names, so a fix made
// to it there applies here as a patch (README.md). The bodies live in nx-common.

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/openpak/nx-common/internalkey"
	"github.com/openpak/nx-common/nxhttp"
	"github.com/openpak/nx-common/nxjwt"
)

const logPrefix = "[nx-pctl]"

func getenv(k, d string) string                          { return nxhttp.Getenv(k, d) }
func writeJSON(w http.ResponseWriter, status int, v any) { nxhttp.WriteJSON(w, status, v) }
func hostOf(r *http.Request) string                      { return nxhttp.HostOf(r) }
func dump(r *http.Request, body []byte, tag string)      { nxhttp.Dump(logPrefix, r, body, tag) }
func str(m map[string]any, k string) string              { return nxjwt.Str(m, k) }

var (
	parseJWT = nxjwt.Parse
	signJWT  = nxjwt.Sign
	uuid4    = nxjwt.UUID4
)

func apiErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// internalOK is nx-baas's game-API check: the internal key when one is configured.
func (s *server) internalOK(r *http.Request) bool { return internalkey.Lenient(r) }

// bearer returns the claims of a token nx-baas signed on the request, or nil. On the pctl
// host that is the console's dauth device token, whose subject is the device.
func (s *server) bearer(r *http.Request) map[string]any {
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, "Bearer ") || s.key == nil {
		return nil
	}
	c, err := parseJWT(strings.TrimPrefix(a, "Bearer "), &s.key.PublicKey)
	if err != nil {
		return nil
	}
	return c
}

// serviceStatus is the "is this online service up" answer the pctl host gave before moon
// existed, kept for every path outside /moon/v1 (nx-baas services.go).
func (s *server) serviceStatus(w http.ResponseWriter, r *http.Request, _ []byte) {
	log.Printf("%s service status %s", logPrefix, r.URL.Path)
	writeJSON(w, 200, map[string]any{"status": "available", "type": "NORMAL"})
}

// fetchAvatar downloads a JPEG from the website (nx-baas avatar.go).
func fetchAvatar(url string) ([]byte, error) {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("avatar: %s said %d", url, resp.StatusCode)
	}
	img, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if len(img) < 2 || img[0] != 0xFF || img[1] != 0xD8 {
		return nil, fmt.Errorf("avatar: %s did not return a JPEG", url)
	}
	return img, nil
}
