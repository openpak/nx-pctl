// nx-pctl: Nintendo Switch parental controls (the pctl sysmodule's moon API) for OpenPak,
// split out of nx-baas (nx-baas docs/service-split.md).
//
// It owns the pctl hostnames -- api-<env>.pctl.srv.nintendo.net (moon: pairing, the
// setting the console polls, owners, players, play events) and the explainer movie on
// parentalcontrols-movie-<env> -- the parent-side routes the website calls
// (/internal/pctl), and the records in $NX_DATA/pctl.json. A parent's save is pushed to the
// console through the penne API (nx-penne, or nx-baas while it still serves Penne).
//
// Two listeners:
//
//	NX_ADDR      TLS for consoles (Traefik passes the SNIs through), certificates from the
//	             OpenPak CA in NX_CA_DIR, exactly as nx-baas terminates them (nx-common/nxtls)
//	NX_API_ADDR  plain HTTP on the openpak network: /internal/pctl for the website, and the
//	             console routes again for what nx-baas forwards here
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openpak/nx-common/nxapi"
	"github.com/openpak/nx-common/nxhttp"
	"github.com/openpak/nx-common/nxjwt"
	"github.com/openpak/nx-common/nxtls"
)

type server struct {
	store *Store
	// key is the BAAS signing key: the console's bearer on moon is a dauth device token
	// nx-baas signed with it.
	key   *rsa.PrivateKey
	idKid string
	// penne delivers a parent's save to the console's connection.
	penne devicePusher
}

// devicePusher is what pctl asks the push side (nxapi.Client implements it).
type devicePusher interface {
	DeviceMessage(ctx context.Context, m nxapi.DeviceMessage) (*nxapi.DeviceResult, error)
}

// penneDeviceMessage writes one message to the live connections of the console's Penne
// registration: the token it gave at activate, else the registration made under its device
// certificate. It returns the registration and how many connections took the message; the
// error is the push side being unreachable (moon.go logs it; the save stands either way and
// the console catches up at its next scheduled retrieve).
func (s *server) penneDeviceMessage(penneID, dauthUser, name, receivers, body string) (string, int, error) {
	if s.penne == nil {
		return "", 0, errors.New("no push side configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := s.penne.DeviceMessage(ctx, nxapi.DeviceMessage{PenneID: penneID, DauthUser: dauthUser, Name: name, Receivers: receivers, Body: body})
	if err != nil {
		return penneID, 0, err
	}
	return res.PenneID, res.Connections, nil
}

// fixedNames were on nx-baas's fixed certificate and stay fixed here. The movie host was
// on demand there and is here.
var fixedNames = []string{"api-lp1.pctl.srv.nintendo.net"}

var debug = os.Getenv("NX_DEBUG") != ""

// ServeHTTP answers the pctl hosts; any other host is misrouted and says so with a 421.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r)
	log.Printf("%s %s %s%s ua=%q", logPrefix, r.Method, host, r.URL.RequestURI(), r.UserAgent())
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if debug {
		// No PIN in the log: parental controls carry one in both directions.
		dump(r, pctlPinInBody.ReplaceAll(body, []byte(`${1}****"`)), "DBG >>>")
		rec := &recorder{ResponseWriter: w, status: 200}
		w = rec
		defer func() {
			log.Printf("%s DBG <<< %d %s %s%s body(%d)=%s", logPrefix, rec.status, r.Method, host, r.URL.Path, rec.buf.Len(), pctlPinInBody.ReplaceAll(rec.buf.Bytes(), []byte(`${1}****"`)))
		}()
	}
	switch {
	case r.URL.Path == "/healthz":
		writeJSON(w, 200, map[string]any{"status": "ok", "service": "nx-pctl"})
	case strings.Contains(host, "pctl.srv.nintendo.net"):
		// The pctl sysmodule's moon API (moon.go). Anything outside /moon/v1 on this host
		// still gets the service-status answer.
		s.moon(w, r, body)
	case strings.HasPrefix(host, "parentalcontrols-movie-"):
		// The Parental Controls explainer clip (moon.go).
		s.pctlMovie(w, r)
	default:
		nxhttp.Misrouted(logPrefix, w, r)
	}
}

// internalAPI is the plain-HTTP listener: the console routes for requests nx-baas forwards
// with their Host kept, and -- for every other Host -- the parent-side routes the website
// calls and a health check. A console host never reaches the parent routes
// (nxhttp.SplitListener).
func (s *server) internalAPI() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/pctl/pairing", s.pctlPairing)
	mux.HandleFunc("/internal/pctl/devices", s.pctlDeviceList)
	mux.HandleFunc("/internal/pctl/devices/", s.pctlDeviceRoute)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok", "service": "nx-pctl"})
	})
	return nxhttp.SplitListener(s, mux)
}

func main() {
	key, err := nxjwt.LoadRSAKey(getenv("BAAS_SIGNING_KEY", "/keys/baas_signing_key.pem"))
	if err != nil {
		log.Fatalf("%s signing key: %v", logPrefix, err)
	}
	penneURL := os.Getenv("NX_PENNE_URL")
	if penneURL == "" {
		// nx-baas serves (or forwards) the penne API too.
		penneURL = os.Getenv("NX_CORE_URL")
	}
	if penneURL == "" {
		log.Fatalf("%s NX_PENNE_URL or NX_CORE_URL is required (who delivers a parent's save to the console)", logPrefix)
	}
	data := getenv("NX_DATA", "/data")
	s := &server{
		store: loadStore(data+"/pctl.json", os.Getenv("NX_PCTL_IMPORT")),
		key:   key,
		idKid: getenv("BAAS_KID", "openpak-baas-key-1"),
		penne: nxapi.New(penneURL),
	}
	go func() {
		addr := getenv("NX_API_ADDR", ":20070")
		log.Printf("%s internal API listening %s (/internal/pctl, forwarded console routes)", logPrefix, addr)
		log.Fatal(http.ListenAndServe(addr, s.internalAPI()))
	}()
	srv := &http.Server{
		Addr: getenv("NX_ADDR", ":21000"), Handler: s,
		TLSConfig: nxtls.ServerConfig(logPrefix, fixedNames, getenv("NX_CA_DIR", "/data/ca"), debug),
	}
	log.Printf("%s listening %s; records %s/pctl.json (%d); penne %s", logPrefix, srv.Addr, data, len(s.store.PctlDevices), penneURL)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// ---------- debug recorder (nx-baas main.go) ----------

type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (rec *recorder) WriteHeader(c int) { rec.status = c; rec.ResponseWriter.WriteHeader(c) }
func (rec *recorder) Write(b []byte) (int, error) {
	if rec.buf.Len() < 8192 {
		rec.buf.Write(b)
	}
	return rec.ResponseWriter.Write(b)
}

func (rec *recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rec *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rec.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("recorder: wrapped writer is not a Hijacker")
}
