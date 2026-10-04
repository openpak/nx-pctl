// Package nxtls is how a Switch-facing OpenPak service terminates TLS: Traefik passes the
// console's connection through by SNI, and the service answers with a certificate signed by
// the OpenPak CA the console trusts. This is nx-baas's listener setup, unchanged:
//
//   - a fixed multi-SAN certificate for the names a console authenticates strictly (an
//     on-demand certificate on those has been refused with 2123-0013);
//   - an on-demand certificate per unknown SNI, so a probe of a name nobody routed still
//     gets past TLS and its request lands in the log;
//   - every cipher suite Go can still speak, insecure ones included, from TLS 1.0 up: the
//     console's web applet is an old engine and offers only legacy TLS 1.2 suites;
//   - no client-certificate request: the console's browser stops dead on one.
package nxtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
)

// SelfSigned mints a leaf for hosts, signed by the CA in caDir (ca.pem, ca.key) when there is
// one, else self-signed (which only consoles patched to skip verification accept).
func SelfSigned(prefix string, hosts []string, caDir string) tls.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := x509.Certificate{
		SerialNumber: func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)); return n }(), Subject: pkix.Name{CommonName: hosts[0], Organization: []string{"OpenPak"}},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: hosts,
	}
	if caPEM, err := os.ReadFile(caDir + "/ca.pem"); err == nil {
		if keyPEM, err := os.ReadFile(caDir + "/ca.key"); err == nil {
			if pair, err := tls.X509KeyPair(caPEM, keyPEM); err == nil {
				if ca, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
					if der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca, &key.PublicKey, pair.PrivateKey); err == nil {
						log.Printf("%s server cert signed by the OpenPak CA", prefix)
						return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
					}
				}
			}
		}
	}
	log.Printf("%s server cert self-signed (relies on disable_ca_verification)", prefix)
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ServerConfig is the listener's TLS config: fixed names on one certificate, everything else
// on demand. debug logs every ClientHello by SNI, which is how a connection that never speaks
// HTTP (a persistent frontline) still shows up in the log.
func ServerConfig(prefix string, fixed []string, caDir string, debug bool) *tls.Config {
	cert := SelfSigned(prefix, fixed, caDir)
	fixedNames := map[string]bool{}
	for _, n := range fixed {
		fixedNames[n] = true
	}
	var onDemand sync.Map
	getCert := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "" || fixedNames[h.ServerName] {
			return &cert, nil
		}
		if c, ok := onDemand.Load(h.ServerName); ok {
			return c.(*tls.Certificate), nil
		}
		log.Printf("%s on-demand cert for SNI %s", prefix, h.ServerName)
		c := SelfSigned(prefix, []string{h.ServerName}, caDir)
		onDemand.Store(h.ServerName, &c)
		return &c, nil
	}
	suites := make([]uint16, 0, 32)
	for _, c := range tls.CipherSuites() {
		suites = append(suites, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		suites = append(suites, c.ID)
	}
	conf := &tls.Config{
		GetCertificate: getCert,
		ClientAuth:     tls.NoClientCert,
		MinVersion:     tls.VersionTLS10,
		CipherSuites:   suites,
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
		},
	}
	if debug {
		conf.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("%s TLS hello sni=%s from=%s alpn=%v", prefix, h.ServerName, h.Conn.RemoteAddr(), h.SupportedProtos)
			return nil, nil
		}
	}
	return conf
}
