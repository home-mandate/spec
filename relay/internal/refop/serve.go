// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/home-mandate/spec/relay"
)

func fsReadFile(name string) ([]byte, error) { return fs.ReadFile(relay.FS(), name) }

// certLifetime is how long the certificates of a test server last.
const certLifetime = time.Hour

// Running is a reference operator that listens on 127.0.0.1 with TLS.
type Running struct {
	// Addr is the address of the listener.
	Addr string
	// Roots holds the CA that signed the certificate of the operator domain.
	Roots *x509.CertPool
	// Operator is the operator behind the listener.
	Operator *Operator
	// RelayAddr is the address of the reference relay, empty without one.
	RelayAddr string

	server *http.Server
}

// Serve starts the operator on a loopback port with a certificate for its domain, issued by a
// CA made for this call. It panics if the system cannot give it a loopback port.
func Serve(cfg Config) *Running {
	o := New(cfg)
	caKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "refop test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(certLifetime),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER := must(x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey))
	ca := must(x509.ParseCertificate(caDER))
	leafKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{o.cfg.Operator},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(certLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER := must(x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey))
	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
	}
	if cfg.Faults.Has(OnlyTLS12) {
		serverTLS.MinVersion, serverTLS.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	}
	l := must(tls.Listen("tcp", "127.0.0.1:0", serverTLS))
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	r := &Running{Addr: l.Addr().String(), Roots: roots, Operator: o,
		server: &http.Server{Handler: o.Handler(), ReadHeaderTimeout: 5 * time.Second,
			ErrorLog: log.New(io.Discard, "", 0)}}
	go func() { _ = r.server.Serve(l) }()
	if cfg.Relay != nil {
		r.RelayAddr = cfg.Relay.Start(o)
	}
	return r
}

// Close stops the listener.
func (r *Running) Close() error {
	err := r.server.Close()
	if r.Operator.cfg.Relay != nil {
		r.Operator.cfg.Relay.Close()
	}
	r.Operator.Close()
	return err
}

// Remap sends connections for the operator domain to the listener, whatever the port, and
// connections for the relay (its host and the relay addresses on port 443) to the reference relay,
// and connections to the name servers of the reference DNS to their listeners.
func (r *Running) Remap(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	switch {
	case err != nil:
		return r.Operator.dns.Remap(hostport)
	case host == r.Operator.cfg.Operator:
		return r.Addr
	case r.RelayAddr != "" && (host == "tunnel."+r.Operator.cfg.Operator || port == "443" && (host == "127.0.0.1" || host == "::1")):
		return r.RelayAddr
	}
	return r.Operator.dns.Remap(hostport)
}

// Lookup resolves the names of the name servers of the reference DNS, for netguard.Options.
func (r *Running) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.Operator.dns.LookupAddr(ctx, host)
}

// NS is the NS lookup of the reference DNS.
func (r *Running) NS(ctx context.Context, name string) ([]string, error) {
	return r.Operator.dns.LookupNS(ctx, name)
}
