// SPDX-License-Identifier: Apache-2.0

// Package refrelay is a reference relay of the Relay Specification (RELAY-v0 section 4), for
// tests of the live test tool relay-conformance only: the clean reference passes the class
// relay, and each deliberate defect, switched on by a Fault, fails exactly the check meant to
// catch it. Neither the tool nor the files of package relay import it (a test checks that).
//
// One listener serves tunnel connections and agent connections and tells them apart by the
// server name (section 4.2). The server name is read from the ClientHello through a buffered
// wrapper that only reads, so that no TLS alert reaches an agent (section 4.5).
package refrelay

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ALPN is the application protocol of tunnel connections (section 4.2).
const ALPN = "hm-tunnel/1"

// Defaults of a Config.
const (
	defaultValidity   = 10 * time.Second
	defaultHeartbeat  = 30 * time.Second
	defaultMaxStreams = 64
	defaultDenyTick   = 20 * time.Millisecond
	// maxHello is the most a relay reads of a ClientHello: 16384 bytes and the record headers.
	maxHello     = 16384 + 64
	helloTimeout = 10 * time.Second
	frameTimeout = 5 * time.Second
	// minAnnounced and maxAnnounced bound the heartbeat interval of hello-ack.
	minAnnounced = 5
	maxAnnounced = 120
)

// defaultAgentAddr is a public address that stands for the agent: in a test the agent connects
// from the loopback, which a gateway refuses as a source (section 4.6).
var defaultAgentAddr = netip.MustParseAddr("45.33.32.156")

// Route is a name the operator serves.
type Route struct {
	// Home is the home ID of the installation.
	Home string
	// Verified is false for an own-domain name that is still pending.
	Verified bool
}

// Registry is what the relay asks the operator.
type Registry interface {
	// Routes returns every name the operator serves, in lower case.
	Routes() map[string]Route
	// Active reports whether the installation may use the tunnel: it is neither unpaired nor
	// blocked.
	Active(home string) bool
	// Denied reports whether the certificate with this serial (hex of the bytes of the number)
	// is on the denylist.
	Denied(serial string) bool
	// Roots holds the operator's tunnel CA.
	Roots() *x509.CertPool
	// TrustDomain is the trust domain of the SPIFFE IDs.
	TrustDomain() string
}

// Config configures a reference relay.
type Config struct {
	// Host is relay.host: the server name of tunnel connections.
	Host string
	// Faults are the defects the relay shows.
	Faults Fault
	// TokenValidity is how long a token lasts; zero means 10 seconds.
	TokenValidity time.Duration
	// Heartbeat is how often the relay pings; zero means 30 seconds. The interval announced in
	// hello-ack is this value in whole seconds, between 5 and 120.
	Heartbeat time.Duration
	// MaxStreams is the most simultaneous agent connections of an installation; zero means 64.
	MaxStreams int
	// AgentAddr is the address written as the agent's in the PROXY header; the zero value is a
	// public IPv4 address.
	AgentAddr netip.Addr
	// DenyTick is how often the relay looks for connections of denied certificates; zero
	// means 20 ms.
	DenyTick time.Duration
	// AnnouncePins makes the relay send pins after hello-ack.
	AnnouncePins bool
}

// Relay is a reference relay.
type Relay struct {
	cfg    Config
	reg    Registry
	listed tls.Certificate
	other  tls.Certificate
	pin    [sha256.Size]byte
	ln     net.Listener
	local  netip.AddrPort

	stop    chan struct{}
	wg      sync.WaitGroup
	closing sync.Once

	mu       sync.Mutex
	sessions map[string]*session
	tokens   map[[sha256.Size]byte]*token
	streams  map[string]int
	raw      map[net.Conn]struct{}
	live     map[*tls.Conn]identity
	tlsCfg   *tls.Config
}

// New returns a relay with its keys. Start makes it listen.
func New(cfg Config) *Relay {
	if cfg.TokenValidity == 0 {
		cfg.TokenValidity = defaultValidity
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = defaultHeartbeat
	}
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = defaultMaxStreams
	}
	if !cfg.AgentAddr.IsValid() {
		cfg.AgentAddr = defaultAgentAddr
	}
	if cfg.DenyTick == 0 {
		cfg.DenyTick = defaultDenyTick
	}
	r := &Relay{cfg: cfg, stop: make(chan struct{}), sessions: map[string]*session{}, tokens: map[[sha256.Size]byte]*token{},
		streams: map[string]int{}, raw: map[net.Conn]struct{}{}, live: map[*tls.Conn]identity{}}
	r.listed, r.pin = selfSigned(cfg.Host, true)
	r.other, _ = selfSigned(cfg.Host, false)
	return r
}

// selfSigned makes a certificate for host with a new Ed25519 or P-256 key and returns it with
// its pin.
func selfSigned(host string, edwards bool) (tls.Certificate, [sha256.Size]byte) {
	var key crypto.Signer
	if edwards {
		_, key = must2(ed25519.GenerateKey(rand.Reader))
	} else {
		key = must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der := must(x509.CreateCertificate(rand.Reader, template, template, key.Public(), key))
	leaf := must(x509.ParseCertificate(der))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
}

// Pins returns the pin of the relay's key as it goes into relay_pins (SHA-256 of the
// SubjectPublicKeyInfo, base64url).
func (r *Relay) Pins() []string {
	return []string{base64.RawURLEncoding.EncodeToString(r.pin[:])}
}

// Start listens on a loopback port and serves with the registry; it returns the address.
func (r *Relay) Start(reg Registry) string {
	r.reg = reg
	// One configuration serves all connections: a new one for each would hide resumption
	// behind fresh ticket keys.
	r.tlsCfg = r.tlsConfig()
	r.ln = must(net.Listen("tcp", "127.0.0.1:0"))
	r.local = netip.MustParseAddrPort(r.ln.Addr().String())
	r.wg.Add(2)
	go r.accept()
	go r.reap()
	return r.ln.Addr().String()
}

// Close stops the relay and closes every connection; it may be called more than once.
func (r *Relay) Close() {
	r.closing.Do(r.shutdown)
}

func (r *Relay) shutdown() {
	close(r.stop)
	_ = r.ln.Close()
	r.mu.Lock()
	for c := range r.raw {
		_ = c.Close()
	}
	for _, t := range r.tokens {
		t.timer.Stop()
	}
	r.mu.Unlock()
	r.wg.Wait()
}

func (r *Relay) has(f Fault) bool { return r.cfg.Faults.Has(f) }

func (r *Relay) accept() {
	defer r.wg.Done()
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		r.raw[c] = struct{}{}
		r.mu.Unlock()
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			// An agent connection that waits for its data connection stays open.
			if !r.handle(c) {
				r.forget(c)
			}
		}()
	}
}

func (r *Relay) forget(c net.Conn) {
	_ = c.Close()
	r.mu.Lock()
	delete(r.raw, c)
	r.mu.Unlock()
}

// reap closes the connections of certificates that are on the denylist, or of installations
// that are no longer active (sections 4.1 and 7.6).
func (r *Relay) reap() {
	defer r.wg.Done()
	tick := time.NewTicker(r.cfg.DenyTick)
	defer tick.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-tick.C:
		}
		if r.has(NoDenylist) {
			continue
		}
		r.mu.Lock()
		for c, id := range r.live {
			if r.reg.Denied(id.serial) || !r.reg.Active(id.home) {
				_ = c.Close()
			}
		}
		r.mu.Unlock()
	}
}

// must returns v and panics on an error that cannot happen with the inputs of this package.
func must[T any](v T, err error) T {
	if err != nil {
		panic("refrelay: " + err.Error())
	}
	return v
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic("refrelay: " + err.Error())
	}
	return a, b
}
