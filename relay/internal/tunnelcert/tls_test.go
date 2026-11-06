// SPDX-License-Identifier: Apache-2.0

package tunnelcert_test

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
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/tunnelcert"
)

const (
	tunnelALPN   = "hm-tunnel/1"
	tlsTrust     = "relay-operator.example"
	tlsHomeA     = "k7q2xwmpd4hj3n6rt5vbyc2ezu"
	tlsHomeB     = "m3n4p5q6r7s2t3u4v5w6x7y2za"
	probeTimeout = 5 * time.Second
)

type tlsProbe struct {
	ID     string `json:"id"`
	Client struct {
		Version     string   `json:"version"`
		Groups      []string `json:"groups"`
		ALPN        []string `json:"alpn"`
		Certificate string   `json:"certificate"`
		Resume      bool     `json:"resume"`
	} `json:"client"`
	Expected string `json:"expected"`
	Why      string `json:"why"`
}

var probeGroups = map[string]tls.CurveID{
	"X25519MLKEM768": tls.X25519MLKEM768,
	"x25519":         tls.X25519,
	"secp256r1":      tls.CurveP256,
}

var probeVersions = map[string]uint16{"1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}

// helloFrame and helloAckFrame are a valid hello and hello-ack of version 1.
var (
	helloFrame    = []byte{0x00, 0x01, 0x00, 0x08, 0x01, 0x01, 0x04, 't', 'e', 's', 't', 0x00}
	helloAckFrame = []byte{0x00, 0x02, 0x00, 0x0b, 0x01, 0x03, 'r', 'e', 'f', 0x00, 0x1e, 0x01, 0x00, 0x40, 0x00}
)

// tunnelEnv holds the certificates of the probes and the relay's pin.
type tunnelEnv struct {
	roots  *x509.CertPool
	certs  map[string]tls.Certificate
	relay  tls.Certificate
	pin    [32]byte
	mu     sync.Mutex
	denied map[string]bool
	// lenient makes the server break section 4.2 wherever a probe should notice it.
	lenient bool
}

func newTunnelEnv(t *testing.T) *tunnelEnv {
	t.Helper()
	env := &tunnelEnv{roots: x509.NewCertPool(), certs: map[string]tls.Certificate{}, denied: map[string]bool{}}
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Tunnel CA (test)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		PermittedURIDomains: []string{tlsTrust},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	env.roots.AddCert(ca)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env.certs["tunnel"] = tunnelLeaf(t, tlsHomeA, ca, caKey, nil)
	env.certs["tunnel-p256"] = tunnelLeaf(t, tlsHomeA, ca, caKey, p256)
	env.certs["unpaired"] = tunnelLeaf(t, tlsHomeB, ca, caKey, nil)
	env.certs["self-signed"] = tunnelLeaf(t, tlsHomeA, nil, nil, nil)
	unpaired, err := x509.ParseCertificate(env.certs["unpaired"].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	env.denied[unpaired.SerialNumber.String()] = true
	env.relay = tunnelLeaf(t, tlsHomeA, nil, nil, nil)
	relayCert, err := x509.ParseCertificate(env.relay.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	env.pin = sha256.Sum256(relayCert.RawSubjectPublicKeyInfo)
	return env
}

// tunnelLeaf issues a tunnel certificate for home, by ca or, without one, self-signed. The
// key is Ed25519 unless one is given.
func tunnelLeaf(t *testing.T, home string, ca *x509.Certificate, caKey crypto.Signer, key crypto.Signer) tls.Certificate {
	t.Helper()
	if key == nil {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	san, err := tunnelcert.SANValue("spiffe://" + tlsTrust + "/home/" + home + "/gateway")
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: san}},
		BasicConstraintsValid: true,
	}
	parent, signer := ca, caKey
	if ca == nil {
		parent, signer = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serverConfig is a relay's TLS configuration for tunnel connections (section 4.2).
func (env *tunnelEnv) serverConfig() *tls.Config {
	if env.lenient {
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{env.relay},
			ClientAuth:   tls.RequestClientCert,
			NextProtos:   []string{tunnelALPN, "h2"},
		}
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		Certificates:           []tls.Certificate{env.relay},
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{tunnelALPN},
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if _, err := tunnelcert.Presented(raw, env.roots, tlsTrust, time.Now()); err != nil {
				return err
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			env.mu.Lock()
			defer env.mu.Unlock()
			if env.denied[leaf.SerialNumber.String()] {
				return errors.New("certificate on the denylist")
			}
			return nil
		},
	}
}

// serve answers tunnel connections like a relay that follows sections 4.1 and 4.2.
// One configuration serves all connections, as on a real server: with session tickets,
// a new one per connection would hide resumption behind fresh ticket keys.
func (env *tunnelEnv) serve(ln net.Listener) {
	cfg := env.serverConfig()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go env.handle(tls.Server(conn, cfg))
	}
}

func (env *tunnelEnv) handle(conn *tls.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return
	}
	if err := conn.Handshake(); err != nil {
		return
	}
	// Before it reads or sends anything, the relay checks TLS 1.3 and the ALPN protocol.
	if s := conn.ConnectionState(); !env.lenient && (s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != tunnelALPN) {
		return
	}
	frame, err := readFrame(conn)
	if err != nil {
		return
	}
	if _, _, err := frames.Control([]frames.Frame{{From: frames.Gateway, Data: frame}}); err != nil {
		return
	}
	_, _ = conn.Write(helloAckFrame)
}

func readFrame(r io.Reader) ([]byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	n := int(head[2])<<8 | int(head[3])
	if n > frames.MaxPayload {
		return nil, fmt.Errorf("payload length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return append(head, payload...), nil
}

// clientConfig is the configuration of a probe; the relay is authenticated by its pin.
func (env *tunnelEnv) clientConfig(t *testing.T, p tlsProbe, cache tls.ClientSessionCache) *tls.Config {
	t.Helper()
	version, ok := probeVersions[p.Client.Version]
	if !ok {
		t.Fatalf("%s: version %q", p.ID, p.Client.Version)
	}
	groups := make([]tls.CurveID, 0, len(p.Client.Groups))
	for _, g := range p.Client.Groups {
		id, ok := probeGroups[g]
		if !ok {
			t.Fatalf("%s: group %q", p.ID, g)
		}
		groups = append(groups, id)
	}
	cert, hasCert := env.certs[p.Client.Certificate]
	if !hasCert && p.Client.Certificate != "none" {
		t.Fatalf("%s: certificate %q", p.ID, p.Client.Certificate)
	}
	return &tls.Config{
		ServerName:         "tunnel.relay-operator.example",
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         version,
		CurvePreferences:   groups,
		NextProtos:         p.Client.ALPN,
		ClientSessionCache: cache,
		InsecureSkipVerify: true, // the relay is authenticated by its pin alone (section 6.8)
		VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			if sha256.Sum256(s.PeerCertificates[0].RawSubjectPublicKeyInfo) != env.pin {
				return errors.New("no stored pin matches")
			}
			return nil
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if !hasCert {
				return &tls.Certificate{}, nil
			}
			return &cert, nil
		},
	}
}

// probe opens one control connection and reports accepted, refused, or what else happened.
func probe(t *testing.T, addr string, cfg *tls.Config) string {
	t.Helper()
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return "refused"
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		t.Fatal(err)
	}
	s := conn.ConnectionState()
	if _, err := conn.Write(helloFrame); err != nil {
		return "refused"
	}
	frame, err := readFrame(conn)
	if err != nil {
		return "refused"
	}
	if _, at, err := frames.Control([]frames.Frame{{From: frames.Gateway, Data: helloFrame}, {From: frames.Relay, Data: frame}}); err != nil {
		return fmt.Sprintf("frame %d is an error: %v", at, err)
	}
	if s.Version != tls.VersionTLS13 || s.CurveID != tls.X25519MLKEM768 || s.NegotiatedProtocol != tunnelALPN || s.DidResume {
		return fmt.Sprintf("accepted with version %x, group %v, ALPN %q, resumed %v", s.Version, s.CurveID, s.NegotiatedProtocol, s.DidResume)
	}
	return "accepted"
}

// runProbes runs every probe against a server of env and returns the outcomes by id.
func runProbes(t *testing.T, env *tunnelEnv) (map[string]string, []tlsProbe) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go env.serve(ln)
	probes := loadCases[tlsProbe](t, "../../conformance/tls-v0.json")
	got := map[string]string{}
	for _, p := range probes {
		cfg := env.clientConfig(t, p, tls.NewLRUClientSessionCache(4))
		if p.Client.Resume {
			if first := probe(t, ln.Addr().String(), cfg); first != "accepted" && !env.lenient {
				t.Fatalf("%s: first connection: %s", p.ID, first)
			}
		}
		got[p.ID] = probe(t, ln.Addr().String(), cfg)
	}
	return got, probes
}

func TestTLSProbesAgainstAConformingServer(t *testing.T) {
	got, probes := runProbes(t, newTunnelEnv(t))
	seen := map[string]bool{}
	for _, p := range probes {
		if got[p.ID] != p.Expected {
			t.Errorf("%s (%s): %s, want %s", p.ID, p.Why, got[p.ID], p.Expected)
		}
		seen[p.Expected] = true
	}
	if !seen["accepted"] || !seen["refused"] {
		t.Error("the probes do not cover both results")
	}
}

// TestTLSProbesCatchALenientServer: against a server that allows TLS 1.2, every group, no
// client certificate, no ALPN check and session tickets, every probe that expects a refusal
// or offers resumption has another outcome, so that the probes tell the two apart.
func TestTLSProbesCatchALenientServer(t *testing.T) {
	env := newTunnelEnv(t)
	env.lenient = true
	got, probes := runProbes(t, env)
	for _, p := range probes {
		if (p.Expected == "refused" || p.Client.Resume) && got[p.ID] == p.Expected {
			t.Errorf("%s (%s): a lenient server also gives %s", p.ID, p.Why, p.Expected)
		}
	}
}

func TestPresentedRefusesWhatTheRelayMustRefuse(t *testing.T) {
	env := newTunnelEnv(t)
	if home, err := tunnelcert.Presented(env.certs["tunnel"].Certificate, env.roots, tlsTrust, time.Now()); err != nil || home != tlsHomeA {
		t.Fatalf("Presented = %q, %v", home, err)
	}
	for name, chain := range map[string][][]byte{
		"self-signed": env.certs["self-signed"].Certificate,
		"empty":       nil,
		"not DER":     {{0x30, 0x00}},
	} {
		if _, err := tunnelcert.Presented(chain, env.roots, tlsTrust, time.Now()); !errors.Is(err, tunnelcert.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := tunnelcert.Presented(env.certs["tunnel"].Certificate, env.roots, "other-operator.example", time.Now()); err == nil {
		t.Error("accepted a certificate of another trust domain")
	}
	if _, err := tunnelcert.Presented(env.certs["tunnel"].Certificate, env.roots, tlsTrust, time.Now().Add(2*time.Hour)); err == nil {
		t.Error("accepted an expired certificate")
	}
}
