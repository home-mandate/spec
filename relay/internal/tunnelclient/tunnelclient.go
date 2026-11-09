// SPDX-License-Identifier: Apache-2.0

// Package tunnelclient is the side of the tunnel protocol (RELAY-v0 section 4) that the live
// test tool plays: the gateway, with TLS 1.3, the key exchange group X25519MLKEM768, the
// relay's pins, a control connection and data connections, and the agent, with a ClientHello
// that carries a server name and a reader of the PROXY header. Every connection goes through
// the address filter of netguard.
package tunnelclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ALPN is the application protocol of tunnel connections (section 4.2).
const ALPN = "hm-tunnel/1"

// PinSize is the size of a pin.
const PinSize = sha256.Size

// Pin is the SHA-256 digest of the SubjectPublicKeyInfo of a relay's certificate (section 6.8).
type Pin [PinSize]byte

// ErrPin is returned when the relay's key matches no stored pin.
var ErrPin = errors.New("tunnelclient: no stored pin matches")

// ParsePin reads a pin as it stands in relay_pins: base64url without padding.
func ParsePin(s string) (Pin, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != PinSize {
		return Pin{}, fmt.Errorf("tunnelclient: not a pin")
	}
	return Pin(raw), nil
}

// PinOf returns the pin of a certificate.
func PinOf(c *x509.Certificate) Pin { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// Dialer opens connections; netguard.Dialer is one.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Params are the TLS parameters of a tunnel connection. The zero value, with ServerName and
// Pins, is a gateway as section 4.2 describes it; the probes of tls-v0.json change them.
type Params struct {
	// ServerName is relay.host.
	ServerName string
	// Pins are the stored pins; the relay is accepted only if its key matches one.
	Pins []Pin
	// AnyKey accepts any key of the relay; the caller reads it from Conn.Pin.
	AnyKey bool
	// Cert is the tunnel certificate; nil means none.
	Cert *tls.Certificate
	// MaxVersion is the highest TLS version offered; zero means TLS 1.3.
	MaxVersion uint16
	// Curves are the key exchange groups offered; nil means X25519MLKEM768 alone.
	Curves []tls.CurveID
	// ALPN are the protocols offered; nil means hm-tunnel/1, an empty list none.
	ALPN []string
	// Cache lets the connection resume a session; nil means no resumption.
	Cache tls.ClientSessionCache
}

func (p Params) config(pin *Pin) *tls.Config {
	version := p.MaxVersion
	if version == 0 {
		version = tls.VersionTLS13
	}
	curves := p.Curves
	if curves == nil {
		curves = []tls.CurveID{tls.X25519MLKEM768}
	}
	protocols := p.ALPN
	if protocols == nil {
		protocols = []string{ALPN}
	}
	return &tls.Config{
		ServerName: p.ServerName, MinVersion: tls.VersionTLS12, MaxVersion: version,
		CurvePreferences: curves, NextProtos: protocols, ClientSessionCache: p.Cache,
		// The relay is authenticated by its pins alone, not by a chain, a validity period or a
		// name (section 4.1).
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			// A TLS client has refused a server without a certificate before it gets here.
			*pin = PinOf(cs.PeerCertificates[0])
			if p.AnyKey || containsPin(p.Pins, *pin) {
				return nil
			}
			return ErrPin
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if p.Cert == nil {
				return &tls.Certificate{}, nil
			}
			return p.Cert, nil
		},
	}
}

func containsPin(list []Pin, pin Pin) bool {
	for _, p := range list {
		if p == pin {
			return true
		}
	}
	return false
}

// Conn is a tunnel connection.
type Conn struct {
	*tls.Conn
	// Pin is the pin of the relay's key.
	Pin Pin

	tap *recordTap
}

// alertRecordLen is the length of the TLS 1.3 record of a close_notify alert: two bytes of
// alert, the content type and the 16 bytes of the authentication tag.
const alertRecordLen = 2 + 1 + 16

// recordTap follows the TLS records that come in on a connection and keeps the length of the
// last one. Go's TLS client reports the end of a stream at a record boundary as io.EOF whether or
// not close_notify came before it, so this is how the tool tells the two apart (section 4.5).
type recordTap struct {
	net.Conn
	mu      sync.Mutex
	header  []byte
	skip    int
	lastLen int
}

func (t *recordTap) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range p[:n] {
		t.feed(b)
	}
	return n, err
}

// feed takes one byte of the stream: five bytes of record header, then the record.
func (t *recordTap) feed(b byte) {
	if t.skip > 0 {
		t.skip--
		return
	}
	t.header = append(t.header, b)
	if len(t.header) == recordHeaderLen {
		t.lastLen = int(t.header[3])<<8 | int(t.header[4])
		t.skip = t.lastLen
		t.header = t.header[:0]
	}
}

const recordHeaderLen = 5

// ClosedWithNotify reports whether the last TLS record that came in has the length of a
// close_notify alert of TLS 1.3. It is meant for use after Read has returned io.EOF, with
// application data whose records are not of this length.
func (c *Conn) ClosedWithNotify() bool {
	c.tap.mu.Lock()
	defer c.tap.mu.Unlock()
	return c.tap.lastLen == alertRecordLen
}

// handshakeTimeout bounds the TLS handshake of one connection, so that a relay that accepts the
// connection and stays silent cannot hold the run.
const handshakeTimeout = 10 * time.Second

// Dial opens a connection to address and completes the TLS handshake within ctx and
// handshakeTimeout. The first write of DialData follows the handshake and has its own deadline.
func Dial(ctx context.Context, d Dialer, address string, p Params) (*Conn, error) {
	raw, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	c := &Conn{tap: &recordTap{Conn: raw}}
	c.Conn = tls.Client(c.tap, p.config(&c.Pin))
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := c.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	return c, nil
}

// Closed reports whether err says that the other side closed the connection: the end of the
// stream, a reset or a TLS alert; a deadline is not a close.
func Closed(err error) bool {
	if err == nil {
		return false
	}
	var nerr net.Error
	return !(errors.As(err, &nerr) && nerr.Timeout()) && !errors.Is(err, context.DeadlineExceeded)
}

// ErrHandshake is returned for a connection that was made but whose TLS handshake failed: the
// relay is there, and refuses or cannot serve these parameters.
var ErrHandshake = errors.New("tunnelclient: handshake failed")

// ErrTimeout is returned when the other side did not answer in time.
var ErrTimeout = errors.New("tunnelclient: timeout")

// setDeadline sets the deadline of a connection for wait; zero means none.
func setDeadline(c net.Conn, wait time.Duration) {
	if wait == 0 {
		_ = c.SetReadDeadline(time.Time{})
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(wait))
}
