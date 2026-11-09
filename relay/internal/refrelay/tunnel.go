// SPDX-License-Identifier: Apache-2.0

package refrelay

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/tunnelcert"
)

// Frame types that tell the two kinds of tunnel connection apart (section 4.2).
const (
	typeHello    = 0x0001
	typeDataBind = 0x0020
	typePins     = 0x0014
)

var errDenied = errors.New("refrelay: certificate denied")

// identity is the installation of a tunnel connection and the certificate it presented.
type identity struct {
	home, serial string
	notBefore    time.Time
}

// tlsConfig is the configuration for tunnel connections (sections 4.1 and 4.2) with the
// defects of the relay.
func (r *Relay) tlsConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		Certificates:           []tls.Certificate{r.listed},
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{ALPN},
		SessionTicketsDisabled: !r.has(Resumption),
		VerifyConnection:       r.verifyConnection,
	}
	if r.has(KeyNotPinned) {
		cfg.Certificates = []tls.Certificate{r.other}
	}
	if r.has(TLS12) {
		cfg.MinVersion = tls.VersionTLS12
		cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
	}
	if r.has(GroupX25519) {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.X25519MLKEM768}
	}
	return cfg
}

// verifyConnection applies sections 4.1 and 4.2 before anything is read or sent: TLS 1.3, the
// ALPN protocol, and the tunnel certificate of an installation that is not denied.
func (r *Relay) verifyConnection(cs tls.ConnectionState) error {
	if !r.has(TLS12) && cs.Version != tls.VersionTLS13 {
		return errors.New("refrelay: not TLS 1.3")
	}
	if cs.NegotiatedProtocol != ALPN {
		return errors.New("refrelay: no hm-tunnel/1")
	}
	id, err := r.identify(cs)
	if err != nil {
		return err
	}
	if !r.has(NoDenylist) && (r.reg.Denied(id.serial) || !r.reg.Active(id.home)) {
		return errDenied
	}
	return nil
}

// identify checks the certificate of the gateway and returns its identity.
func (r *Relay) identify(cs tls.ConnectionState) (identity, error) {
	chain := make([][]byte, len(cs.PeerCertificates))
	for i, c := range cs.PeerCertificates {
		chain[i] = c.Raw
	}
	home, err := tunnelcert.Presented(chain, r.reg.Roots(), r.reg.TrustDomain(), time.Now())
	if err != nil {
		return identity{}, err
	}
	leaf := cs.PeerCertificates[0]
	return identity{home: home, serial: hex.EncodeToString(leaf.SerialNumber.Bytes()), notBefore: leaf.NotBefore}, nil
}

// handle reads the server name and passes the connection on. It returns true if the
// connection is an agent connection that was kept.
func (r *Relay) handle(c net.Conn) bool {
	pc := newReplayConn(c)
	var claimed netip.AddrPort
	if r.has(AgentProxyHeader) {
		claimed, _ = pc.takeProxyHeader()
	}
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	name, err := pc.serverName()
	if err != nil {
		return false
	}
	_ = c.SetReadDeadline(time.Time{})
	if strings.EqualFold(name, r.cfg.Host) {
		pc.rewind()
		r.tunnel(pc)
		return false
	}
	pc.release()
	return r.agent(pc, name, claimed)
}

// tunnel completes the handshake, reads the first frame and tells control from data.
func (r *Relay) tunnel(pc *replayConn) {
	tc := tls.Server(pc, r.tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(frameTimeout))
	if tc.Handshake() != nil {
		return
	}
	id, err := r.identify(tc.ConnectionState())
	if err != nil {
		return
	}
	r.mu.Lock()
	r.live[tc] = id
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.live, tc)
		r.mu.Unlock()
		_ = tc.Close()
	}()
	first, err := frames.ReadFrame(tc)
	if err != nil {
		r.refuse(tc)
		return
	}
	_ = tc.SetDeadline(time.Time{})
	switch binary.BigEndian.Uint16(first) {
	case typeHello:
		r.control(tc, first, id)
	case typeDataBind:
		r.data(tc, first, id)
	default:
		r.refuse(tc)
	}
}
