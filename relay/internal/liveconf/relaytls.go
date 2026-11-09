// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/home-mandate/spec/relay/internal/tunnelcert"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

var (
	groupIDs = map[string]tls.CurveID{"X25519MLKEM768": tls.X25519MLKEM768, "x25519": tls.X25519, "secp256r1": tls.CurveP256}
	versions = map[string]uint16{"1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}
)

// key checks that the key the relay presents is one of relay_pins (RELAY-v0 sections 4.1 and
// 6.8). A relay whose key the gateway does not know is not played further.
func (rl *relayRun) key(ctx context.Context) error {
	cred := newest(rl.s.insts[0])
	p := rl.t.params(&cred.cert)
	p.Pins, p.AnyKey = nil, true
	ctl, err := rl.t.dialControl(ctx, p)
	if err != nil {
		if fatal := netProblem(err); fatal != nil {
			return fatal
		}
		rl.note(CheckRelayHello, "a TLS connection with a valid tunnel certificate was refused: "+esc(classify(err).kind))
		rl.stopped = true
		return nil
	}
	pin := ctl.Pin()
	ctl.Close()
	if !rl.pinIn(pin) {
		rl.note(CheckRelayKey, "the SHA-256 of the SubjectPublicKeyInfo of the relay's certificate is in no entry of relay_pins")
		rl.stopped = true
		return nil
	}
	rl.note(CheckRelayKey, "")
	return nil
}

// probeParams builds the parameters of a probe of tls-v0.json; false if the run has no
// certificate of the kind the probe needs.
func (rl *relayRun) probeParams(pr tlsProbe) (tunnelclient.Params, bool) {
	var cert *tls.Certificate
	switch pr.Client.Certificate {
	case "tunnel":
		cert = &newest(rl.s.insts[0]).cert
	case "tunnel-p256":
		cred := rl.p256()
		if cred == nil {
			return tunnelclient.Params{}, false
		}
		cert = &cred.cert
	case "self-signed":
		cert = selfSignedTunnel(rl.s.doc.TrustDomain, rl.s.insts[0].paired.Installation.HomeID)
	}
	p := rl.t.params(cert)
	p.MaxVersion = versions[pr.Client.Version]
	for _, g := range pr.Client.Groups {
		p.Curves = append(p.Curves, groupIDs[g])
	}
	p.ALPN = pr.Client.ALPN
	if pr.Client.Resume {
		p.Cache = tls.NewLRUClientSessionCache(2)
	}
	return p, true
}

// p256 returns a tunnel certificate of the run with a P-256 key.
func (rl *relayRun) p256() *tunnelCred {
	for _, inst := range rl.s.insts {
		for i := range credsOf(inst) {
			if inst.creds[i].p256 {
				return &inst.creds[i]
			}
		}
	}
	return nil
}

// selfSignedTunnel returns a self-signed certificate with the subject alternative name of a tunnel
// certificate of the home (the probe self-signed of tls-v0.json).
func selfSignedTunnel(trustDomain, home string) *tls.Certificate {
	_, key := must2(ed25519.GenerateKey(rand.Reader))
	san := must(tunnelcert.SANValue("spiffe://" + trustDomain + "/home/" + home + "/gateway"))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ExtraExtensions: sanExtension(san),
	}
	der := must(x509.CreateCertificate(rand.Reader, template, template, key.Public(), key))
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// probes plays the probes of tls-v0.json against the relay: the outcome of each is accepted (the
// relay answers hello with hello-ack on TLS 1.3, X25519MLKEM768 and hm-tunnel/1, without
// resumption) or refused. The probe unpaired is played after the unpairing.
func (rl *relayRun) probes(ctx context.Context) error {
	var problems []string
	for _, pr := range loadCases[tlsProbe](tlsFile) {
		if pr.Client.Certificate == "unpaired" {
			continue
		}
		p, ok := rl.probeParams(pr)
		if !ok {
			return nil
		}
		got, err := rl.runProbe(ctx, p, pr.Client.Resume)
		if err != nil {
			return err
		}
		if got != pr.Expected {
			problems = append(problems, fmt.Sprintf("%s: %s, want %s", pr.ID, got, pr.Expected))
		}
	}
	rl.note(CheckRelayTLS, strings.Join(problems[:min(len(problems), maxProblems)], ", "))
	return nil
}

// runProbe opens a control connection with the parameters and reports the outcome; with resume it
// first opens one that is accepted and then offers its session again.
func (rl *relayRun) runProbe(ctx context.Context, p tunnelclient.Params, resume bool) (string, error) {
	if resume {
		if first, err := rl.probe(ctx, p); err != nil || first != "accepted" {
			return first, err
		}
	}
	return rl.probe(ctx, p)
}

// probe opens one control connection and tells what the relay does.
func (rl *relayRun) probe(ctx context.Context, p tunnelclient.Params) (string, error) {
	ctl, err := rl.t.dialControl(ctx, p)
	if err != nil {
		return "refused", netProblem(err)
	}
	defer ctl.Close()
	if err := rl.t.hello(ctx, ctl); err != nil {
		return "refused", ctxProblem(ctx)
	}
	_, err = ctl.Recv(rl.t.timing.Tunnel)
	var relayErr *tunnelclient.RelayError
	switch {
	case errors.Is(err, tunnelclient.ErrTimeout):
		return "no answer", nil
	case errors.Is(err, tunnelclient.ErrClosed):
		return "refused", nil
	case errors.As(err, &relayErr):
		return fmt.Sprintf("error %d", relayErr.Code), nil
	}
	// A hello-ack, valid or not: what the probe asks is whether the relay serves the connection;
	// the check hello judges the frame.
	s := ctl.State()
	if s.Version != tls.VersionTLS13 || s.CurveID != tls.X25519MLKEM768 || s.NegotiatedProtocol != tunnelclient.ALPN || s.DidResume {
		return fmt.Sprintf("accepted with TLS %x, group %v, protocol %s, resumed %t", s.Version, s.CurveID, esc(s.NegotiatedProtocol), s.DidResume), nil
	}
	return "accepted", nil
}

// ctxProblem returns the error of a run that ended, nil if the context is alive.
func ctxProblem(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return incompleteFor(err)
	}
	return nil
}

// hello checks that the relay sends nothing before hello and answers it with a valid hello-ack
// (RELAY-v0 section 4.4).
func (rl *relayRun) hello(ctx context.Context) error {
	cred := newest(rl.s.insts[0])
	ctl, err := rl.t.dialControl(ctx, rl.t.params(&cred.cert))
	if err != nil {
		return netProblem(err)
	}
	defer ctl.Close()
	if events, closed := ctl.Drain(rl.t.timing.Slack); len(events) > 0 || closed {
		rl.note(CheckRelayHello, "the relay sent a frame or closed the connection before hello")
		return nil
	}
	if err := rl.t.hello(ctx, ctl); err != nil {
		return ctxProblem(ctx)
	}
	_, err = ctl.Recv(rl.t.timing.Tunnel)
	rl.note(CheckRelayHello, ackProblem(err))
	return nil
}

// ackProblem says what is wrong with the answer to hello, "" if it is a valid hello-ack.
func ackProblem(err error) string {
	var relayErr *tunnelclient.RelayError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, tunnelclient.ErrTimeout):
		return "no hello-ack within the time of section 4.4"
	case errors.Is(err, tunnelclient.ErrClosed):
		return "the relay closed the connection after hello"
	case errors.As(err, &relayErr):
		return fmt.Sprintf("the relay answered hello with error %d", relayErr.Code)
	}
	return "the hello-ack breaks the rules of section 4.4: " + esc(err.Error())
}

// sanExtension is the critical subject alternative name extension with the value.
func sanExtension(value []byte) []pkix.Extension {
	return []pkix.Extension{{Id: oidSAN, Critical: true, Value: value}}
}
