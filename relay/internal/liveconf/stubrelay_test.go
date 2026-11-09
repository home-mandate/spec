// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/refop"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

// serveStub starts a relay of this test only: it speaks TLS as section 4.2 says, accepts every
// client certificate, and lets serve decide what to do with each connection. It returns its address
// and its pin.
func serveStub(t *testing.T, serve func(*tls.Conn)) (addr, pin string) {
	t.Helper()
	return serveStubWith(t, func(*tls.Config) {}, serve)
}

// serveStubWith is serveStub with a change of the TLS configuration.
func serveStubWith(t *testing.T, change func(*tls.Config), serve func(*tls.Conn)) (addr, pin string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{tunnelclient.ALPN}, ClientAuth: tls.RequestClientCert,
	}
	change(cfg)
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				if tc := c.(*tls.Conn); tc.Handshake() == nil {
					serve(tc)
				}
			}()
		}
	}()
	return l.Addr().String(), base64.RawURLEncoding.EncodeToString(sum[:])
}

// runAgainstStub runs the class relay against a reference operator whose metadata names the stub
// as its relay.
func runAgainstStub(t *testing.T, serve func(*tls.Conn)) Result {
	t.Helper()
	return runAgainstStubWith(t, func(*tls.Config) {}, serve)
}

func runAgainstStubWith(t *testing.T, change func(*tls.Config), serve func(*tls.Conn)) Result {
	t.Helper()
	addr, pin := serveStubWith(t, change, serve)
	base := refop.New(refop.Config{})
	var doc map[string]any
	if err := json.Unmarshal(base.Metadata(), &doc); err != nil {
		t.Fatal(err)
	}
	base.Close()
	doc["relay_pins"] = []string{pin}
	data, _ := json.Marshal(doc)
	r, env := serve2(t, refop.Config{Document: data})
	real := env.Net.Remap
	env.Net.Remap = func(hostport string) string {
		if isRelayDial(hostport) {
			return addr
		}
		return real(hostport)
	}
	env.Timing.Tunnel, env.Timing.Close = 300*time.Millisecond, 300*time.Millisecond
	set := enrollSettings(t, r, ClassRelay)
	set.OwnDomain, set.DNSHook = "", ""
	return RunWith(ctx(t), set, env)
}

// serve2 is serve with the real unpairing and no pacing.
func serve2(t *testing.T, cfg refop.Config) (*refop.Running, Env) {
	t.Helper()
	r, env := serve(t, cfg)
	env.Timing.Gap, env.Timing.Jitter = 0, 0
	env.Unpair = unpairInstallation
	return r, env
}

func readHello(c *tls.Conn) bool {
	_, err := frames.ReadFrame(c)
	return err == nil
}

// TestARelayThatMisbehavesInOtherWaysFailsTheChecksItBreaks: relays that the reference does not
// show: one that closes after the handshake, one that answers hello with an error, one that never
// answers, one that acknowledges everything and does nothing else.
func TestARelayThatMisbehavesInOtherWaysFailsTheChecksItBreaks(t *testing.T) {
	ack := must(frames.HelloAck{Version: 1, Software: "stub", Heartbeat: 30, MaxStreams: 8}.Encode())
	for name, tt := range map[string]struct {
		serve func(*tls.Conn)
		want  []string
	}{
		"closes after the handshake": {func(*tls.Conn) {}, []string{CheckRelayTLS, CheckRelayHello, CheckRelayFrames}},
		"answers hello with an error": {func(c *tls.Conn) {
			if readHello(c) {
				e, _ := frames.EncodeError(frames.CodeLimitExceeded, "no")
				_, _ = c.Write(e)
			}
		}, []string{CheckRelayTLS, CheckRelayHello, CheckRelayFrames}},
		"never answers": {func(c *tls.Conn) { _, _ = io.Copy(io.Discard, c) }, []string{CheckRelayTLS, CheckRelayHello, CheckRelayFrames}},
		"acknowledges everything": {func(c *tls.Conn) {
			if readHello(c) {
				_, _ = c.Write(ack)
				_, _ = io.Copy(io.Discard, c)
			}
		}, []string{CheckRelaySession, CheckRelayRouting, CheckRelayStream}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res := runAgainstStub(t, tt.serve)
			got := map[string]bool{}
			for _, f := range res.Report.Failures {
				got[f.ID] = true
			}
			for _, id := range tt.want {
				if !got[id] {
					t.Errorf("%s did not fail; failures %v", id, failureIDs(res))
				}
			}
			if res.Exit != ExitFails && res.Exit != ExitIncomplete {
				t.Errorf("exit %d (%s)", res.Exit, res.Message)
			}
			if res.Report.Installations.Created != res.Report.Installations.Unpaired || !slices.Contains([]int{ExitFails, ExitIncomplete}, res.Exit) {
				t.Errorf("installations %+v", res.Report.Installations)
			}
		})
	}
}

// TestARelayThatCannotDoTLS13OrIsNotThere: no TLS 1.3 with X25519MLKEM768 fails the check hello and
// stops the class; a relay that is not in the metadata leaves the class unplayed and skipped.
func TestARelayThatCannotDoTLS13OrIsNotThere(t *testing.T) {
	res := runAgainstStubWith(t, func(c *tls.Config) {
		c.MinVersion, c.MaxVersion, c.CurvePreferences = tls.VersionTLS12, tls.VersionTLS12, []tls.CurveID{tls.X25519}
	}, func(*tls.Conn) {})
	if ids := failureIDs(res); !slices.Equal(ids, []string{CheckRelayHello}) {
		t.Errorf("failures %v", ids)
	}
	base := refop.New(refop.Config{})
	var doc map[string]any
	if err := json.Unmarshal(base.Metadata(), &doc); err != nil {
		t.Fatal(err)
	}
	base.Close()
	doc["relay"] = map[string]any{"host": "tunnel." + refop.DefaultOperator}
	data, _ := json.Marshal(doc)
	r, env := serve2(t, refop.Config{Document: data})
	set := enrollSettings(t, r, ClassRelay)
	set.OwnDomain, set.DNSHook = "", ""
	res = RunWith(ctx(t), set, env)
	if c := res.Report.Classes[ClassRelay]; c.Conforms || c.Cases == 0 || c.Skipped != c.Cases || len(res.Report.Failures) != 0 {
		t.Errorf("class relay %+v, failures %v", c, failureIDs(res))
	}
}
