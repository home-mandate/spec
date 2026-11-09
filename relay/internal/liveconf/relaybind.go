// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

const (
	// tailBytes is what an agent sends after its ClientHello, and replyBytes what the gateway
	// answers; neither makes a TLS record of the length of a close_notify.
	tailBytes  = 64
	replyBytes = 300
	// handshakeRecord is the first byte of a TLS handshake record, which an agent must not
	// get back from a relay that closes it; alertRecord is the first byte of an alert, which a
	// relay may send.
	handshakeRecord = 0x16
	// claimedSource is the address an agent claims in a PROXY header it sends.
	claimedSource = "9.9.9.9:4545"
)

var claimedDestination = netip.MustParseAddrPort("192.0.2.1:443")

// closedProblem judges an agent connection that has to end without a TLS handshake: it says what
// is wrong, "" if the relay closed it.
func closedProblem(got routed) string {
	switch {
	case got.opened:
		return "the relay sent a stream-open"
	case len(got.bytes) > 0 && got.bytes[0] == handshakeRecord:
		return "the relay answered with a TLS handshake"
	case !got.closed:
		return "the relay kept the connection open"
	}
	return ""
}

// mixedCase writes every other letter of a name in upper case.
func mixedCase(name string) string {
	out := []byte(name)
	for i := range out {
		if i%2 == 0 && out[i] >= 'a' && out[i] <= 'z' {
			out[i] -= 'a' - 'A'
		}
	}
	return string(out)
}

// token opens an agent connection for the name and waits for the stream-open on the control
// connection; the agent connection comes back, open.
func (rl *relayRun) token(ctx context.Context, ctl *tunnelclient.Control, sni string) (net.Conn, tunnelclient.Open, string, error) {
	agent, err := rl.t.dialAgent(ctx, tunnelclient.ClientHello(sni))
	if err != nil {
		return nil, tunnelclient.Open{}, "", netProblem(err)
	}
	got := await(ctx, ctl, agent, rl.t.timing.Tunnel)
	if !got.opened {
		_ = agent.Close()
		return nil, tunnelclient.Open{}, "the relay sent no stream-open for the standard name", ctxProblem(ctx)
	}
	return agent, got.open, "", nil
}

// routing checks the routing of agent connections by name (RELAY-v0 sections 4.5 and 6.1): the
// standard name, without regard to case, and names that are closed without a TLS handshake.
func (rl *relayRun) routing(ctx context.Context) error {
	a := rl.s.insts[0]
	var problems []string
	for name, sni := range map[string]string{"the standard name": stdName(a), "the standard name in mixed case": mixedCase(stdName(a))} {
		agent, open, problem, err := rl.token(ctx, rl.sa, sni)
		if err != nil {
			return err
		}
		if problem != "" {
			problems = append(problems, name+": "+problem)
			continue
		}
		_ = rl.sa.StreamClose(open.Token, frames.ReasonRefused)
		_ = agent.Close()
	}
	negatives := []struct{ name, sni string }{
		{"a name that is not served", "unknown-" + randomLabel() + "." + rl.s.doc.NameDomain},
		{"no server name", ""},
	}
	if b := rl.s.insts[1]; b != nil {
		negatives = append(negatives, struct{ name, sni string }{"an installation without a control connection", stdName(b)})
	}
	for _, n := range negatives {
		if p, err := rl.closedAgent(ctx, n.sni); err != nil {
			return err
		} else if p != "" {
			problems = append(problems, n.name+": "+p)
		}
	}
	rl.note(CheckRelayRouting, strings.Join(problems, "; "))
	return nil
}

func randomLabel() string {
	raw := make([]byte, 5)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

// closedAgent connects as an agent with the name and says what is wrong with the relay's
// treatment of a connection that has to be closed.
func (rl *relayRun) closedAgent(ctx context.Context, sni string) (string, error) {
	agent, err := rl.t.dialAgent(ctx, tunnelclient.ClientHello(sni))
	if err != nil {
		return "", netProblem(err)
	}
	defer agent.Close()
	return closedProblem(await(ctx, rl.sa, agent, rl.t.timing.Close)), ctxProblem(ctx)
}

// ownPending checks that the own-domain name is not routed while it is pending (RELAY-v0 section 6.4).
func (s *script) relayOwnPending(ctx context.Context, own string) error {
	rl := s.rl
	if rl == nil || rl.stopped {
		return nil
	}
	p, err := rl.closedAgent(ctx, own)
	if err != nil {
		return err
	}
	if p != "" {
		rl.addProblem(CheckRelayRouting, "the own-domain name while it is pending: "+p)
	}
	rl.reached[CheckRelayRouting] = true
	return nil
}

// relayOwnVerified checks that the own-domain name is routed once it is verified.
func (s *script) relayOwnVerified(ctx context.Context, own string) error {
	rl := s.rl
	if rl == nil || rl.stopped {
		return nil
	}
	agent, open, problem, err := rl.token(ctx, rl.sa, own)
	if err != nil {
		return err
	}
	if problem != "" {
		rl.addProblem(CheckRelayRouting, "the verified own-domain name: "+problem)
	} else {
		_ = rl.sa.StreamClose(open.Token, frames.ReasonRefused)
		_ = agent.Close()
	}
	rl.reached[CheckRelayRouting] = true
	return nil
}

// addProblem adds a problem to a check that is judged at the end of the run.
func (rl *relayRun) addProblem(id, problem string) {
	if len(rl.problems[id]) < maxProblems {
		rl.problems[id] = append(rl.problems[id], clean(problem))
	}
}

// observeBound reads what a relay does with a data connection: it binds it (the first bytes are
// the signature of a PROXY header) or closes it. sent counts the bytes it sent before it closed.
func observeBound(d net.Conn, wait time.Duration) (bound, closed bool, sent int) {
	seen := tunnelclient.Observe(d, wait, proxySignatureLen)
	return tunnelclient.IsProxySignature(seen.Bytes), seen.Closed, len(seen.Bytes)
}

// proxySignatureLen is the length of the signature that opens a PROXY header.
const proxySignatureLen = 12

// bindResult is what a case of binding-v0.json found.
type bindResult struct {
	skipped bool
	problem string
	// noisy is set if the relay sent bytes before it closed the connection.
	noisy bool
}

// binding plays the cases of binding-v0.json that a live test can play (RELAY-v0 section 4.5):
// the case that needs a limit of the installation (b07) and the case that is a hello on the wire
// (b09, which a relay takes for a control connection) cannot be played, and the case whose data
// connection has a later notBefore than the control connection (b16) is played with the control
// connection of the older certificate.
func (rl *relayRun) binding(ctx context.Context) error {
	var problems []string
	noisy := false
	for _, c := range loadCases[bindingCase](bindingFile) {
		res, err := rl.bindCase(ctx, c)
		if err != nil {
			return err
		}
		if res.skipped {
			continue
		}
		if res.problem != "" {
			problems = append(problems, c.ID+": "+res.problem)
		}
		noisy = noisy || res.noisy
	}
	rl.note(CheckRelayBinding, strings.Join(problems[:min(len(problems), maxProblems)], ", "))
	rl.note(CheckRelaySilent, onlyIf(noisy, "the relay sent a byte before it closed a data connection"))
	return nil
}

// bindCase plays one case.
func (rl *relayRun) bindCase(ctx context.Context, c bindingCase) (bindResult, error) {
	first := must(hex.DecodeString(c.FirstBytes))
	if c.LimitReached || first[1] == 1 {
		return bindResult{skipped: true}, nil
	}
	switch {
	case c.Connection.NotBefore < c.ControlNotBefore:
		if rl.olderCred == nil {
			return bindResult{skipped: true}, nil
		}
		return rl.present(ctx, c, first, rl.sa, rl.olderCred)
	case c.Connection.NotBefore > c.ControlNotBefore:
		return rl.bindLater(ctx, c, first)
	}
	return rl.present(ctx, c, first, rl.sa, rl.saCred)
}

// ownToken finds the token of the case that the first bytes carry and returns its state, the
// installation that holds it and its bytes; the state is "" if the bytes are no token of the case,
// and the bytes are then those of the open token of the case's own installation, which the other
// first bytes of the case were made from.
func ownToken(c bindingCase, first []byte) (state, owner string, token []byte) {
	if len(first) >= 4+frames.TokenSize {
		payload := hex.EncodeToString(first[4 : 4+frames.TokenSize])
		for _, t := range c.Tokens {
			if t.Token == payload {
				return t.State, t.Installation, must(hex.DecodeString(t.Token))
			}
		}
	}
	for _, t := range c.Tokens {
		if t.State == "open" && t.Installation == c.Connection.Installation {
			return "", "", must(hex.DecodeString(t.Token))
		}
	}
	return "", "", make([]byte, frames.TokenSize)
}

// present plays a case on a data connection with the certificate, the token being one of the
// control connection ctl (or of the second installation's, or the used one): the live token takes
// the place of the token of the case, and the outcome is compared with the case.
func (rl *relayRun) present(ctx context.Context, c bindingCase, first []byte, ctl *tunnelclient.Control, cred *tunnelCred) (bindResult, error) {
	state, owner, reference := ownToken(c, first)
	foreign := state == "open" && owner != c.Connection.Installation
	var token [frames.TokenSize]byte
	if state == "used" {
		token = rl.used
	} else {
		holder, inst := ctl, rl.s.insts[0]
		if foreign {
			holder, inst = rl.ensureB(ctx), rl.s.insts[1]
		}
		if holder == nil {
			return bindResult{skipped: true}, ctxProblem(ctx)
		}
		agent, open, problem, err := rl.token(ctx, holder, stdName(inst))
		if err != nil || problem != "" {
			return bindResult{problem: problem}, err
		}
		defer agent.Close()
		token = open.Token
		rl.age(state, holder, agent, open)
	}
	res, bound, err := rl.judge(ctx, c, substitute(first, reference, token[:]), cred)
	if err != nil {
		return res, err
	}
	if bound && state == "open" {
		rl.used = token
	}
	if res.problem == "" && !bound {
		res.problem, err = rl.consumed(ctx, c, state, foreign, token)
	}
	return res, err
}

// age brings a fresh token into the state of the case: withdrawn by stream-close, or expired.
// The relay closes the agent connection of a token that became void; that tells the tool the
// state is reached.
func (rl *relayRun) age(state string, ctl *tunnelclient.Control, agent net.Conn, open tunnelclient.Open) {
	switch state {
	case "withdrawn":
		_ = ctl.StreamClose(open.Token, frames.ReasonRefused)
		tunnelclient.Observe(agent, rl.t.timing.Close, 1)
	case "expired":
		tunnelclient.Observe(agent, time.Duration(open.ValidityMS)*time.Millisecond+rl.t.timing.Slack, 1)
	}
}

// judge opens the data connection, sends the first bytes and compares the outcome with the case.
func (rl *relayRun) judge(ctx context.Context, c bindingCase, first []byte, cred *tunnelCred) (bindResult, bool, error) {
	d, err := rl.t.dialData(ctx, &cred.cert, first)
	if err != nil {
		return bindResult{}, false, netProblem(err)
	}
	defer d.Close()
	bound, closed, sent := observeBound(d, rl.t.timing.Close)
	res := bindResult{noisy: closed && !bound && sent > 0}
	switch {
	case bound != (c.Expected == "bound"):
		res.problem = fmt.Sprintf("%s, want %s", map[bool]string{true: "bound", false: "closed"}[bound], c.Expected)
	case !bound && !closed:
		res.problem = "the relay kept the connection open"
	}
	return res, bound, nil
}

// consumed checks after a refused case what the case says about the token: the token of another
// installation is void for its own installation too (the case lists it), and an untouched token
// of the control connection still binds (the case lists no token).
func (rl *relayRun) consumed(ctx context.Context, c bindingCase, state string, foreign bool, token [frames.TokenSize]byte) (string, error) {
	switch {
	case foreign && c.Consumed != nil && len(*c.Consumed) == 1:
		return rl.bindOnce(ctx, newest(rl.s.insts[1]), token, false, "the token of another installation is still good for its own installation")
	case !foreign && c.Consumed != nil && len(*c.Consumed) == 0 && (state == "" || state == "open"):
		return rl.bindOnce(ctx, rl.saCred, token, true, "a refused first frame consumed the token")
	}
	return "", nil
}

// bindOnce presents a token with the certificate; the problem is returned if the outcome is not
// the wanted one.
func (rl *relayRun) bindOnce(ctx context.Context, cred *tunnelCred, token [frames.TokenSize]byte, wantBound bool, problem string) (string, error) {
	d, err := rl.t.dialData(ctx, &cred.cert, frames.EncodeDataBind(token))
	if err != nil {
		return "", netProblem(err)
	}
	defer d.Close()
	if bound, _, _ := observeBound(d, rl.t.timing.Close); bound != wantBound {
		return problem, nil
	}
	return "", nil
}

// ensureB opens the control connection of the second installation, once; nil if there is none.
func (rl *relayRun) ensureB(ctx context.Context) *tunnelclient.Control {
	if rl.sb != nil || rl.s.insts[1] == nil {
		return rl.sb
	}
	o, err := rl.openSession(ctx, &newest(rl.s.insts[1]).cert)
	if err != nil || o.ctl == nil || o.code != 0 {
		if o.ctl != nil {
			o.ctl.Close()
		}
		return nil
	}
	rl.sb = o.ctl
	return rl.sb
}

// bindLater plays the case whose data connection has a later notBefore than the control
// connection: the control connection is the one of the older certificate, opened after the first
// one was closed, and afterwards the newer one takes its place again.
func (rl *relayRun) bindLater(ctx context.Context, c bindingCase, first []byte) (bindResult, error) {
	if rl.olderCred == nil {
		return bindResult{skipped: true}, nil
	}
	current, older := rl.saCred, rl.olderCred
	rl.sa.Close()
	ctl, problem, err := rl.reopen(ctx, older)
	if ctl == nil {
		return bindResult{problem: problem}, err
	}
	res, err := rl.present(ctx, c, first, ctl, current)
	// The control connection of the newer certificate replaces the older one again.
	if o, oerr := rl.openSession(ctx, &current.cert); oerr == nil && o.ctl != nil && o.code == 0 {
		ctl.Close()
		rl.sa = o.ctl
	} else {
		rl.sa = ctl
	}
	return res, err
}

// reopen opens a control connection after another of the installation was closed: the relay may
// need a moment to see the close, and answers session-exists until then.
func (rl *relayRun) reopen(ctx context.Context, cred *tunnelCred) (*tunnelclient.Control, string, error) {
	deadline := time.Now().Add(rl.t.timing.Close)
	for {
		o, err := rl.openSession(ctx, &cred.cert)
		if err != nil {
			return nil, "", err
		}
		if o.ctl != nil && o.code == 0 {
			return o.ctl, "", nil
		}
		if o.ctl != nil {
			o.ctl.Close()
		}
		if o.ctl == nil || time.Now().After(deadline) {
			return nil, "the relay holds a control connection that was closed", nil
		}
		if err := sleep(ctx, pollInterval); err != nil {
			return nil, "", incompleteFor(err)
		}
	}
}

// stream checks the PROXY header, the bytes of an agent, and the end of each direction on a bound
// data connection (RELAY-v0 sections 4.5 and 4.6).
func (rl *relayRun) stream(ctx context.Context) error {
	hello := tunnelclient.ClientHello(stdName(rl.s.insts[0]))
	tail := make([]byte, tailBytes)
	_, _ = rand.Read(tail)
	agent, err := rl.t.dialAgent(ctx, hello, tail)
	if err != nil {
		return netProblem(err)
	}
	defer agent.Close()
	got := await(ctx, rl.sa, agent, rl.t.timing.Tunnel)
	if !got.opened {
		rl.note(CheckRelayStream, "the relay sent no stream-open for the standard name")
		return ctxProblem(ctx)
	}
	d, err := rl.t.dialData(ctx, &rl.saCred.cert, frames.EncodeDataBind(got.open.Token))
	if err != nil {
		return netProblem(err)
	}
	defer d.Close()
	_ = d.SetReadDeadline(time.Now().Add(rl.t.timing.Tunnel))
	proxy, perr := tunnelclient.ReadPROXY(d)
	rl.note(CheckRelayProxy, proxyProblem(perr))
	if perr != nil && !errors.Is(perr, tunnelclient.ErrProxyContent) {
		rl.note(CheckRelayStream, "no PROXY header, so the stream cannot be read")
		return nil
	}
	_ = proxy
	rl.note(CheckRelayStream, rl.passBytes(agent, d, append(append([]byte{}, hello...), tail...)))
	return nil
}

// proxyProblem says what is wrong with the PROXY header, "" if it is as section 4.6 says.
func proxyProblem(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, tunnelclient.ErrProxyContent):
		return "the PROXY header has addresses that section 4.6 does not allow: " + esc(err.Error())
	case errors.Is(err, tunnelclient.ErrProxyFraming):
		return "the PROXY header is not of the form of section 4.6"
	}
	return "no PROXY header within the time of section 4.5"
}

// gatewayStream is the data connection as the stream check uses it.
type gatewayStream interface {
	io.ReadWriter
	CloseWrite() error
	ClosedWithNotify() bool
}

// passBytes sends the end of the agent and the answer of the gateway and says what is wrong.
func (rl *relayRun) passBytes(agent net.Conn, d gatewayStream, sent []byte) string {
	got := make([]byte, len(sent))
	if _, err := io.ReadFull(d, got); err != nil || !bytes.Equal(got, sent) {
		return "the bytes of the agent did not arrive unchanged"
	}
	if err := tunnelclient.CloseWrite(agent); err != nil {
		return "the tool cannot half-close its agent connection"
	}
	if n, err := d.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		return "the half close of the agent did not end the stream towards the gateway"
	}
	if !d.ClosedWithNotify() {
		return "the half close of the agent was not passed on as close_notify (the check assumes an unpadded record; a TLS stack that pads records fails it too)"
	}
	reply := make([]byte, replyBytes)
	_, _ = rand.Read(reply)
	if _, err := d.Write(reply); err != nil {
		return "the answer of the gateway could not be sent after the half close of the agent"
	}
	_ = d.CloseWrite()
	_ = agent.SetReadDeadline(time.Now().Add(rl.t.timing.Close))
	// One byte more than the reply is read, so that a relay that sends more shows and cannot
	// make the tool read without end.
	back, err := io.ReadAll(io.LimitReader(agent, int64(len(reply))+1))
	if err != nil || !bytes.Equal(back, reply) {
		return "the answer of the gateway did not arrive unchanged after the half close of the agent"
	}
	return ""
}

// proxyAgent checks that a PROXY header that an agent sends is not taken over (RELAY-v0 section
// 4.6): the relay closes the connection, or routes it and writes the address it sees.
func (rl *relayRun) proxyAgent(ctx context.Context) error {
	claimed := netip.MustParseAddrPort(claimedSource)
	header := tunnelclient.EncodeProxy(claimed, claimedDestination)
	agent, err := rl.t.dialAgent(ctx, header, tunnelclient.ClientHello(stdName(rl.s.insts[0])))
	if err != nil {
		return netProblem(err)
	}
	defer agent.Close()
	got := await(ctx, rl.sa, agent, rl.t.timing.Close)
	if !got.opened {
		rl.note(CheckRelayProxy, "")
		return nil
	}
	d, err := rl.t.dialData(ctx, &rl.saCred.cert, frames.EncodeDataBind(got.open.Token))
	if err != nil {
		return netProblem(err)
	}
	defer d.Close()
	_ = d.SetReadDeadline(time.Now().Add(rl.t.timing.Tunnel))
	proxy, _ := tunnelclient.ReadPROXY(d)
	if proxy.Src == claimed {
		rl.note(CheckRelayProxy, "the relay took the address from a PROXY header that the agent sent")
		return nil
	}
	rl.note(CheckRelayProxy, "")
	return nil
}

// relayBeforeUnpair binds a data connection of the second installation and keeps it open together
// with its agent connection, so that there is something for the relay to close when the
// installation is unpaired (RELAY-v0 section 4.1).
func (s *script) relayBeforeUnpair(ctx context.Context) error {
	rl := s.rl
	if rl == nil || rl.stopped || s.insts[1] == nil {
		return nil
	}
	ctl := rl.ensureB(ctx)
	if ctl == nil {
		return nil
	}
	name := stdName(s.insts[1])
	agent, open, problem, err := rl.token(ctx, ctl, name)
	if err != nil || problem != "" {
		return err
	}
	d, err := rl.t.dialData(ctx, &newest(s.insts[1]).cert, frames.EncodeDataBind(open.Token))
	if err != nil {
		_ = agent.Close()
		return netProblem(err)
	}
	_ = d.SetReadDeadline(time.Now().Add(rl.t.timing.Tunnel))
	_, perr := tunnelclient.ReadPROXY(d)
	_, rerr := io.ReadFull(d, make([]byte, len(tunnelclient.ClientHello(name))))
	if perr != nil || rerr != nil {
		_ = agent.Close()
		_ = d.Close()
		return nil
	}
	_ = d.SetReadDeadline(time.Time{})
	rl.boundB, rl.agentB = d, agent
	return nil
}

// relayUnpaired says when the second installation was unpaired.
func (s *script) relayUnpaired() {
	if s.rl != nil {
		s.rl.unpaired = time.Now()
	}
}

// relayDenylist checks, after the second installation was unpaired, that the relay closes its
// connections within 60 seconds and then refuses its certificate (RELAY-v0 section 4.1; the
// probe unpaired of tls-v0.json is played more than 60 seconds after the unpairing).
func (s *script) relayDenylist(ctx context.Context) error {
	rl := s.rl
	if rl == nil || rl.unpaired.IsZero() || rl.sb == nil {
		return nil
	}
	deadline := rl.unpaired.Add(rl.t.timing.Deny)
	var problems []string
	select {
	case <-rl.sb.Done():
	case <-time.After(time.Until(deadline)):
		problems = append(problems, "the control connection of the unpaired installation is still open")
	case <-ctx.Done():
		return incompleteFor(ctx.Err())
	}
	if rl.boundB != nil {
		if seen := tunnelclient.Observe(rl.boundB, time.Until(deadline), 1); !seen.Closed {
			problems = append(problems, "the data connection of the unpaired installation is still open")
		}
	}
	if err := sleep(ctx, time.Until(deadline)); err != nil {
		return incompleteFor(err)
	}
	for _, pr := range loadCases[tlsProbe](tlsFile) {
		if pr.Client.Certificate != "unpaired" {
			continue
		}
		p := rl.t.params(&newest(s.insts[1]).cert)
		got, err := rl.runProbe(ctx, p, false)
		if err != nil {
			return err
		}
		if got != pr.Expected {
			problems = append(problems, fmt.Sprintf("%s: the certificate of the unpaired installation is %s, want %s", pr.ID, got, pr.Expected))
		}
	}
	rl.note(CheckRelayDenylist, strings.Join(problems, "; "))
	return nil
}
