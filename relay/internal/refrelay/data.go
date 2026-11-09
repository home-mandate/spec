// SPDX-License-Identifier: Apache-2.0

package refrelay

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"net/netip"
	"strings"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
)

// token is an agent connection that waits for a data connection (section 4.5).
type token struct {
	home   string
	sess   *session
	agent  *replayConn
	src    netip.AddrPort
	timer  *time.Timer
	digest [sha256.Size]byte
	raw    [frames.TokenSize]byte
	used   bool
}

// agent routes an agent connection by its server name: it closes it, without completing a
// TLS handshake, or sends stream-open and keeps it until a data connection binds.
// It returns true if it keeps the connection.
func (r *Relay) agent(pc *replayConn, name string, claimed netip.AddrPort) bool {
	route, ok := r.route(name)
	if !ok || !r.reg.Active(route.Home) {
		return false
	}
	src := claimed
	if !src.IsValid() {
		src = netip.AddrPortFrom(r.cfg.AgentAddr, netip.MustParseAddrPort(pc.RemoteAddr().String()).Port())
	}
	var raw [frames.TokenSize]byte
	_, _ = rand.Read(raw[:])
	t := &token{home: route.Home, agent: pc, src: src, digest: sha256.Sum256(raw[:]), raw: raw}
	if !r.register(t) {
		return false
	}
	open, _ := frames.EncodeStreamOpen(raw, int(r.cfg.TokenValidity/time.Millisecond))
	t.sess.send(open)
	return true
}

// route finds the installation of a server name: an own-domain name only while it is verified,
// and without regard to case.
func (r *Relay) route(name string) (Route, bool) {
	if !r.has(CaseSensitiveSNI) {
		name = strings.ToLower(name)
	}
	route, ok := r.reg.Routes()[name]
	return route, ok && (route.Verified || r.has(PendingRouted))
}

// register stores the token of an agent connection if the installation has a control
// connection that is not draining and room for another stream.
func (r *Relay) register(t *token) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.sessions[t.home]
	if s == nil || r.streams[t.home] >= r.cfg.MaxStreams {
		return false
	}
	s.mu.Lock()
	drained := s.drained
	s.mu.Unlock()
	if drained {
		return false
	}
	t.sess = s
	r.tokens[t.digest] = t
	r.streams[t.home]++
	t.timer = time.AfterFunc(r.cfg.TokenValidity, func() { r.void(t.digest, frames.ReasonTimeout, true) })
	return true
}

// void withdraws a token that was not bound: the agent connection is closed and, while the
// control connection is open, stream-close says so.
func (r *Relay) void(digest [sha256.Size]byte, reason int, notify bool) {
	r.mu.Lock()
	t := r.tokens[digest]
	if t == nil || t.used {
		r.mu.Unlock()
		return
	}
	delete(r.tokens, digest)
	r.streams[t.home]--
	r.mu.Unlock()
	t.timer.Stop()
	r.forget(t.agent.Conn)
	if notify {
		closeFrame, _ := frames.EncodeStreamClose(t.raw, reason)
		t.sess.send(closeFrame)
	}
}

// withdraw voids a token on the request of the gateway of the same control connection.
func (r *Relay) withdraw(s *session, digest [sha256.Size]byte) {
	r.mu.Lock()
	t := r.tokens[digest]
	r.mu.Unlock()
	if t != nil && t.sess == s {
		r.void(digest, frames.ReasonRefused, false)
	}
}

// voidTokensOf voids the tokens sent on a control connection that ended.
func (r *Relay) voidTokensOf(s *session) {
	r.mu.Lock()
	var mine [][sha256.Size]byte
	for d, t := range r.tokens {
		if t.sess == s && !t.used {
			mine = append(mine, d)
		}
	}
	r.mu.Unlock()
	for _, d := range mine {
		r.void(d, frames.ReasonInternal, false)
	}
}

// take consumes the token of a data-bind: its first presentation voids it, also when the
// binding is refused. A relay with the defect R5 keeps the token; fresh is false for a
// presentation after the first.
func (r *Relay) take(digest [sha256.Size]byte) (t *token, fresh bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t = r.tokens[digest]
	if t == nil || t.used {
		return t, false
	}
	t.used = true
	t.timer.Stop()
	if !r.has(TokenReuse) {
		delete(r.tokens, digest)
	}
	return t, true
}

// refuse closes a data connection without any answer; a relay with the defect R7 writes a frame
// first.
func (r *Relay) refuse(tc *tls.Conn) {
	if r.has(ByteBeforeClose) {
		raw, _ := frames.EncodeError(frames.CodeProtocol, "")
		_, _ = tc.Write(raw)
	}
	_ = tc.Close()
}

// data serves a data connection whose first frame has been read.
func (r *Relay) data(tc *tls.Conn, first []byte, id identity) {
	bind, err := frames.DataBind(first)
	if err != nil {
		r.refuse(tc)
		return
	}
	r.mu.Lock()
	s := r.sessions[id.home]
	r.mu.Unlock()
	if s == nil || id.notBefore.Before(s.id.notBefore) {
		r.refuse(tc)
		return
	}
	t, fresh := r.take(sha256.Sum256(bind))
	if t == nil || (t.home != id.home && !r.has(ForeignToken)) {
		r.refuse(tc)
		return
	}
	if _, err := tc.Write(r.proxyHeader(t.src)); err != nil || !fresh {
		return
	}
	r.pipe(tc, t)
}
