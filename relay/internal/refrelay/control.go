// SPDX-License-Identifier: Apache-2.0

package refrelay

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
)

const softwareName = "refrelay/1"

// session is a control connection.
type session struct {
	r         *Relay
	tc        *tls.Conn
	id        identity
	period    time.Duration
	wmu       sync.Mutex
	dead      chan struct{}
	mu        sync.Mutex
	fs        *frames.Session
	drained   bool
	missed    bool
	pingValue *[8]byte
}

// announcedHeartbeat is the interval of hello-ack in seconds.
func (r *Relay) announcedHeartbeat() int {
	if r.has(Heartbeat3) {
		return 3
	}
	return min(max(int(r.cfg.Heartbeat/time.Second), minAnnounced), maxAnnounced)
}

// control serves a control connection whose first frame, a hello, has been read.
func (r *Relay) control(tc *tls.Conn, first []byte, id identity) {
	s := &session{r: r, tc: tc, id: id, period: r.cfg.Heartbeat, dead: make(chan struct{}), fs: frames.NewSession()}
	defer close(s.dead)
	hello, err := s.observe(frames.Gateway, first)
	if err != nil {
		s.fail(frames.CodeMalformed)
		return
	}
	if hello["min_version"].(int) > 1 {
		s.fail(frames.CodeUnsupportedVersion)
		return
	}
	if code := r.admit(s); code != 0 {
		s.fail(code)
		return
	}
	defer r.release(s)
	s.sendAck()
	if r.cfg.AnnouncePins {
		pins, _ := frames.EncodePins(1, [][frames.TokenSize]byte{r.pin}, nil)
		s.send(pins)
	}
	go s.ping()
	s.read()
}

// sendAck answers the hello. A relay with the defect R14 announces an interval that its own
// frame check would refuse, so the check is fed a valid one.
func (s *session) sendAck() {
	ack := frames.HelloAck{Version: 1, Software: softwareName, Heartbeat: s.r.announcedHeartbeat(), MaxStreams: s.r.cfg.MaxStreams}
	raw, _ := ack.Encode()
	valid := ack
	valid.Heartbeat = max(valid.Heartbeat, minAnnounced)
	checked, _ := valid.Encode()
	s.mu.Lock()
	_, _ = s.fs.Next(frames.Frame{From: frames.Relay, Data: checked})
	s.mu.Unlock()
	s.write(raw)
}

// observe feeds a frame to the rules of the connection.
func (s *session) observe(from string, raw []byte) (frames.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fs.Next(frames.Frame{From: from, Data: raw})
}

func (s *session) write(raw []byte) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_ = s.tc.SetWriteDeadline(time.Now().Add(frameTimeout))
	_, _ = s.tc.Write(raw)
}

// send writes a frame of the relay after the rules saw it.
func (s *session) send(raw []byte) {
	_, _ = s.observe(frames.Relay, raw)
	s.write(raw)
}

// fail sends error and closes the connection.
func (s *session) fail(code int) {
	raw, _ := frames.EncodeError(code, "")
	s.write(raw)
	_ = s.tc.Close()
}

// ping sends a ping once per heartbeat interval and ends a connection whose gateway missed the
// heartbeat: the silence of three intervals (section 4.4) is cut short by it after two.
func (s *session) ping() {
	tick := time.NewTicker(s.period)
	defer tick.Stop()
	for {
		select {
		case <-s.dead:
			return
		case <-tick.C:
		}
		s.mu.Lock()
		if s.pingValue != nil {
			s.missed = true
			s.mu.Unlock()
			s.fail(frames.CodeTimeout)
			return
		}
		var value [8]byte
		_, _ = rand.Read(value[:])
		s.pingValue = &value
		s.mu.Unlock()
		s.send(frames.EncodePing(value))
	}
}

// read serves the frames of the gateway until the connection ends.
func (s *session) read() {
	for {
		raw, err := frames.ReadFrame(s.tc)
		if errors.Is(err, frames.ErrFrame) {
			s.fail(frames.CodeMalformed)
			return
		}
		if err != nil {
			return
		}
		if s.r.has(PinsFromGateway) && binary.BigEndian.Uint16(raw) == typePins {
			continue
		}
		msg, err := s.observe(frames.Gateway, raw)
		if err != nil {
			s.fail(frames.CodeMalformed)
			return
		}
		if !s.handle(msg) {
			return
		}
	}
}

// handle acts on a frame of the gateway; it returns false when the connection ends.
func (s *session) handle(msg frames.Message) bool {
	switch msg["type"] {
	case "ping":
		value, _ := hex.DecodeString(msg["value"].(string))
		s.send(frames.EncodePong([8]byte(value)))
	case "pong":
		s.mu.Lock()
		s.pingValue = nil
		s.mu.Unlock()
	case "error":
		return false
	case "drain":
		s.mu.Lock()
		s.drained = true
		s.mu.Unlock()
	case "stream-close":
		token, _ := hex.DecodeString(msg["token"].(string))
		s.r.withdraw(s, sha256.Sum256(token))
	}
	return true
}

// replaceable reports whether a new control connection with a certificate that starts at
// notBefore may replace this one (section 4.4).
func (s *session) replaceable(notBefore time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.missed || s.drained || s.id.notBefore.Before(notBefore)
}

// admit registers a control connection. It returns 0, or the code of the error that answers it.
func (r *Relay) admit(s *session) int {
	r.mu.Lock()
	cur := r.sessions[s.id.home]
	switch {
	case cur == nil:
		r.sessions[s.id.home] = s
	case cur.replaceable(s.id.notBefore):
		r.sessions[s.id.home] = s
		defer cur.supersede()
	case r.has(NoSessionExists):
	default:
		r.mu.Unlock()
		return frames.CodeSessionExists
	}
	r.mu.Unlock()
	return 0
}

// supersede ends a control connection that a newer one replaced.
func (s *session) supersede() {
	s.r.voidTokensOf(s)
	s.fail(frames.CodeSuperseded)
}

// release removes a control connection that ended, and voids its tokens.
func (r *Relay) release(s *session) {
	r.mu.Lock()
	if r.sessions[s.id.home] == s {
		delete(r.sessions, s.id.home)
	}
	r.mu.Unlock()
	r.voidTokensOf(s)
}
