// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/home-mandate/spec/relay/internal/frames"
	"github.com/home-mandate/spec/relay/internal/tunnelclient"
)

// maxProblems is how many problems of one check a failure names.
const maxProblems = 4

// tunnelCred is a tunnel certificate of the run with its key.
type tunnelCred struct {
	cert      tls.Certificate
	notBefore time.Time
	p256      bool
}

// relayRun is the class relay inside the script: the checks need the installations, their
// tunnel certificates and the own-domain name that the classes enrollment and dns bring about,
// so the steps of the class are called from the sequence of the script (RELAY-v0 section 8.3).
type relayRun struct {
	s      *script
	t      *tun
	active []tunnelclient.Pin

	problems map[string][]string
	reached  map[string]bool
	stopped  bool

	// sa and sb are the open control connections of the two installations, and saCred and
	// olderCred the certificate of sa and the certificate of the same installation that starts
	// before it, if there is one.
	sa, sb    *tunnelclient.Control
	saCred    *tunnelCred
	olderCred *tunnelCred
	// boundB is a bound data connection of the second installation and its agent connection,
	// kept open until the installation is unpaired.
	used     [frames.TokenSize]byte
	boundB   *tunnelclient.Conn
	agentB   net.Conn
	unpaired time.Time
}

// credsOf returns the tunnel certificates of an installation in the order they were issued.
func credsOf(inst *liveInst) []tunnelCred {
	if inst == nil {
		return nil
	}
	return inst.creds
}

// newest returns the tunnel certificate with the latest notBefore, nil if there is none.
func newest(inst *liveInst) *tunnelCred {
	creds := credsOf(inst)
	if len(creds) == 0 {
		return nil
	}
	best := &creds[0]
	for i := range creds {
		if creds[i].notBefore.After(best.notBefore) {
			best = &creds[i]
		}
	}
	return best
}

// oldest returns the tunnel certificate with the earliest notBefore.
func oldest(inst *liveInst) *tunnelCred {
	creds := credsOf(inst)
	if len(creds) == 0 {
		return nil
	}
	best := &creds[0]
	for i := range creds {
		if creds[i].notBefore.Before(best.notBefore) {
			best = &creds[i]
		}
	}
	return best
}

// note records a problem of a check; an empty problem only says that the check was reached.
func (rl *relayRun) note(id, problem string) {
	rl.reached[id] = true
	if problem == "" || len(rl.problems[id]) >= maxProblems {
		return
	}
	rl.problems[id] = append(rl.problems[id], clean(problem))
}

// record gives the verdicts of the checks that were reached.
func (rl *relayRun) record() {
	for _, c := range checksOf(ClassRelay) {
		if rl.reached[c.ID] {
			rl.s.rec(c.ID, strings.Join(rl.problems[c.ID], "; "))
		}
	}
}

// close ends the connections the run holds.
func (rl *relayRun) close() {
	for _, c := range []*tunnelclient.Control{rl.sa, rl.sb} {
		if c != nil {
			c.Close()
		}
	}
	if rl.boundB != nil {
		_ = rl.boundB.Close()
	}
	if rl.agentB != nil {
		_ = rl.agentB.Close()
	}
}

func runRelay(ctx context.Context, r *run) error { return r.playScript(ctx) }

func (s *script) wantRelay() bool { return s.r.selected(ClassRelay) }

// newRelay prepares the class: the way to the relay and the pins of the metadata. There is no
// class run if the run has no installation or the metadata names no relay.
func (s *script) newRelay() {
	if !s.wantRelay() {
		return
	}
	active := parsePins(s.doc.RelayPins)
	all := append(slices.Clone(active), parsePins(s.doc.RelayBackupPins)...)
	t, err := newTun(s.r.env, s.doc.Relay.Host, s.doc.Relay.Port, s.doc.RelayAddresses, all)
	if err != nil {
		return
	}
	if hint := ipv6Hint(s.doc.RelayAddresses); hint != "" {
		s.r.note(hint)
	}
	s.rl = &relayRun{s: s, t: t, active: active, problems: map[string][]string{}, reached: map[string]bool{}}
}

// ipv6Hint says which IPv6 addresses of relay_addresses stay unchecked: agents connect to the
// first address only, and a tester without IPv6 could not reach the others anyway. The text is
// empty if every IPv6 address is the one in use.
func ipv6Hint(addresses []string) string {
	var unchecked []string
	for _, text := range addresses {
		if a, err := netip.ParseAddr(text); err == nil && a.Is6() && text != addresses[0] {
			unchecked = append(unchecked, esc(text))
		}
	}
	if len(unchecked) == 0 {
		return ""
	}
	return "IPv6 stays unchecked (AAAA, agent connections): the agent connections went to " + esc(addresses[0]) +
		" only, not to " + strings.Join(unchecked, ", ")
}

// relayTunnel plays the checks of the class that need no own-domain name and no unpairing, once
// the installations have their certificates.
func (s *script) relayTunnel(ctx context.Context) error {
	s.newRelay()
	rl := s.rl
	if rl == nil {
		return nil
	}
	if !s.hasCredentials() {
		return &incompleteError{"the class relay needs a tunnel certificate the tool can read for each installation"}
	}
	steps := []func(context.Context) error{
		rl.key, rl.probes, rl.hello, rl.framesCases, rl.session, rl.routing, rl.binding, rl.stream, rl.proxyAgent,
	}
	for _, step := range steps {
		if rl.stopped {
			break
		}
		if err := step(ctx); err != nil {
			return err
		}
	}
	return nil
}

// hasCredentials reports whether every installation of the run has a tunnel certificate the
// class relay can present.
func (s *script) hasCredentials() bool {
	for _, inst := range s.insts {
		if inst != nil && newest(inst) == nil {
			return false
		}
	}
	return s.insts[0] != nil
}

// stdName returns the standard name of the installation.
func stdName(inst *liveInst) string { return inst.paired.Installation.PublicName }

// pinIn reports whether the pin is among the active pins of the metadata.
func (rl *relayRun) pinIn(pin tunnelclient.Pin) bool { return slices.Contains(rl.active, pin) }

// parsePins reads pins as they stand in the metadata; those that do not parse are left out (the
// check of the metadata has said so).
func parsePins(list []string) []tunnelclient.Pin {
	var pins []tunnelclient.Pin
	for _, text := range list {
		if pin, err := tunnelclient.ParsePin(text); err == nil {
			pins = append(pins, pin)
		}
	}
	return pins
}
