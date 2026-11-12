// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"crypto"
	"crypto/rand"
	"encoding/base32"
	"math/big"
	"strings"
	"time"
)

// DefaultACMEAccountPrefix and the like are the values the reference operator publishes.
const (
	instPath     = "/enroll/installation/"
	homeIDBytes  = 16
	instIDBytes  = 16
	tokenBytes   = 16
	pairValidity = time.Hour
	maxAddrTTL   = 300
)

var base32Lower = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ownDomain is the registration of an own-domain name.
type ownDomain struct {
	name, token, status string
}

type acmePair struct{ account, caa string }

// installation is an installation of the reference operator.
type installation struct {
	id, homeID    string
	key           crypto.PublicKey
	status        string
	blocked       bool
	offline       bool
	pairedAt      time.Time
	tunnelKeys    []crypto.PublicKey
	serials       []*big.Int
	lastNotBefore time.Time
	acme          *acmePair
	pending       *acmePair
	own           *ownDomain
	endedToken    string
}

// codeUse is a redeemed pairing code.
type codeUse struct {
	inst string
	key  crypto.PublicKey
}

func (o *Operator) base() string { return "https://" + o.cfg.Operator }

func (o *Operator) installationURL(inst *installation) string {
	return o.base() + instPath + inst.id
}

func (o *Operator) stdName(inst *installation) string { return inst.homeID + "." + DefaultNameDomain }

func randomLabel(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	return base32Lower.EncodeToString(raw)
}

// newHomeID returns a home ID never assigned before: 26 characters of a-z2-7.
func (o *Operator) newHomeID() string {
	for {
		id := randomLabel(homeIDBytes)[:26]
		if !o.homeIDs[id] {
			o.homeIDs[id] = true
			return id
		}
	}
}

// lookup returns the installation that a kid names.
func (o *Operator) lookup(kid string) *installation {
	rest, ok := strings.CutPrefix(kid, o.base()+instPath)
	if !ok || strings.Contains(rest, "/") {
		return nil
	}
	return o.insts[rest]
}

// held reports whether another active installation holds the own-domain name.
func (o *Operator) held(name string, except *installation) bool {
	for _, other := range o.insts {
		if other != except && other.status == "active" && other.own != nil && other.own.status == "verified" && other.own.name == name {
			return true
		}
	}
	return false
}

// Block blocks the installation at its URL; Unblock lifts it (tests of the order of section 5.1).
func (o *Operator) Block(installationURL string, blocked bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.insts[strings.TrimPrefix(installationURL, o.base()+instPath)].blocked = blocked
}

// SetOffline says that the installation has been offline for longer than max_offline_days.
func (o *Operator) SetOffline(installationURL string, offline bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.insts[strings.TrimPrefix(installationURL, o.base()+instPath)].offline = offline
}

// Denylist returns the serial numbers (hex) of the certificates of unpaired installations.
func (o *Operator) Denylist() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string{}, o.denylist...)
}

// AgePairing makes the pairing of the installation older than an hour, so that the first report
// of an ACME account needs the confirmation of the household (RELAY-v0 section 5.6).
func (o *Operator) AgePairing(installationURL string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	inst := o.insts[strings.TrimPrefix(installationURL, o.base()+instPath)]
	inst.pairedAt = inst.pairedAt.Add(-2 * pairValidity)
}
