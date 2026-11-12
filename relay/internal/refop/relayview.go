// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"crypto/x509"

	"github.com/home-mandate/spec/relay/internal/refrelay"
)

// The operator is the registry of its reference relay (refrelay.Registry).
var _ refrelay.Registry = (*Operator)(nil)

// Routes returns the names the operator serves: the standard name of every active installation,
// and its own-domain name, verified or still pending.
func (o *Operator) Routes() map[string]refrelay.Route {
	o.mu.Lock()
	defer o.mu.Unlock()
	routes := map[string]refrelay.Route{}
	for _, inst := range o.insts {
		if inst.status != "active" {
			continue
		}
		routes[o.stdName(inst)] = refrelay.Route{Home: inst.homeID, Verified: true}
		if inst.own != nil {
			routes[inst.own.name] = refrelay.Route{Home: inst.homeID, Verified: inst.own.status == "verified"}
		}
	}
	return routes
}

// Active reports whether the installation with the home ID is active and not blocked.
func (o *Operator) Active(home string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, inst := range o.insts {
		if inst.homeID == home {
			return inst.status == "active" && !inst.blocked
		}
	}
	return false
}

// Denied reports whether the serial (hex) of a tunnel certificate is on the denylist.
func (o *Operator) Denied(serial string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, s := range o.denylist {
		if s == serial {
			return true
		}
	}
	return false
}

// Roots holds the tunnel CA of the operator.
func (o *Operator) Roots() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(o.ca.cert)
	return roots
}

// TrustDomain is the trust domain of the operator.
func (o *Operator) TrustDomain() string { return o.cfg.Operator }
