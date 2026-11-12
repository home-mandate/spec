// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay/internal/refdns"
)

const (
	apexTTL     = 3600
	longTTL     = 7200
	challengeAt = "_acme-challenge."
	proofAt     = "_home-mandate-relay."
)

// RelayAddresses are the addresses of relay_addresses in the metadata of the reference operator.
var RelayAddresses = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}

func (o *Operator) ttl(normal uint32) uint32 {
	if o.cfg.Faults.Has(LongTTL) {
		return longTTL
	}
	return normal
}

// publishApex publishes the CAA records at the apex of the name domain (section 6.3).
func (o *Operator) publishApex() {
	apex := DefaultNameDomain
	issue := ";"
	if o.cfg.Faults.Has(ApexIssueCA) {
		issue = "ca.example"
	}
	rrs := []dnsmessage.Resource{refdns.CAA(apex, o.ttl(apexTTL), 0, "issue", issue)}
	if !o.cfg.Faults.Has(ApexNoIssuewild) {
		rrs = append(rrs, refdns.CAA(apex, o.ttl(apexTTL), 0, "issuewild", ";"))
	}
	o.dns.Replace(apex, refdns.TypeCAA, rrs...)
	if o.cfg.Faults.Has(ApexCNAME) {
		o.dns.Replace(apex, refdns.TypeCNAME, refdns.CNAME(apex, o.ttl(apexTTL), "other.example"))
	}
}

// publishName publishes the records of a new installation: A and AAAA, and the CAA record
// that permits no issuance.
func (o *Operator) publishName(inst *installation) {
	name := o.stdName(inst)
	var as, aaaas []dnsmessage.Resource
	for _, a := range RelayAddresses {
		if o.cfg.Faults.Has(WrongAddress) && a.Is4() {
			a = netip.MustParseAddr("127.0.0.9")
		}
		rr := refdns.A(name, o.ttl(300), a)
		if a.Is4() {
			as = append(as, rr)
		} else {
			aaaas = append(aaaas, rr)
		}
	}
	o.dns.Replace(name, refdns.TypeA, as...)
	o.dns.Replace(name, refdns.TypeAAAA, aaaas...)
	if !o.cfg.Faults.Has(NoClosedCAA) {
		o.dns.Replace(name, refdns.TypeCAA, refdns.CAA(name, o.ttl(300), 0, "issue", ";"))
	}
	if o.cfg.Faults.Has(ExtraTXT) {
		o.dns.Replace(name, refdns.TypeTXT, refdns.TXT(name, o.ttl(300), "extra"))
	}
}

// publishCAA publishes the CAA record of the account in force (section 6.3).
func (o *Operator) publishCAA(inst *installation) {
	name := o.stdName(inst)
	value := inst.acme.caa + "; accounturi=" + inst.acme.account
	if !o.cfg.Faults.Has(NoValidationMethods) {
		value += "; validationmethods=dns-01"
	}
	o.dns.Replace(name, refdns.TypeCAA, refdns.CAA(name, o.ttl(300), 0, "issue", value), refdns.CAA(name, o.ttl(300), 0, "issuewild", ";"))
}

// publishChallenge publishes the challenge values; with ChallengeBeforeSecondServer the
// second name server gets them later than the answer.
func (o *Operator) publishChallenge(inst *installation, values []string) {
	name := challengeAt + o.stdName(inst)
	rrs := make([]dnsmessage.Resource, len(values))
	for i, v := range values {
		rrs[i] = refdns.TXT(name, 60, v)
	}
	if !o.cfg.Faults.Has(ChallengeBeforeSecondServer) {
		o.dns.Replace(name, refdns.TypeTXT, rrs...)
		return
	}
	o.dns.ReplaceOn(0, name, refdns.TypeTXT, rrs...)
	time.AfterFunc(o.cfg.DNSLag, func() { o.dns.ReplaceOn(1, name, refdns.TypeTXT, rrs...) })
}

// unpublish removes every record of the standard name (section 5.7).
func (o *Operator) unpublish(inst *installation) {
	name := o.stdName(inst)
	left := o.dns.Lookup(0, name, refdns.TypeCAA)
	o.dns.RemoveBelow(name)
	if o.cfg.Faults.Has(CAAStaysAfterUnpair) {
		o.dns.Replace(name, refdns.TypeCAA, left...)
	}
}

// proof returns the TXT value at the proof name of an own-domain name, if it is there.
func (o *Operator) proof(name string) (string, bool) {
	at := proofAt + name
	if !o.dns.Covers(at) {
		return "", false
	}
	for _, rr := range o.dns.Lookup(0, at, refdns.TypeTXT) {
		return strings.Join(rr.Body.(*dnsmessage.TXTResource).TXT, ""), true
	}
	return "", false
}
