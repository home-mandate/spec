// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay/internal/dnsq"
)

const maxTTL = 3600

// perServer asks every name server of the zone for name and type, and returns what judge finds
// wrong in the first answer that is wrong; a server that gives no usable answer is wrong.
func (s *script) perServer(ctx context.Context, name string, typ dnsmessage.Type, judge func(dnsq.Answer) string) string {
	for _, a := range s.dns.ask(ctx, s.servers, name, typ) {
		if a.err != nil {
			return "no usable answer from " + esc(a.server.String()) + " (" + classify(a.err).kind + ")"
		}
		if a.answer.RCode != dnsmessage.RCodeSuccess && a.answer.RCode != dnsmessage.RCodeNameError {
			return esc(a.server.Host) + " answers with the rcode " + fmt.Sprint(int(a.answer.RCode))
		}
		if p := judge(a.answer); p != "" {
			return esc(a.server.Host) + ": " + p
		}
	}
	return ""
}

// caaValues returns the parsed issue and issuewild values of the CAA records of an answer, and
// an error text if one does not parse.
func caaValues(a dnsq.Answer) (issue, issuewild []dnsq.Issue, problem string) {
	for _, r := range a.Records {
		if r.Type != dnsq.TypeCAA || (r.CAA.Tag != "issue" && r.CAA.Tag != "issuewild") {
			continue
		}
		v, err := dnsq.ParseIssue(r.CAA.Value)
		if err != nil {
			return nil, nil, "a CAA " + r.CAA.Tag + " value that does not parse: " + esc(r.CAA.Value)
		}
		if r.CAA.Tag == "issue" {
			issue = append(issue, v)
		} else {
			issuewild = append(issuewild, v)
		}
	}
	return issue, issuewild, ""
}

func closed(v dnsq.Issue) bool { return v.Domain == "" && len(v.Params) == 0 }

func allClosed(list []dnsq.Issue) bool {
	return !slices.ContainsFunc(list, func(v dnsq.Issue) bool { return !closed(v) })
}

// judgeApex: exactly issue ";" and issuewild ";" (RELAY-v0 section 6.3).
func judgeApex(a dnsq.Answer) string {
	issue, wild, problem := caaValues(a)
	switch {
	case problem != "":
		return problem
	case len(issue) != 1 || !closed(issue[0]):
		return fmt.Sprintf("%d issue records, want exactly issue \";\"", len(issue))
	case len(wild) != 1 || !closed(wild[0]):
		return fmt.Sprintf("%d issuewild records, want exactly issuewild \";\"", len(wild))
	}
	return ""
}

// judgeClosed: issue ";" as the only issue record, no issuewild that permits anything.
func judgeClosed(a dnsq.Answer) string {
	issue, wild, problem := caaValues(a)
	switch {
	case problem != "":
		return problem
	case len(issue) != 1 || !closed(issue[0]):
		return fmt.Sprintf("%d issue records, want exactly issue \";\" until an account is reported", len(issue))
	case !allClosed(wild):
		return "an issuewild record that permits issuance"
	}
	return ""
}

// judgeAccount: exactly one issue record, the CA, the account and dns-01 only.
func judgeAccount(caaID, account string) func(dnsq.Answer) string {
	return func(a dnsq.Answer) string {
		issue, wild, problem := caaValues(a)
		switch {
		case problem != "":
			return problem
		case len(issue) != 1:
			return fmt.Sprintf("%d issue records, want exactly one", len(issue))
		case !allClosed(wild):
			return "an issuewild record that permits issuance"
		}
		got := issue[0]
		uri, _ := got.Param("accounturi")
		methods, hasMethods := got.Param("validationmethods")
		switch {
		case got.Domain != strings.ToLower(caaID) || uri != account:
			return "the issue record is not for the reported CA and account"
		case !hasMethods || methods != "dns-01":
			return "the issue record has no validationmethods=dns-01"
		case len(got.Params) != 2:
			return "the issue record has parameters besides accounturi and validationmethods"
		}
		return ""
	}
}

// dnsServers finds the name servers of the name domain and hints at DNSSEC.
func (s *script) dnsServers(ctx context.Context) error {
	_, servers, err := s.dns.res.Zone(ctx, s.doc.NameDomain)
	if err != nil {
		s.rec(CheckDNSServers, "no name servers of the name domain were found")
		return nil
	}
	s.servers = servers
	problem := s.perServer(ctx, s.doc.NameDomain, dnsq.TypeNS, func(dnsq.Answer) string { return "" })
	s.rec(CheckDNSServers, problem)
	signed := false
	for _, a := range s.dns.ask(ctx, servers[:1], s.doc.NameDomain, dnsq.TypeDNSKEY) {
		signed = a.err == nil && len(a.answer.Records) > 0
	}
	if !signed {
		s.r.note("the name domain does not show DNSSEC keys (RELAY-v0 section 7.1 asks for DNSSEC)")
	}
	return nil
}

// dnsAfterPairing checks the records of the name domain and of the standard name of the first
// installation right after pairing.
func (s *script) dnsAfterPairing(ctx context.Context) error {
	if !s.wantDNS() {
		return nil
	}
	if err := s.dnsServers(ctx); err != nil || len(s.servers) == 0 {
		return err
	}
	std := s.insts[0].paired.Installation.PublicName
	s.rec(CheckDNSApex, s.apexProblem(ctx))
	s.rec(CheckDNSClosed, s.perServer(ctx, std, dnsq.TypeCAA, judgeClosed))
	s.rec(CheckDNSAddresses, s.addressProblem(ctx, std))
	s.rec(CheckDNSTTL, s.ttlProblem(ctx, std))
	s.rec(CheckDNSNoOther, s.otherProblem(ctx, std))
	return nil
}

// apexProblem checks the CAA records at the apex, and that the apex is no CNAME or DNAME, which
// would make a CA follow it (RELAY-v0 section 6.3).
func (s *script) apexProblem(ctx context.Context) string {
	if p := s.perServer(ctx, s.doc.NameDomain, dnsq.TypeCAA, judgeApex); p != "" {
		return p
	}
	for _, typ := range []dnsmessage.Type{dnsq.TypeCNAME, dnsq.TypeDNAME} {
		if p := s.perServer(ctx, s.doc.NameDomain, typ, func(a dnsq.Answer) string {
			if len(a.Records) > 0 {
				return fmt.Sprintf("a record of type %d at the apex", typ)
			}
			return ""
		}); p != "" {
			return p
		}
	}
	return ""
}

func (s *script) addressProblem(ctx context.Context, std string) string {
	want := map[dnsmessage.Type][]string{dnsq.TypeA: nil, dnsq.TypeAAAA: nil}
	for _, text := range s.doc.RelayAddresses {
		if a, err := netip.ParseAddr(text); err == nil {
			typ := dnsq.TypeAAAA
			if a.Is4() {
				typ = dnsq.TypeA
			}
			want[typ] = append(want[typ], a.String())
		}
	}
	for _, typ := range []dnsmessage.Type{dnsq.TypeA, dnsq.TypeAAAA} {
		expected := slices.Sorted(slices.Values(want[typ]))
		if p := s.perServer(ctx, std, typ, func(a dnsq.Answer) string {
			var got []string
			for _, r := range a.Records {
				if r.Type == typ {
					got = append(got, r.Addr.String())
				}
			}
			if !slices.Equal(slices.Sorted(slices.Values(got)), expected) {
				return fmt.Sprintf("the records of type %d are not the relay_addresses", typ)
			}
			return ""
		}); p != "" {
			return p
		}
	}
	return ""
}

func (s *script) ttlProblem(ctx context.Context, std string) string {
	judge := func(a dnsq.Answer) string {
		for _, r := range a.Records {
			if r.TTL > maxTTL {
				return fmt.Sprintf("a record with the TTL %d, more than %d", r.TTL, maxTTL)
			}
		}
		return ""
	}
	for _, q := range []struct {
		name string
		typ  dnsmessage.Type
	}{{std, dnsq.TypeA}, {std, dnsq.TypeAAAA}, {std, dnsq.TypeCAA}, {s.doc.NameDomain, dnsq.TypeCAA}} {
		if p := s.perServer(ctx, q.name, q.typ, judge); p != "" {
			return p
		}
	}
	return ""
}

// otherProblem: no record that a CA uses for validation at the standard name (section 6.3).
func (s *script) otherProblem(ctx context.Context, std string) string {
	for _, typ := range []dnsmessage.Type{dnsq.TypeTXT, dnsq.TypeCNAME, dnsq.TypeDNAME, dnsq.TypeNS} {
		if p := s.perServer(ctx, std, typ, func(a dnsq.Answer) string {
			if len(a.Records) > 0 {
				return fmt.Sprintf("a record of type %d at the standard name", typ)
			}
			return ""
		}); p != "" {
			return p
		}
	}
	return ""
}

// dnsAccount checks the CAA record after the first report.
func (s *script) dnsAccount(ctx context.Context, a *liveInst) error {
	if !s.wantDNS() || len(s.servers) == 0 {
		return nil
	}
	s.rec(CheckDNSAccount, s.perServer(ctx, a.paired.Installation.PublicName, dnsq.TypeCAA, judgeAccount(s.caaID, s.account)))
	return nil
}

// dnsChallenge checks that the challenge value shows on every name server.
func (s *script) dnsChallenge(ctx context.Context, a *liveInst, value string) error {
	if !s.wantDNS() || len(s.servers) == 0 {
		return nil
	}
	name := "_acme-challenge." + a.paired.Installation.PublicName
	s.rec(CheckDNSChallenge, s.perServer(ctx, name, dnsq.TypeTXT, func(ans dnsq.Answer) string {
		if !onlyText(ans, value) {
			return "the challenge value is not the only TXT record when the answer is 200"
		}
		return ""
	}))
	return nil
}

// dnsRemoved checks that an unpaired installation left no record.
func (s *script) dnsRemoved(ctx context.Context, b *liveInst) error {
	if !s.wantDNS() || len(s.servers) == 0 {
		return nil
	}
	std := b.paired.Installation.PublicName
	for _, q := range []struct {
		name string
		typ  dnsmessage.Type
	}{
		{std, dnsq.TypeA}, {std, dnsq.TypeAAAA}, {std, dnsq.TypeCAA}, {std, dnsq.TypeTXT}, {"_acme-challenge." + std, dnsq.TypeTXT},
	} {
		if p := s.perServer(ctx, q.name, q.typ, func(a dnsq.Answer) string {
			if len(a.Records) > 0 {
				return "a record is left after unpairing"
			}
			return ""
		}); p != "" {
			s.rec(CheckDNSRemoved, strings.TrimSpace(p))
			return nil
		}
	}
	s.rec(CheckDNSRemoved, "")
	return nil
}
