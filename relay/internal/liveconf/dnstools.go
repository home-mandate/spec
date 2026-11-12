// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/spec/relay/internal/dnsq"
	"github.com/home-mandate/spec/relay/internal/netguard"
)

var errNotVisible = errors.New("the record does not show on all name servers of its zone in time")

// dnsTools asks the authoritative name servers of zones.
type dnsTools struct {
	res    *dnsq.Resolver
	timing Timing
}

func newDNSTools(env Env) *dnsTools {
	lookupNS := env.NS
	if lookupNS == nil {
		lookupNS = systemNS
	}
	return &dnsTools{timing: env.Timing, res: &dnsq.Resolver{Dialer: netguard.New(env.Net), NS: lookupNS, Timeout: env.Timing.Request}}
}

// answered is the answer of one name server, or the reason it gave none.
type answered struct {
	server dnsq.Server
	answer dnsq.Answer
	err    error
}

// ask asks every server; an error of one server does not stop the others.
func (d *dnsTools) ask(ctx context.Context, servers []dnsq.Server, name string, typ dnsmessage.Type) []answered {
	out := make([]answered, len(servers))
	for i, s := range servers {
		a, err := d.res.Ask(ctx, s, name, typ)
		out[i] = answered{server: s, answer: a, err: err}
	}
	return out
}

// waitTXT waits until every name server of the zone of name shows exactly the TXT value, or,
// for an empty want, no TXT record.
func (d *dnsTools) waitTXT(ctx context.Context, name, want string) error {
	deadline := time.Now().Add(d.timing.Visible)
	for {
		if d.txtIs(ctx, name, want) {
			return nil
		}
		if time.Now().After(deadline) {
			return errNotVisible
		}
		if err := sleep(ctx, d.timing.Poll); err != nil {
			return err
		}
	}
}

func (d *dnsTools) txtIs(ctx context.Context, name, want string) bool {
	_, servers, err := d.res.Zone(ctx, name)
	if err != nil {
		return false
	}
	for _, a := range d.ask(ctx, servers, name, dnsq.TypeTXT) {
		if a.err != nil || a.answer.RCode > dnsmessage.RCodeNameError || !onlyText(a.answer, want) {
			return false
		}
	}
	return true
}

func onlyText(a dnsq.Answer, want string) bool {
	var found []string
	for _, r := range a.Records {
		if r.Type == dnsq.TypeTXT {
			found = append(found, r.Text)
		}
	}
	if want == "" {
		return len(found) == 0
	}
	return len(found) == 1 && found[0] == want
}

// systemNS looks the name servers of a name up with the system's resolver.
func systemNS(ctx context.Context, name string) ([]string, error) {
	records, err := net.DefaultResolver.LookupNS(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.Host
	}
	return out, nil
}
