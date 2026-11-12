// SPDX-License-Identifier: Apache-2.0

package refdns

import (
	"net"
	"net/http"
)

// txtTTL is the TTL of the records that the control endpoint sets.
const txtTTL = 60

// Control serves a small HTTP endpoint on 127.0.0.1 with which a DNS hook, a process of its
// own, sets and removes one TXT record the way a tester's hook does at its DNS provider:
// POST /txt?name=<name>&value=<text> and DELETE /txt?name=<name>. It returns the base URL and
// the function that stops it.
func (d *DNS) Control() (string, func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/txt", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if d.zoneOf(name) == nil {
			http.Error(w, "no such zone", http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodPost:
			d.Replace(name, TypeTXT, TXT(name, txtTTL, r.URL.Query().Get("value")))
		case http.MethodDelete:
			d.Replace(name, TypeTXT)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
	l := must(net.Listen("tcp4", "127.0.0.1:0"))
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	return "http://" + l.Addr().String(), func() { _ = srv.Close() }
}

// must returns v and panics on an error that cannot happen on a machine with a loopback.
func must[T any](v T, err error) T {
	if err != nil {
		panic("refdns: " + err.Error())
	}
	return v
}
