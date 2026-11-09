// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/home-mandate/spec/relay/internal/enroll"
	"github.com/home-mandate/spec/relay/internal/netguard"
)

const (
	// maxHeaderBytes limits the response header.
	maxHeaderBytes = 16 << 10
	// maxRetries is how often one request is repeated after a Retry-After.
	maxRetries = 3
	// maxRetryAfter keeps a Retry-After value from overflowing a duration.
	maxRetryAfter = 1 << 20
	// defaultRetryAfter is the wait, in units, for a Retry-After that cannot be read.
	defaultRetryAfter = 1
	handshakeTimeout  = 10 * time.Second
)

// Failure kinds of a network error. The text of the underlying error is never shown: it can
// hold the URL of an installation or an address of the operator.
const (
	kindCertificate = "certificate"
	kindBlocked     = "address"
	kindTimeout     = "timeout"
	kindOther       = "network"
)

// netFailure is a network error reduced to its kind.
type netFailure struct{ kind string }

func (e *netFailure) Error() string { return "network failure: " + e.kind }

// errRateLimited is returned when the operator limits the run and waiting would exceed the
// budget (RELAY-v0 section 8.3).
var errRateLimited = errors.New("the operator limits the rate of requests")

var errNotHTTPS = errors.New("only https URLs are fetched")

func classify(err error) *netFailure {
	var verify *tls.CertificateVerificationError
	var nerr net.Error
	switch {
	case errors.As(err, &verify):
		return &netFailure{kindCertificate}
	case errors.Is(err, netguard.ErrBlocked):
		return &netFailure{kindBlocked}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &nerr) && nerr.Timeout():
		return &netFailure{kindTimeout}
	}
	return &netFailure{kindOther}
}

// fetched is the answer to a GET.
type fetched struct {
	Status int
	Header http.Header
	Body   []byte
	// Over is set if the body is longer than the limit; Body then holds the first bytes.
	Over bool
}

// Web is the HTTPS client of a run. Every connection goes through the address filter, nothing
// is read from the environment (no proxy), no redirect is followed, nothing is compressed,
// and a request has a total time limit. The client sends no User-Agent of its own choosing.
type Web struct {
	client *http.Client
	timing Timing
	policy func(netip.Addr) bool

	mu    sync.Mutex
	last  time.Time
	spent time.Duration
}

func newWeb(env Env) *Web {
	dialer := netguard.New(env.Net)
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: env.Roots},
		TLSHandshakeTimeout:    handshakeTimeout,
		ResponseHeaderTimeout:  env.Timing.Request,
		MaxResponseHeaderBytes: maxHeaderBytes,
		// A non-nil, empty map keeps the transport from offering HTTP/2.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   max(env.Timing.Request, env.Timing.Slow),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Web{client: client, timing: env.Timing, policy: dialer.Policy()}
}

// get fetches rawURL and reads at most limit bytes of the body. It honours Retry-After within
// the budget of the run.
func (w *Web) get(ctx context.Context, rawURL string, limit int64) (fetched, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return fetched{}, errNotHTTPS
	}
	for attempt := 0; ; attempt++ {
		if err := w.pace(ctx); err != nil {
			return fetched{}, classify(err)
		}
		res, err := w.send(ctx, http.MethodGet, rawURL, nil, "", limit, w.timing.Request)
		if err != nil {
			return fetched{}, classify(err)
		}
		retryAfter := res.Header.Get("Retry-After")
		if res.Status != http.StatusTooManyRequests && !(res.Status == http.StatusServiceUnavailable && retryAfter != "") {
			return res, nil
		}
		wait := w.retryWait(retryAfter)
		if retryAfter == "" || attempt == maxRetries || !w.spend(wait) {
			return fetched{}, errRateLimited
		}
		if err := sleep(ctx, wait); err != nil {
			return fetched{}, classify(err)
		}
	}
}

// send makes one request, without pacing and without repeating it.
func (w *Web) send(ctx context.Context, method, rawURL string, body []byte, contentType string, limit int64, timeout time.Duration) (fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req := must(http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body)))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fetched{}, scrub(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fetched{}, err
	}
	res := fetched{Status: resp.StatusCode, Header: resp.Header, Body: data}
	if int64(len(data)) > limit {
		res.Body, res.Over = data[:limit], true
	}
	return res, nil
}

// Do sends one request of the enrollment client, paced like every connection and not repeated
// (enroll.Transport). The status and the body are returned as they are.
func (w *Web) Do(ctx context.Context, method, rawURL string, body []byte, contentType string, slow bool) (enroll.Response, error) {
	if u, err := url.Parse(rawURL); err != nil || u.Scheme != "https" {
		return enroll.Response{}, classify(errNotHTTPS)
	}
	if err := w.pace(ctx); err != nil {
		return enroll.Response{}, classify(err)
	}
	timeout := w.timing.Request
	if slow {
		timeout = w.timing.Slow
	}
	res, err := w.send(ctx, method, rawURL, body, contentType, enroll.MaxBody, timeout)
	if err != nil {
		return enroll.Response{}, classify(err)
	}
	return enroll.Response{Status: res.Status, Header: res.Header, Body: res.Body, Over: res.Over}, nil
}

// Backoff waits for the Retry-After of a response within the budget of the run
// (enroll.Transport); a response without the header is waited for like a header of one second.
func (w *Web) Backoff(ctx context.Context, resp enroll.Response) error {
	wait := w.retryWait(resp.Header.Get("Retry-After"))
	if !w.spend(wait) {
		return errRateLimited
	}
	return sleep(ctx, wait)
}

// scrub removes the URL that net/http puts around an error.
func scrub(err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err
	}
	return err
}

// retryWait converts a Retry-After value (seconds or an HTTP date) to a wait.
func (w *Web) retryWait(value string) time.Duration {
	seconds := int64(defaultRetryAfter)
	if n, err := strconv.ParseInt(value, 10, 64); err == nil && n >= 0 {
		seconds = min(n, maxRetryAfter)
	} else if t, err := http.ParseTime(value); err == nil {
		seconds = min(max(int64(time.Until(t).Seconds()), 0), maxRetryAfter)
	}
	return time.Duration(seconds) * w.timing.RetryUnit
}

// spend takes wait from the budget of the run, if it is left.
func (w *Web) spend(wait time.Duration) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.spent+wait > w.timing.RetryBudget {
		return false
	}
	w.spent += wait
	return true
}

// pace waits until at least Gap has passed since the last connection, plus a random time up
// to Jitter.
func (w *Web) pace(ctx context.Context) error {
	w.mu.Lock()
	now := time.Now()
	start := now
	if next := w.last.Add(w.timing.Gap); next.After(start) {
		start = next
	}
	if w.timing.Jitter > 0 {
		start = start.Add(rand.N(w.timing.Jitter))
	}
	w.last = start
	w.mu.Unlock()
	return sleep(ctx, start.Sub(now))
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
