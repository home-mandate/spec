// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// MaxBody is the largest response the client reads (RELAY-v0 section 5.1: a gateway MAY
// reject a response larger than 64 KiB).
const MaxBody = 64 << 10

const (
	problemPrefix = "https://home-mandate.org/relay/errors/"
	// maxAttempts is how often a request is repeated after a rate limit or a bad nonce.
	maxAttempts = 3
	// ServerInternal is the name of every error response that is none of the listed ones.
	ServerInternal = "server-internal"
	contentJOSE    = "application/jose"
)

// errorNames are the errors of RELAY-v0 section 5.1.
var errorNames = map[string]bool{
	"malformed": true, "bad-nonce": true, "bad-signature": true, "pairing-refused": true,
	"confirmation-required": true, "offline-too-long": true, "blocked": true, "bad-csr": true,
	"name-unavailable": true, "key-conflict": true, "unpaired": true, "rate-limited": true,
	ServerInternal: true,
}

// Response is a response of the enrollment endpoint.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	// Over is set if the body was longer than MaxBody.
	Over bool
}

// Transport sends the requests. Do sends one request; the status is returned as it is.
// Backoff waits before a request is repeated after a response that limits the rate, and
// fails if waiting would exceed what the run accepts.
type Transport interface {
	Do(ctx context.Context, method, rawURL string, body []byte, contentType string, slow bool) (Response, error)
	Backoff(ctx context.Context, resp Response) error
}

// Error is an error response of the operator: one of the names of section 5.1 and the
// status. It holds nothing else of the response.
type Error struct {
	Name   string
	Status int
}

func (e *Error) Error() string { return "enrollment error " + e.Name }

// ErrorName returns the name of the error of a response, empty for a success. A response
// that is no problem document of section 5.1 is server-internal.
func ErrorName(r Response) string {
	if r.Status >= 200 && r.Status < 300 {
		return ""
	}
	var p struct {
		Type string `json:"type"`
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/problem+json") || json.Unmarshal(r.Body, &p) != nil {
		return ServerInternal
	}
	name, ok := strings.CutPrefix(p.Type, problemPrefix)
	if !ok || !errorNames[name] {
		return ServerInternal
	}
	return name
}

// Directory holds the URLs of the directory (RELAY-v0 section 5.1).
type Directory struct {
	NewNonce  string `json:"new_nonce"`
	Pair      string `json:"pair"`
	KeyChange string `json:"key_change"`
}

// Client talks to one enrollment endpoint. It sends only to HTTPS URLs on Host.
type Client struct {
	T Transport
	// Host is the host (with a port, if any) of the enrollment URL.
	Host string
	Dir  Directory
	// Validate, if set, is called with the definition name and the body of every success
	// response, so that the caller can check it against the schema.
	Validate func(def string, body []byte)

	// NoNonceOnError counts error responses without a valid Replay-Nonce.
	NoNonceOnError int

	nonce string
}

// ErrHost is returned for a URL that is not an HTTPS URL on the enrollment host.
var ErrHost = errors.New("enroll: the URL is not on the enrollment host")

// CheckURL accepts an HTTPS URL on host, without user info and fragment.
func CheckURL(raw, host string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Host == "" || u.Host != host {
		return ErrHost
	}
	return nil
}

// Load fetches the directory at enrollmentURL (RELAY-v0 section 5.1).
func (c *Client) Load(ctx context.Context, enrollmentURL string) (Response, error) {
	if err := CheckURL(enrollmentURL, c.Host); err != nil {
		return Response{}, err
	}
	resp, err := c.T.Do(ctx, http.MethodGet, enrollmentURL, nil, "", false)
	if err != nil {
		return resp, err
	}
	c.remember(resp)
	if resp.Status != http.StatusOK {
		return resp, &Error{ErrorName(resp), resp.Status}
	}
	var dir Directory
	if json.Unmarshal(resp.Body, &dir) != nil {
		return resp, errors.New("enroll: the directory is not JSON")
	}
	for _, u := range []string{dir.NewNonce, dir.Pair, dir.KeyChange} {
		if err := CheckURL(u, c.Host); err != nil {
			return resp, err
		}
	}
	c.Dir = dir
	c.validate("directory", resp.Body)
	return resp, nil
}

func (c *Client) validate(def string, body []byte) {
	if c.Validate != nil {
		c.Validate(def, body)
	}
}

// remember keeps the nonce of a response for the next request.
func (c *Client) remember(resp Response) {
	c.nonce = ""
	if n := resp.Header.Get("Replay-Nonce"); ValidNonce(n) {
		c.nonce = n
	} else if resp.Status >= 400 {
		c.NoNonceOnError++
	}
}

// ValidNonce reports whether n is base64url without padding of at least 16 bytes.
func ValidNonce(n string) bool {
	raw, err := b64.Strict().DecodeString(n)
	return err == nil && len(raw) >= 16 && len(n) <= 128
}

// FreshNonce asks new_nonce for a nonce with HEAD and returns the response too.
func (c *Client) FreshNonce(ctx context.Context) (string, Response, error) {
	if err := CheckURL(c.Dir.NewNonce, c.Host); err != nil {
		return "", Response{}, err
	}
	resp, err := c.T.Do(ctx, http.MethodHead, c.Dir.NewNonce, nil, "", false)
	if err != nil {
		return "", resp, err
	}
	c.remember(resp)
	if resp.Status != http.StatusOK || c.nonce == "" {
		return "", resp, &Error{ErrorName(resp), resp.Status}
	}
	return c.nonce, resp, nil
}

// TakeNonce returns the nonce of the last response, or fetches one; each nonce is used once.
func (c *Client) TakeNonce(ctx context.Context) (string, error) {
	if n := c.nonce; n != "" {
		c.nonce = ""
		return n, nil
	}
	n, _, err := c.FreshNonce(ctx)
	c.nonce = ""
	return n, err
}

// Send sends the request that build makes with a nonce, as a POST to rawURL. It repeats the
// request, with a fresh nonce, after a rate limit and, if retryNonce is set, once after
// bad-nonce. It returns the last response.
func (c *Client) Send(ctx context.Context, rawURL string, build func(nonce string) string, retryNonce, slow bool) (Response, error) {
	if err := CheckURL(rawURL, c.Host); err != nil {
		return Response{}, err
	}
	var resp Response
	nonceRetried := false
	for range maxAttempts {
		nonce, err := c.TakeNonce(ctx)
		if err != nil {
			return resp, err
		}
		if resp, err = c.T.Do(ctx, http.MethodPost, rawURL, []byte(build(nonce)), contentJOSE, slow); err != nil {
			return resp, err
		}
		c.remember(resp)
		switch name := ErrorName(resp); {
		case resp.Status == http.StatusTooManyRequests || resp.Status == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "":
			if err := c.T.Backoff(ctx, resp); err != nil {
				return resp, err
			}
		case name == "bad-nonce" && retryNonce && !nonceRetried:
			nonceRetried = true
		default:
			return resp, nil
		}
	}
	return resp, &Error{"rate-limited", resp.Status}
}
