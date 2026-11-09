// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

// HTTPTransport is a Transport over an http.Client, for tests that do not need the paced and
// filtered client of the tool. It never follows a redirect and reads at most MaxBody bytes.
type HTTPTransport struct {
	Client *http.Client
	// RetryUnit is the length of a second of Retry-After; zero means a second.
	RetryUnit time.Duration
	// MaxWaits is how many waits Backoff accepts.
	MaxWaits int

	waited int
}

// Do implements Transport.
func (t *HTTPTransport) Do(ctx context.Context, method, rawURL string, body []byte, contentType string, _ bool) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	client := *t.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return Response{}, err
	}
	out := Response{Status: resp.StatusCode, Header: resp.Header, Body: data}
	if len(data) > MaxBody {
		out.Body, out.Over = data[:MaxBody], true
	}
	return out, nil
}

// ErrBackoff is returned by Backoff when it has waited as often as it may.
var ErrBackoff = errors.New("enroll: no more waiting for a rate limit")

// Backoff implements Transport.
func (t *HTTPTransport) Backoff(ctx context.Context, resp Response) error {
	if t.waited >= t.MaxWaits {
		return ErrBackoff
	}
	t.waited++
	seconds, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || seconds < 0 {
		seconds = 1
	}
	unit := t.RetryUnit
	if unit == 0 {
		unit = time.Second
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(seconds) * unit):
		return nil
	}
}
