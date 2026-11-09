// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Identity is an installation as the gateway knows it: its URL, the kid of its requests, and
// the key it signs with.
type Identity struct {
	URL    string
	Signer *Signer
}

// OwnDomain is the own-domain registration of an installation (RELAY-v0 section 6.4).
type OwnDomain struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

// Installation is the installation of section 5.3; members the tool does not use are left out.
type Installation struct {
	Status         string     `json:"status"`
	HomeID         string     `json:"home_id"`
	PublicName     string     `json:"public_name"`
	MaxOfflineDays int        `json:"max_offline_days"`
	Certificate    string     `json:"certificate"`
	ACMEChallenge  string     `json:"acme_challenge"`
	ACMEAccount    string     `json:"acme_account"`
	CAAIdentity    string     `json:"caa_identity"`
	OwnDomain      *OwnDomain `json:"own_domain"`
}

// Issued is a certificate response (RELAY-v0 section 5.4): the chain in DER and not_after.
type Issued struct {
	Chain    [][]byte
	NotAfter time.Time
}

// Paired is the answer to a pairing request.
type Paired struct {
	// Location is the installation URL, as sent.
	Location     string
	Installation Installation
	Certificate  Issued
}

// apiError returns the error of a response, nil if its status is one of ok.
func apiError(resp Response, ok ...int) error {
	for _, s := range ok {
		if resp.Status == s {
			return nil
		}
	}
	name := ErrorName(resp)
	if name == "" {
		name = ServerInternal
	}
	return &Error{name, resp.Status}
}

// NewCSR returns a certificate request (PKCS #10, DER) for a key.
func NewCSR(key crypto.Signer) ([]byte, error) {
	return x509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, key)
}

func csrPayload(csr []byte) string { return `{"csr":"` + B64(csr) + `"}` }

// Pair sends a pairing request (RELAY-v0 section 5.2) with the code (as sent: upper case,
// without hyphens) and the certificate request, signed with the installation key.
func (c *Client) Pair(ctx context.Context, s *Signer, code string, csr []byte) (Paired, Response, error) {
	payload := `{"code":"` + code + `","csr":"` + B64(csr) + `"}`
	resp, err := c.Send(ctx, c.Dir.Pair, func(nonce string) string {
		return Spec{Signer: s, JWK: true, Nonce: nonce, URL: c.Dir.Pair, Payload: payload}.Compact()
	}, true, false)
	if err != nil {
		return Paired{}, resp, err
	}
	if err := apiError(resp, http.StatusCreated); err != nil {
		return Paired{}, resp, err
	}
	var body struct {
		Installation      Installation    `json:"installation"`
		TunnelCertificate json.RawMessage `json:"tunnel_certificate"`
	}
	if json.Unmarshal(resp.Body, &body) != nil {
		return Paired{}, resp, errors.New("enroll: the pairing response is not JSON")
	}
	cert, err := parseIssued(body.TunnelCertificate)
	if err != nil {
		return Paired{}, resp, err
	}
	c.validate("pair_response", resp.Body)
	return Paired{Location: resp.Header.Get("Location"), Installation: body.Installation, Certificate: cert}, resp, nil
}

func parseIssued(raw []byte) (Issued, error) {
	var body struct {
		Chain    []string `json:"chain"`
		NotAfter string   `json:"not_after"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return Issued{}, errors.New("enroll: the certificate response is not JSON")
	}
	out := Issued{}
	for _, c := range body.Chain {
		der, err := b64.Strict().DecodeString(c)
		if err != nil {
			return Issued{}, errors.New("enroll: a certificate is not base64url")
		}
		out.Chain = append(out.Chain, der)
	}
	t, err := time.Parse(time.RFC3339, body.NotAfter)
	if err != nil {
		return Issued{}, errors.New("enroll: not_after is not a time")
	}
	out.NotAfter = t
	return out, nil
}

// post sends a signed request of an installation with a payload (empty for a read).
func (c *Client) post(ctx context.Context, id Identity, rawURL, payload string, slow bool) (Response, error) {
	return c.Send(ctx, rawURL, func(nonce string) string {
		return Spec{Signer: id.Signer, Kid: id.URL, Nonce: nonce, URL: rawURL, Payload: payload}.Compact()
	}, true, slow)
}

func (c *Client) installation(resp Response, err error) (Installation, error) {
	if err != nil {
		return Installation{}, err
	}
	if err := apiError(resp, http.StatusOK); err != nil {
		return Installation{}, err
	}
	var inst Installation
	if json.Unmarshal(resp.Body, &inst) != nil {
		return Installation{}, errors.New("enroll: the installation is not JSON")
	}
	c.validate("installation", resp.Body)
	return inst, nil
}

// Read reads the installation (POST-as-GET, section 5.3).
func (c *Client) Read(ctx context.Context, id Identity) (Installation, error) {
	resp, err := c.post(ctx, id, id.URL, "", false)
	return c.installation(resp, err)
}

// Update sends an installation update (payload: the JSON text of the update). Updates may
// wait for DNS, so they get the longer time limit.
func (c *Client) Update(ctx context.Context, id Identity, payload string) (Installation, error) {
	resp, err := c.post(ctx, id, id.URL, payload, true)
	return c.installation(resp, err)
}

// ReportACME reports the ACME account (section 5.6).
func (c *Client) ReportACME(ctx context.Context, id Identity, account, caaIdentity string) (Installation, error) {
	return c.Update(ctx, id, `{"acme_account":"`+account+`","caa_identity":"`+caaIdentity+`"}`)
}

// SetOwnDomain registers an own-domain name (section 6.4); "" removes it.
func (c *Client) SetOwnDomain(ctx context.Context, id Identity, name string) (Installation, error) {
	if name == "" {
		return c.Update(ctx, id, `{"own_domain":null}`)
	}
	return c.Update(ctx, id, `{"own_domain":"`+name+`"}`)
}

// Unpair unpairs the installation (section 5.7).
func (c *Client) Unpair(ctx context.Context, id Identity) (Installation, error) {
	return c.Update(ctx, id, `{"status":"unpaired"}`)
}

// Certificate asks for a tunnel certificate (section 5.4).
func (c *Client) Certificate(ctx context.Context, id Identity, certificateURL string, csr []byte) (Issued, Response, error) {
	resp, err := c.post(ctx, id, certificateURL, csrPayload(csr), false)
	if err != nil {
		return Issued{}, resp, err
	}
	if err := apiError(resp, http.StatusOK); err != nil {
		return Issued{}, resp, err
	}
	issued, err := parseIssued(resp.Body)
	if err == nil {
		c.validate("certificate_response", resp.Body)
	}
	return issued, resp, err
}

// Challenge publishes challenge values at the operator (section 5.6) and returns the values
// of the answer.
func (c *Client) Challenge(ctx context.Context, id Identity, challengeURL string, values []string) ([]string, error) {
	if values == nil {
		values = []string{}
	}
	list, _ := json.Marshal(values)
	resp, err := c.post(ctx, id, challengeURL, `{"values":`+string(list)+`}`, true)
	if err != nil {
		return nil, err
	}
	if err := apiError(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var body struct {
		Values []string `json:"values"`
	}
	if json.Unmarshal(resp.Body, &body) != nil {
		return nil, errors.New("enroll: the challenge answer is not JSON")
	}
	return body.Values, nil
}

// KeyChangeJWS builds the inner JWS of a key change (section 5.5), signed with the new key.
func KeyChangeJWS(newKey *Signer, oldKeyJWK, installation, rawURL string) string {
	head := B64([]byte(render([]member{{"alg", quote(newKey.Alg())}, {"jwk", newKey.JWK()}, {"url", quote(rawURL)}})))
	payload := B64([]byte(`{"installation":` + quote(installation) + `,"old_key":` + oldKeyJWK + `}`))
	return head + "." + payload + "." + B64(newKey.Sign([]byte(head+"."+payload)))
}

// KeyChange replaces the installation key by newKey.
func (c *Client) KeyChange(ctx context.Context, id Identity, newKey *Signer) (Installation, error) {
	inner := KeyChangeJWS(newKey, id.Signer.JWK(), id.URL, c.Dir.KeyChange)
	resp, err := c.post(ctx, id, c.Dir.KeyChange, `{"jws":"`+inner+`"}`, false)
	return c.installation(resp, err)
}
