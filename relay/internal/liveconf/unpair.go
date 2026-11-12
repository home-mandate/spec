// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"

	"github.com/home-mandate/spec/relay/internal/enroll"
)

var errNoKey = errors.New("no key of the state file fits the installation")

// signersOf returns the signers of the keys of the state file by ID.
func signersOf(keys []StateKey) (map[string]*enroll.Signer, error) {
	out := make(map[string]*enroll.Signer, len(keys))
	for _, k := range keys {
		der, err := base64.RawURLEncoding.DecodeString(k.Private)
		if err != nil {
			return nil, errors.New("a key of the state file is unreadable")
		}
		if out[k.ID], err = enroll.ParseSigner(der); err != nil {
			return nil, errors.New("a key of the state file is unreadable")
		}
	}
	return out, nil
}

// isUnpaired tells whether the answer to an unpairing means the installation is unpaired: the
// installation it returns says so, or the operator answers unpaired (410). A 200 that leaves
// the installation active is no success.
func isUnpaired(inst enroll.Installation, err error) bool {
	if err == nil {
		return inst.Status == "unpaired"
	}
	var apiErr *enroll.Error
	return errors.As(err, &apiErr) && apiErr.Name == "unpaired"
}

// unpairInstallation unpairs a test installation (RELAY-v0 section 5.7) with the key the state
// file names for it and, if the operator does not know that key (a key change whose
// record was lost), with the other keys of the run. An installation that is unpaired already
// counts as done. The error never contains the installation URL.
func unpairInstallation(ctx context.Context, w *Web, enrollment string, inst StateInstallation, keys []StateKey) error {
	signers, err := signersOf(keys)
	if err != nil {
		return err
	}
	u, err := url.Parse(enrollment)
	if err != nil {
		return errors.New("the enrollment URL is unusable")
	}
	c := &enroll.Client{T: w, Host: u.Host}
	if _, err := c.Load(ctx, enrollment); err != nil {
		return errors.New("the directory could not be fetched")
	}
	order := []string{inst.Key}
	for _, k := range keys {
		if !slices.Contains(order, k.ID) {
			order = append(order, k.ID)
		}
	}
	for _, id := range order {
		signer := signers[id]
		if signer == nil {
			continue
		}
		done, err := c.Unpair(ctx, enroll.Identity{URL: inst.URL, Signer: signer})
		var apiErr *enroll.Error
		switch {
		case isUnpaired(done, err):
			return nil
		case errors.As(err, &apiErr) && apiErr.Name == "bad-signature":
			continue
		}
		return errors.New("the installation could not be unpaired")
	}
	return errNoKey
}

// UnpairInstallation is the unpairing the command uses. It is exported for the tests of the
// command, which build an environment for a reference operator and need the real unpairing.
func UnpairInstallation(ctx context.Context, w *Web, enrollment string, inst StateInstallation, keys []StateKey) error {
	return unpairInstallation(ctx, w, enrollment, inst, keys)
}
