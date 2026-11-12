// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const (
	stateVersion = 1
	// maxStateBytes limits the state file that -cleanup reads.
	maxStateBytes = 64 << 10
	maxStateKeys  = 8
	// stateMode is the mode of the state file: it holds throwaway private keys.
	stateMode  = 0o600
	lockSuffix = ".lock"
)

// ErrState is returned for a state file that cannot be used.
var ErrState = errors.New("liveconf: unusable state file")

// StateKey is a throwaway private key of a run (PKCS #8, base64url).
type StateKey struct {
	ID      string `json:"id"`
	Alg     string `json:"alg"`
	Private string `json:"private"`
}

// StateInstallation is a test installation. The URL is what unpairing needs, and it stays
// secret: it is the capability of the installation.
type StateInstallation struct {
	URL      string `json:"url"`
	Key      string `json:"key"`
	Unpaired bool   `json:"unpaired"`
}

// State is the content of the state file. It holds no command line of a DNS hook and no
// pairing code.
type State struct {
	Version       int                 `json:"version"`
	Operator      string              `json:"operator"`
	Created       string              `json:"created"`
	Keys          []StateKey          `json:"keys"`
	Installations []StateInstallation `json:"installations"`
	// OwnName is the own-domain name whose TXT record a DNS hook set; -cleanup removes it
	// (with the hook given again: the state file never holds a command line).
	OwnName string `json:"own_name,omitempty"`
}

func newState(operator string, keys []StateKey) State {
	return State{Version: stateVersion, Operator: operator, Created: time.Now().UTC().Format(time.RFC3339),
		Keys: keys, Installations: []StateInstallation{}}
}

// WithInstallation returns the state with one more installation.
func (s State) WithInstallation(inst StateInstallation) State {
	s.Installations = append(slices.Clone(s.Installations), inst)
	return s
}

// WithUnpaired returns the state with installation i marked as unpaired.
func (s State) WithUnpaired(i int) State {
	s.Installations = slices.Clone(s.Installations)
	s.Installations[i].Unpaired = true
	return s
}

// WithKey returns the state with installation i using the key with this ID.
func (s State) WithKey(i int, id string) State {
	s.Installations = slices.Clone(s.Installations)
	s.Installations[i].Key = id
	return s
}

// WithOwnName returns the state with the name of the own-domain record.
func (s State) WithOwnName(name string) State {
	s.OwnName = name
	return s
}

// Pending reports how many installations are not unpaired yet.
func (s State) Pending() int {
	n := 0
	for _, inst := range s.Installations {
		if !inst.Unpaired {
			n++
		}
	}
	return n
}

// StateFile is a state file held under a lock.
type StateFile struct {
	path  string
	lock  *os.File
	state State
}

// CreateState creates the state file with the state. The file must not exist, is not reached
// through a symbolic link, has mode 0600, and is written atomically and synced; another
// process cannot hold the same file at the same time.
func CreateState(path string, s State) (*StateFile, error) {
	lock, err := lockFile(path)
	if err != nil {
		return nil, err
	}
	f := &StateFile{path: path, lock: lock, state: s}
	if err := f.write(true); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// OpenState opens and locks an existing state file, with a size limit and strict parsing.
func OpenState(path string) (*StateFile, error) {
	lock, err := lockFile(path)
	if err != nil {
		return nil, err
	}
	s, err := readState(path)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return &StateFile{path: path, lock: lock, state: s}, nil
}

func readState(path string) (State, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return State{}, fmt.Errorf("%w: %w", ErrState, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil || len(data) > maxStateBytes {
		return State{}, fmt.Errorf("%w: unreadable or larger than %d bytes", ErrState, maxStateBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s State
	if err := dec.Decode(&s); err != nil {
		return State{}, fmt.Errorf("%w: not a state file", ErrState)
	}
	if dec.More() || s.Version != stateVersion || !ValidDomain(s.Operator) ||
		len(s.Keys) > maxStateKeys || len(s.Installations) > MaxCodes+1 || len(s.OwnName) > 253 {
		return State{}, fmt.Errorf("%w: unexpected content", ErrState)
	}
	return s, nil
}

// lockFile takes the lock of the state file at path: a lock on a file next to it, because the
// state file itself is replaced on every write.
func lockFile(path string) (*os.File, error) {
	lock, err := os.OpenFile(path+lockSuffix, os.O_RDWR|os.O_CREATE|noFollow, stateMode)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrState, err)
	}
	if err := flock(lock); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("%w: in use by another process", ErrState)
	}
	return lock, nil
}

// State returns the content.
func (f *StateFile) State() State { return f.state }

// Save replaces the content atomically: a temporary file next to the state file is written,
// synced and renamed over it, and the directory is synced.
func (f *StateFile) Save(s State) error {
	f.state = s
	return f.write(false)
}

// write writes f.state to a temporary file next to the state file and syncs it. A new state
// file is then linked into place, which fails if the path exists; a saved one is renamed over
// the old one. Finally the directory is synced.
func (f *StateFile) write(create bool) error {
	data := must(json.MarshalIndent(f.state, "", "  "))
	tmp := f.path + ".tmp"
	flags := os.O_WRONLY | os.O_CREATE | noFollow
	if create {
		flags |= os.O_EXCL
	} else {
		flags |= os.O_TRUNC
	}
	file, err := os.OpenFile(tmp, flags, stateMode)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	_, werr := file.Write(append(data, '\n'))
	if err := errors.Join(werr, file.Sync(), file.Close()); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	place := os.Rename
	if create {
		place = linkAndRemove
	}
	if err := place(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	return syncDir(filepath.Dir(f.path))
}

// linkAndRemove gives the file at tmp the name path, if path does not exist, and removes tmp.
func linkAndRemove(tmp, path string) error {
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	return os.Remove(tmp)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	defer d.Close()
	return d.Sync()
}

// Remove deletes the state file and its lock file and releases the lock.
func (f *StateFile) Remove() error {
	err := os.Remove(f.path)
	if rmErr := os.Remove(f.path + lockSuffix); err == nil {
		err = rmErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// Close releases the lock and keeps the state file.
func (f *StateFile) Close() error { return f.lock.Close() }

// CheckInstallationURL accepts an installation URL only if it is an https URL on exactly the
// host (and port) of the enrollment URL, without user info and fragment: an operator cannot
// send the tool to another host by what it publishes or what a state file says.
func CheckInstallationURL(raw, enrollment string) error {
	u, err := url.Parse(raw)
	e, eerr := url.Parse(enrollment)
	if err != nil || eerr != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Host == "" || u.Host != e.Host {
		return errors.New("the installation URL is not on the enrollment host")
	}
	return nil
}
