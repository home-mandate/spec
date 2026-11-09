// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"slices"

	"github.com/home-mandate/spec/relay"
	"github.com/home-mandate/spec/relay/internal/frames"
)

// Files of the cases the class relay plays.
const (
	tlsFile     = "conformance/tls-v0.json"
	framesFile  = "conformance/frames-v0.json"
	bindingFile = "conformance/binding-v0.json"
)

// tlsProbe is a case of tls-v0.json.
type tlsProbe struct {
	ID     string `json:"id"`
	Client struct {
		Version     string   `json:"version"`
		Groups      []string `json:"groups"`
		ALPN        []string `json:"alpn"`
		Certificate string   `json:"certificate"`
		Resume      bool     `json:"resume"`
	} `json:"client"`
	Expected string `json:"expected"`
}

// framesCase is a case of frames-v0.json.
type framesCase struct {
	ID     string `json:"id"`
	Frames []struct {
		From string `json:"from"`
		Hex  string `json:"hex"`
	} `json:"frames"`
	Expected string `json:"expected"`
	At       *int   `json:"at"`
}

// bindingCase is a case of binding-v0.json.
type bindingCase struct {
	ID     string `json:"id"`
	Tokens []struct {
		Token        string `json:"token"`
		Installation string `json:"installation"`
		State        string `json:"state"`
	} `json:"tokens"`
	ControlNotBefore string `json:"control_not_before"`
	LimitReached     bool   `json:"limit_reached"`
	Connection       struct {
		Installation string `json:"installation"`
		NotBefore    string `json:"not_before"`
	} `json:"connection"`
	FirstBytes string    `json:"first_bytes"`
	Expected   string    `json:"expected"`
	Consumed   *[]string `json:"consumed"`
}

// loadCases reads the cases of a file of package relay. The files are embedded and checked by the
// tests of the repository, so a file that does not parse is a defect of the tool.
func loadCases[T any](path string) []T {
	var file struct {
		Cases []T `json:"cases"`
	}
	must0(json.Unmarshal(must(fs.ReadFile(relay.FS(), path)), &file))
	return file.Cases
}

// liveHello is the hello the tool sends before the frames of a case; liveAck stands for the
// answer of the relay when the tool asks the rules of the receiver what a live sequence is.
var (
	liveHello = must(frames.Hello{MinVersion: 1, MaxVersion: 1, Software: "relay-conformance"}.Encode())
	liveAck   = must(frames.HelloAck{Version: 1, Software: "relay", Heartbeat: 30, MaxStreams: 1}.Encode())
)

// livePlay is a case of frames-v0.json as the tool plays it: the frames the gateway sends in
// order, the last of which the relay must refuse.
type livePlay struct {
	id     string
	frames [][]byte
	// kind is the check the case belongs to.
	kind string
}

var errNotPlayable = errors.New("not playable live")

// playOf decides whether a case can be played against a live relay and with which frames. A case
// is playable if the first frame it holds that its receiver refuses is a frame of the gateway and
// the frames before it are the hello of the gateway and the hello-ack of the relay, which a live
// relay sends by itself: where the outcome would depend on timing (a ping, a pong, a stream-open
// of the relay), or on what the relay announces by itself (pins), it is not played. The hello
// the tool sends is its own, and the rules of the receiver are asked about the sequence as it
// is sent: a case whose frame is no error in that sequence (a drain "before hello-ack" that
// arrives after it) is not played either.
func playOf(c framesCase) (livePlay, error) {
	if c.Expected != "error" || c.At == nil || len(c.Frames) == 0 || c.Frames[0].From != frames.Gateway {
		return livePlay{}, errNotPlayable
	}
	var sent [][]byte
	for i, f := range c.Frames {
		raw := must(hex.DecodeString(f.Hex))
		switch {
		case f.From == frames.Gateway:
			sent = append(sent, raw)
		case i != 1:
			return livePlay{}, errNotPlayable
		}
	}
	if *c.At >= len(c.Frames) || c.Frames[*c.At].From != frames.Gateway {
		return livePlay{}, errNotPlayable
	}
	name, _ := frames.Peek(sent[len(sent)-1])
	if name == "pins-ack" {
		return livePlay{}, errNotPlayable
	}
	kind := CheckRelayFrames
	if name == "pins" {
		kind = CheckRelayPins
	}
	in := []frames.Frame{{From: frames.Gateway, Data: sent[0]}}
	if len(sent) > 1 {
		in = append(in, frames.Frame{From: frames.Relay, Data: liveAck})
		for _, raw := range sent[1:] {
			in = append(in, frames.Frame{From: frames.Gateway, Data: raw})
		}
	}
	if _, at, err := frames.Control(in); err == nil || at != len(in)-1 {
		return livePlay{}, errNotPlayable
	}
	return livePlay{id: c.ID, frames: sent, kind: kind}, nil
}

// playableFrames returns the cases of frames-v0.json that a live test plays.
func playableFrames() []livePlay {
	var plays []livePlay
	for _, c := range loadCases[framesCase](framesFile) {
		if p, err := playOf(c); err == nil {
			plays = append(plays, p)
		}
	}
	return plays
}

// substitute replaces the token of a case by a live token: every byte of the payload that equals
// the byte of the case's reference token becomes the byte of the live one, every byte that
// differs from it differs from the live one in the same bits. Bytes after the 32 and the header
// stay as they are.
func substitute(first, reference, live []byte) []byte {
	out := slices.Clone(first)
	for i := 0; i < len(reference) && 4+i < len(out); i++ {
		out[4+i] = live[i] ^ (first[4+i] ^ reference[i])
	}
	return out
}
