// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"errors"
	"testing"
)

func TestControlRefusesWhatIsNoFrame(t *testing.T) {
	for name, f := range map[string]Frame{
		"two bytes":     {From: Gateway, Data: []byte{0x00, 0x01}},
		"no sender":     {From: "agent", Data: []byte{0x00, 0x01, 0x00, 0x00}},
		"short payload": {From: Gateway, Data: []byte{0x00, 0x01, 0x00, 0x05, 0x01}},
	} {
		if _, _, err := Control([]Frame{f}); !errors.Is(err, ErrCase) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPinsAckTooShortIsAnError(t *testing.T) {
	hello := []byte{0x00, 0x01, 0x00, 0x05, 0x01, 0x01, 0x01, 'g', 0x00}
	ack := []byte{0x00, 0x02, 0x00, 0x09, 0x01, 0x01, 'r', 0x00, 0x1e, 0x01, 0x00, 0x40, 0x00}
	short := []byte{0x00, 0x15, 0x00, 0x02, 0x00, 0x00}
	_, at, err := Control([]Frame{{Gateway, hello}, {Relay, ack}, {Gateway, short}})
	if !errors.Is(err, ErrFrame) || at != 2 {
		t.Errorf("at %d: %v", at, err)
	}
}
