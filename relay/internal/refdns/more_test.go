// SPDX-License-Identifier: Apache-2.0

package refdns

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestNewFailsWhenASocketCannotBeOpened(t *testing.T) {
	realUDP, realTCP := listenUDP, listenTCP
	defer func() { listenUDP, listenTCP = realUDP, realTCP }()
	boom := errors.New("no socket")
	listenUDP = func(string, *net.UDPAddr) (*net.UDPConn, error) { return nil, boom }
	if _, err := New("a.example"); !errors.Is(err, boom) {
		t.Errorf("no UDP socket: %v", err)
	}
	listenUDP = realUDP
	listenTCP = func(string, string) (net.Listener, error) { return nil, boom }
	start := time.Now()
	if _, err := New("a.example"); !errors.Is(err, boom) {
		t.Errorf("no TCP socket: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the retries took long")
	}
	// The second name server fails: the first is closed again.
	calls := 0
	listenUDP = func(network string, addr *net.UDPAddr) (*net.UDPConn, error) {
		if calls++; calls > 1 {
			return nil, boom
		}
		return realUDP(network, addr)
	}
	listenTCP = realTCP
	if _, err := New("a.example"); !errors.Is(err, boom) {
		t.Errorf("the second server: %v", err)
	}
}

func TestMustPanicsOnAnError(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	must(0, errors.New("x"))
}
