// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestGr8OffersALoginTheHostHoldsAndTheClusterDoesnt(t *testing.T) {
	logins := map[string]Login{
		"claude": {Commands: []string{"claude"}},
		"acme":   {Commands: []string{"acme", "claude"}, File: "missing"},
		"other":  {Commands: []string{"other"}},
	}
	onHost := func(login Login) bool { return login.File != "missing" }
	offer := func(stored, declined []string) []string {
		return LoginsToOffer("claude", logins, stored, declined, onHost)
	}
	if got := offer(nil, nil); !slices.Equal(got, []string{"claude"}) {
		t.Errorf("offered %v, want claude alone: acme isn't on the host, other isn't for claude", got)
	}
	if got := offer([]string{"claude"}, nil); got != nil {
		t.Errorf("offered %v for a stored login", got)
	}
	if got := offer(nil, []string{"claude"}); got != nil {
		t.Errorf("offered %v for a declined login", got)
	}
}

func TestADeclinedLoginIsNotOfferedAgain(t *testing.T) {
	home := t.TempDir()
	if got := DeclinedLogins(home); len(got) != 0 {
		t.Errorf("a fresh home declined %v", got)
	}
	for _, name := range []string{"claude", "acme"} {
		if err := declineLogin(home, name); err != nil {
			t.Fatal(err)
		}
	}
	if got := DeclinedLogins(home); !slices.Equal(got, []string{"claude", "acme"}) {
		t.Errorf("DeclinedLogins = %v", got)
	}
}

func TestTheOfferDefaultsToYes(t *testing.T) {
	for answer, want := range map[string]bool{"\n": true, "y\n": true, "yes\n": true, "n\n": false, "No\n": false, "": true} {
		var out bytes.Buffer
		if got := TerminalConfirm(strings.NewReader(answer), &out)("Move it?"); got != want {
			t.Errorf("answer %q = %v, want %v", answer, got, want)
		}
		if !strings.Contains(out.String(), "[Y/n]") {
			t.Errorf("prompt %q doesn't show yes as the default", out.String())
		}
	}
}
