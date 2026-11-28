// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// LoginsToOffer names the logins gr8 offers to move into the cluster before running
// command (podster-pojp): those for command that the host holds, aren't stored yet,
// and the user hasn't declined.
func LoginsToOffer(command string, logins map[string]Login, stored, declined []string,
	onHost func(Login) bool) []string {
	var offer []string
	for _, name := range LoginNames(logins) {
		login := logins[name]
		if login.For(command) && !slices.Contains(stored, name) && !slices.Contains(declined, name) && onHost(login) {
			offer = append(offer, name)
		}
	}
	return offer
}

// declinedLogins is where gr8 remembers the logins the user said no to, one per line,
// so it asks once.
func declinedLogins(home string) string {
	return filepath.Join(home, ".config", "gr8", "declined-logins")
}

// DeclinedLogins reads the logins the user declined to move.
func DeclinedLogins(home string) []string {
	raw, _ := os.ReadFile(declinedLogins(home))
	return strings.Fields(string(raw))
}

func declineLogin(home, name string) error {
	path := declinedLogins(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintln(file, name)
	return err
}

// TerminalConfirm asks on the terminal, taking anything but n or no as yes.
func TerminalConfirm(in io.Reader, out io.Writer) func(string) bool {
	return func(prompt string) bool {
		fmt.Fprintf(out, "gr8: %s [Y/n] ", prompt)
		line, _ := bufio.NewReader(in).ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer != "n" && answer != "no"
	}
}

// offerLogins asks, for each login LoginsToOffer names, whether to move it into the
// cluster, stores those the user accepts and remembers those declined. It returns
// STORED with the new ones added.
func offerLogins(options Options, home, command string, logins map[string]Login, stored []string,
	ask func(string) bool) []string {
	onHost := func(login Login) bool {
		_, err := login.HostTokens(home)
		return err == nil
	}
	for _, name := range LoginsToOffer(command, logins, stored, DeclinedLogins(home), onHost) {
		if !ask(fmt.Sprintf("%s's login is on this machine but not in the cluster, so the sandbox can't use it. "+
			"Move it there, so the sandbox holds only stand-ins?", name)) {
			if err := declineLogin(home, name); err == nil {
				fmt.Fprintf(os.Stderr, "gr8: not asking again; gr8 --login %s moves it any time\n", name)
			}
			continue
		}
		if err := StoreLogin(options.Kubeconfig, options.Namespace, name); err != nil {
			fmt.Fprintf(os.Stderr, "gr8: moving %s's login: %v\n", name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "gr8: %s's login is in the cluster; this sandbox holds stand-in tokens\n", name)
		stored = append(stored, name)
	}
	return stored
}
