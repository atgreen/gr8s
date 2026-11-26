package client

import "strings"

// passedEnv names the variables a command gets from the caller's environment
// without asking; credentials such as SSH_AUTH_SOCK, *_TOKEN or AWS_* pass
// only when named with --env.
var passedEnv = map[string]bool{
	"TERM": true, "COLORTERM": true, "LANG": true, "LANGUAGE": true, "TZ": true,
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"EDITOR": true, "VISUAL": true, "PAGER": true, "NO_COLOR": true,
}

// SelectEnv returns the NAME=VALUE entries of environ that a command gets:
// the default set, LC_* locale variables, and the names in extra.
func SelectEnv(environ []string, extra []string) []string {
	named := make(map[string]bool, len(extra))
	for _, name := range extra {
		named[name] = true
	}
	var selected []string
	for _, entry := range environ {
		name, _, found := strings.Cut(entry, "=")
		if found && (passedEnv[name] || strings.HasPrefix(name, "LC_") || named[name]) {
			selected = append(selected, entry)
		}
	}
	return selected
}
