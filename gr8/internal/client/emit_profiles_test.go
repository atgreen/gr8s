package client

import (
	"encoding/json"
	"os"
	"testing"
)

// TestEmitLoginProfiles writes the objects `gr8 login claude` applies, for the gr8s
// suite to validate (GR8_EMIT names the directory); otherwise it checks they marshal.
func TestEmitLoginProfiles(t *testing.T) {
	for name, object := range map[string]map[string]any{
		"security-profile.json": ClaudeSecurityProfile("gr8"),
		"sandbox-profile.json":  ClaudeSandboxProfile(),
	} {
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if dir := os.Getenv("GR8_EMIT"); dir != "" {
			if err := os.WriteFile(dir+"/"+name, raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
