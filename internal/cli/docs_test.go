package cli

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestEveryCommandIsDocumented fails when a command exists in the CLI but is missing from
// docs/commands.md (the command reference that the README links to). Every command needs a
// one-line Short description (it shows in --help) and an entry with an example in the reference.
func TestEveryCommandIsDocumented(t *testing.T) {
	ref, err := os.ReadFile("../../docs/commands.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(ref)
	a := &app{env: &Env{Stdout: io.Discard, Stderr: io.Discard, Getenv: func(string) string { return "" }}}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if sub.Hidden || sub.Name() == "help" || sub.Name() == "completion" {
				continue
			}
			path := strings.TrimPrefix(sub.CommandPath(), "ylctl ")
			if strings.TrimSpace(sub.Short) == "" {
				t.Errorf("%q has no Short description, so it is missing from --help", path)
			}
			if !strings.Contains(doc, "ylctl "+path) {
				t.Errorf("%q is not in docs/commands.md (add it with an example)", path)
			}
			walk(sub)
		}
	}
	walk(a.rootCmd())
}
