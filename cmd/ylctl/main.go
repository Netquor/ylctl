// Command ylctl diagnoses and brings up Yealink desk phones from a laptop.
package main

import (
	"os"

	"github.com/Netquor/ylctl/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.OSEnv()))
}
