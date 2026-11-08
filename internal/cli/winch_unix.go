//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// sigwinch is the terminal-resize signal (not available on Windows, where the bar is simply not re-pinned on resize).
var sigwinch os.Signal = syscall.SIGWINCH
