//go:build windows

package cli

import "os"

// sigwinch is nil on Windows: there is no resize signal, so nothing is subscribed.
var sigwinch os.Signal
