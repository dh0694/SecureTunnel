//go:build !windows && !darwin

// Command agent is the SecureTunnel Windows agent. It only runs on Windows.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "the SecureTunnel agent runs on Windows only")
	os.Exit(1)
}
