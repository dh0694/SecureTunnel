// Command genicon writes the app icon files used by the Windows build:
// icon.png (for the exe resources) and icon.ico (for the installer).
//
//	go run ./tools/genicon <out-dir>
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"securetunnel/server/internal/agenticon"
)

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := os.WriteFile(filepath.Join(dir, "icon.png"), agenticon.PNG(256, agenticon.Brand), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(dir, "icon.ico"), agenticon.ICO(agenticon.Brand), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
