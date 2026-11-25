// Command mkmacpkg prepares the Mac agent downloads on Linux.
//
//	go run ./tools/mkmacpkg -arm64 bin/arm64 -amd64 bin/amd64 -version 1.2.3 -out /out/clients/macos
//
// It always writes the two binaries and meta.json; the downloads page builds
// the zip installer from them. If bomutils' mkbom is installed it also
// writes Payload and Bom, from which the downloads page builds the .pkg.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"securetunnel/server/internal/macagent"
	"securetunnel/server/internal/macpkg"
)

// Meta is what the downloads page reads.
type Meta struct {
	Version string `json:"version"`
	Files   int    `json:"files"`
	KBytes  int    `json:"kbytes"`
	Built   int64  `json:"built"`
	Pkg     bool   `json:"pkg"` // Payload + Bom are present
}

func main() {
	arm := flag.String("arm64", "", "Apple silicon binary")
	amd := flag.String("amd64", "", "Intel binary")
	ver := flag.String("version", "", "version")
	out := flag.String("out", "", "output directory")
	mkbom := flag.String("mkbom", "mkbom", "path to bomutils mkbom (optional)")
	flag.Parse()
	if *arm == "" || *amd == "" || *ver == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	armBin, err := os.ReadFile(*arm)
	if err != nil {
		log.Fatal(err)
	}
	amdBin, err := os.ReadFile(*amd)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	for name, b := range map[string][]byte{"securetunnel-arm64": armBin, "securetunnel-x86_64": amdBin} {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	now := time.Now()
	entries := macagent.Payload(armBin, amdBin, macagent.Icon(), *ver)
	files, kb := macpkg.Stats(entries)
	m := Meta{Version: *ver, Files: files, KBytes: kb, Built: now.Unix()}

	if path, err := exec.LookPath(*mkbom); err != nil {
		fmt.Println("mkbom not found: building the zip installer only (no .pkg)")
	} else {
		payload, err := macpkg.CPIO(entries, now)
		if err != nil {
			log.Fatal(err)
		}
		list := filepath.Join(*out, "bom.txt")
		if err := os.WriteFile(list, []byte(macpkg.BomList(entries)), 0o644); err != nil {
			log.Fatal(err)
		}
		if b, err := exec.Command(path, "-i", list, filepath.Join(*out, "Bom")).CombinedOutput(); err != nil {
			log.Fatalf("mkbom: %v: %s", err, b)
		}
		if err := os.WriteFile(filepath.Join(*out, "Payload"), payload, 0o644); err != nil {
			log.Fatal(err)
		}
		m.Pkg = true
	}
	mb, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(*out, "meta.json"), mb, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("mac agent %s: %d files, %d KB, pkg=%v\n", *ver, files, kb, m.Pkg)
}
