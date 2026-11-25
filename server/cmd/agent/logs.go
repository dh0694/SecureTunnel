//go:build windows || darwin

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
)

// Log bundles for IT: the agent log (last part), the connection checks, the
// current status and the network settings, zipped, under 3 MB.

type logSource struct {
	name string
	data []byte
}

// tailFile returns up to max bytes from the end of a file.
func tailFile(path string, max int64) []byte {
	f, err := os.Open(path)
	if err != nil {
		return []byte("(not available: " + err.Error() + ")\n")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	if st.Size() > max {
		_, _ = f.Seek(st.Size()-max, io.SeekStart)
	}
	b, _ := io.ReadAll(io.LimitReader(f, max))
	return b
}

// commandOutput runs a command with a timeout and returns its output.
func commandOutput(name string, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		out = append(out, []byte("\n(command failed: "+err.Error()+")\n")...)
	}
	return out
}

func buildLogZip(sources []logSource) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	sort.SliceStable(sources, func(i, j int) bool { return sources[i].name < sources[j].name })
	for _, s := range sources {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: s.name, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(s.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func diagText(items []diagItem) []byte {
	var b strings.Builder
	for _, d := range items {
		mark := "OK  "
		if !d.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "[%s] %s: %s\n", mark, d.Name, d.Detail)
	}
	return []byte(b.String())
}

// sendLogs gathers and uploads a bundle; returns the reference code.
func sendLogs(ctx context.Context, e *agentcore.Engine, client func(string) *clientapi.Client, devID, reason string,
	gather func(context.Context) []logSource) (string, error) {
	server, _ := configuredServer()
	if server == "" {
		return "", errors.New("no server is set up yet")
	}
	st := e.Status()
	statusJSON, _ := json.MarshalIndent(st, "", "  ")
	sources := append(gather(ctx), logSource{name: "status.json", data: statusJSON},
		logSource{name: "about.txt", data: []byte(fmt.Sprintf("SecureTunnel %s\nDevice: %s\nServer: %s\nTime: %s\nReason: %s\n",
			version, devID, server, time.Now().Format(time.RFC3339), reason))})
	data, err := buildLogZip(sources)
	if err != nil {
		return "", err
	}
	if len(data) > 3<<20 {
		return "", errors.New("the logs are too large to send")
	}
	sid, tok := "", ""
	if s, ok := e.CurrentSession(); ok {
		sid, tok = s.ID, s.ResumeToken
	}
	uctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return client(server).UploadLogs(uctx, sid, tok, devID, reason, data)
}
