// Package macagent defines what the Mac installer puts on disk and the
// scripts it runs. The build uses it to make the payload; the downloads page
// uses it to bake the server address into the install script.
package macagent

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"time"

	"securetunnel/server/internal/agenticon"
	"securetunnel/server/internal/macpkg"
)

const (
	Identifier = "com.securetunnel.agent"
	PkgName    = "securetunnel.pkg"
	MinOS      = "12.0"
)

const launcher = `#!/bin/sh
# Starts the SecureTunnel binary for this Mac's processor.
D="$(cd "$(dirname "$0")" && pwd)"
case "$(/usr/bin/uname -m)" in
  arm64) exec "$D/securetunnel-arm64" "$@" ;;
  *)     exec "$D/securetunnel-x86_64" "$@" ;;
esac
`

const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>SecureTunnel</string>
  <key>CFBundleDisplayName</key><string>SecureTunnel</string>
  <key>CFBundleIdentifier</key><string>com.securetunnel.app</string>
  <key>CFBundleExecutable</key><string>SecureTunnel</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>%[1]s</string>
  <key>CFBundleVersion</key><string>%[1]s</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
`

const daemonPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.securetunnel.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Applications/SecureTunnel.app/Contents/MacOS/SecureTunnel</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>AbandonProcessGroup</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardErrorPath</key><string>/Library/Application Support/SecureTunnel/daemon.err</string>
</dict>
</plist>
`

const uiPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.securetunnel.ui</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Applications/SecureTunnel.app/Contents/MacOS/SecureTunnel</string>
    <string>ui</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
`

const uninstallScript = `#!/bin/sh
# Removes SecureTunnel. Run with: sudo "/Applications/SecureTunnel.app/Contents/Resources/uninstall.sh"
if [ "$(id -u)" != "0" ]; then echo "Run with sudo." >&2; exit 1; fi
U=$(/usr/bin/stat -f %u /dev/console)
[ "$U" != "0" ] && /bin/launchctl bootout "gui/$U/com.securetunnel.ui" 2>/dev/null
/bin/launchctl bootout system/com.securetunnel.agent 2>/dev/null
rm -f /Library/LaunchDaemons/com.securetunnel.agent.plist /Library/LaunchAgents/com.securetunnel.ui.plist
rm -rf /Applications/SecureTunnel.app "/Library/Application Support/SecureTunnel" /var/run/securetunnel.sock
/usr/sbin/pkgutil --forget com.securetunnel.agent >/dev/null 2>&1
echo "SecureTunnel removed."
`

const preinstall = `#!/bin/sh
# Nothing to stop here: the postinstall restarts the service, and a live VPN
# session is picked up again by the new version.
exit 0
`

// postinstall: %s is the server address baked in by the downloads page ("" = ask).
const postinstall = `#!/bin/sh
SERVER='%s'
DIR="/Library/Application Support/SecureTunnel"
mkdir -p "$DIR" && chmod 755 "$DIR"
FIRST=0
[ -f "$DIR/.installed" ] || FIRST=1

# Server address from the download (only if none is set yet).
if [ -n "$SERVER" ] && [ ! -f "$DIR/config.json" ]; then
  printf '{\n  "server": "%%s"\n}\n' "$SERVER" > "$DIR/config.json"
  chmod 600 "$DIR/config.json"
fi

# (Re)start the background service. A connected session resumes on its own.
/bin/launchctl bootout system/com.securetunnel.agent 2>/dev/null
/bin/launchctl bootstrap system /Library/LaunchDaemons/com.securetunnel.agent.plist

# The window helper for whoever is logged in.
U=$(/usr/bin/stat -f %%u /dev/console)
if [ -n "$U" ] && [ "$U" != "0" ]; then
  /bin/launchctl bootout "gui/$U/com.securetunnel.ui" 2>/dev/null
  /bin/launchctl bootstrap "gui/$U" /Library/LaunchAgents/com.securetunnel.ui.plist
  if [ "$FIRST" = "1" ] && [ "$COMMAND_LINE_INSTALL" != "1" ]; then
    /bin/launchctl asuser "$U" /usr/bin/open -a /Applications/SecureTunnel.app
  fi
fi
touch "$DIR/.installed"
exit 0
`

// Payload lists the files the package installs.
func Payload(armBin, amdBin, icon []byte, version string) []macpkg.Entry {
	dir := func(p string, mode uint32, gid int) macpkg.Entry {
		return macpkg.Entry{Path: p, Mode: macpkg.TypeDir | mode, GID: gid}
	}
	file := func(p string, mode uint32, data []byte) macpkg.Entry {
		return macpkg.Entry{Path: p, Mode: macpkg.TypeFile | mode, Data: data}
	}
	app := "Applications/SecureTunnel.app/Contents"
	e := []macpkg.Entry{
		dir("Applications", 0o775, 80), // root:admin, as macOS ships it
		dir("Applications/SecureTunnel.app", 0o755, 0),
		dir(app, 0o755, 0),
		dir(app+"/MacOS", 0o755, 0),
		dir(app+"/Resources", 0o755, 0),
		file(app+"/Info.plist", 0o644, []byte(fmt.Sprintf(infoPlist, version))),
		file(app+"/MacOS/SecureTunnel", 0o755, []byte(launcher)),
		file(app+"/MacOS/securetunnel-arm64", 0o755, armBin),
		file(app+"/MacOS/securetunnel-x86_64", 0o755, amdBin),
		file(app+"/Resources/uninstall.sh", 0o755, []byte(uninstallScript)),
		dir("Library", 0o755, 0),
		dir("Library/LaunchDaemons", 0o755, 0),
		dir("Library/LaunchAgents", 0o755, 0),
		file("Library/LaunchDaemons/com.securetunnel.agent.plist", 0o644, []byte(daemonPlist)),
		file("Library/LaunchAgents/com.securetunnel.ui.plist", 0o644, []byte(uiPlist)),
	}
	if len(icon) > 0 {
		e = append(e, file(app+"/Resources/AppIcon.icns", 0o644, icon))
	}
	return e
}

var serverRE = regexp.MustCompile(`^https://[A-Za-z0-9.\-]+(:[0-9]{1,5})?$`)

// Scripts returns the Scripts archive with the server address baked into
// postinstall. A server that isn't a plain https://host[:port] is left out.
func Scripts(server string, mtime time.Time) ([]byte, error) {
	server = strings.TrimRight(server, "/")
	if !serverRE.MatchString(server) {
		server = ""
	}
	return macpkg.CPIO([]macpkg.Entry{
		{Path: "preinstall", Mode: macpkg.TypeFile | 0o755, Data: []byte(preinstall)},
		{Path: "postinstall", Mode: macpkg.TypeFile | 0o755, Data: []byte(fmt.Sprintf(postinstall, server))},
	}, mtime)
}

// Info describes the package for PackageInfo and Distribution.
func Info(version string, files, kbytes int) macpkg.Info {
	return macpkg.Info{Identifier: Identifier, Version: version, Title: "SecureTunnel", PkgName: PkgName,
		Files: files, KBytes: kbytes, HasPre: true, HasPost: true, MinOS: MinOS}
}

// Icon returns the app icon as an .icns file (PNG-based entries).
func Icon() []byte {
	var body []byte
	for _, e := range []struct {
		typ  string
		size int
	}{{"ic07", 128}, {"ic08", 256}, {"ic09", 512}} {
		png := agenticon.PNG(e.size, agenticon.Brand)
		h := make([]byte, 8)
		copy(h, e.typ)
		binary.BigEndian.PutUint32(h[4:], uint32(len(png)+8))
		body = append(body, h...)
		body = append(body, png...)
	}
	hdr := make([]byte, 8)
	copy(hdr, "icns")
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(body)+8))
	return append(hdr, body...)
}

// installScript is in the zip download: it does what the .pkg does.
const installScript = `#!/bin/sh
# Installs SecureTunnel from this folder. Run:  sudo ./install.sh
set -e
if [ "$(id -u)" != "0" ]; then echo "Run with sudo:  sudo ./install.sh" >&2; exit 1; fi
HERE="$(cd "$(dirname "$0")" && pwd)"
/usr/bin/xattr -dr com.apple.quarantine "$HERE/SecureTunnel.app" 2>/dev/null || true
rm -rf /Applications/SecureTunnel.app
/usr/bin/ditto "$HERE/SecureTunnel.app" /Applications/SecureTunnel.app
chown -R root:wheel /Applications/SecureTunnel.app
cp "$HERE/com.securetunnel.agent.plist" /Library/LaunchDaemons/
cp "$HERE/com.securetunnel.ui.plist" /Library/LaunchAgents/
chown root:wheel /Library/LaunchDaemons/com.securetunnel.agent.plist /Library/LaunchAgents/com.securetunnel.ui.plist
chmod 644 /Library/LaunchDaemons/com.securetunnel.agent.plist /Library/LaunchAgents/com.securetunnel.ui.plist
sh "$HERE/.postinstall"
echo "SecureTunnel is installed. It opens from Applications."
`

// ZipFiles lists the zip download's files (path → mode, data), with the
// server address baked into the install script.
func ZipFiles(armBin, amdBin []byte, version, server string) []ZipFile {
	server = strings.TrimRight(server, "/")
	if !serverRE.MatchString(server) {
		server = ""
	}
	var out []ZipFile
	for _, e := range Payload(armBin, amdBin, Icon(), version) {
		if e.Mode&0o170000 != macpkg.TypeFile {
			continue
		}
		switch {
		case strings.HasPrefix(e.Path, "Applications/"):
			out = append(out, ZipFile{Name: strings.TrimPrefix(e.Path, "Applications/"), Mode: e.Mode & 0o777, Data: e.Data})
		case strings.HasPrefix(e.Path, "Library/"):
			out = append(out, ZipFile{Name: e.Path[strings.LastIndex(e.Path, "/")+1:], Mode: 0o644, Data: e.Data})
		}
	}
	out = append(out,
		ZipFile{Name: "install.sh", Mode: 0o755, Data: []byte(installScript)},
		ZipFile{Name: ".postinstall", Mode: 0o755, Data: []byte(fmt.Sprintf(postinstall, server))},
		ZipFile{Name: "README.txt", Mode: 0o644, Data: []byte(fmt.Sprintf(zipReadme, version, server))},
	)
	return out
}

// ZipFile is one file in the Mac zip download.
type ZipFile struct {
	Name string
	Mode uint32
	Data []byte
}

const zipReadme = `SecureTunnel for Mac %s
Server: %s

Install:
  1. Open Terminal in this folder (or drag install.sh into a Terminal window).
  2. Run:  sudo ./install.sh
  3. SecureTunnel opens. Sign in to connect.

Remove:  sudo /Applications/SecureTunnel.app/Contents/Resources/uninstall.sh

Works on macOS 12 or later, Apple silicon and Intel.
`
