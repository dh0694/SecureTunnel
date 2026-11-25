// Package macpkg writes macOS installer packages (.pkg, the "product archive"
// that double-clicks into Installer.app) without Apple's tools, so the Linux
// build can produce the Mac agent installer.
//
// A product archive is a xar archive holding:
//
//	Distribution                 installer script (title, choices, one pkg-ref)
//	<name>.pkg/PackageInfo       identifier, version, payload size, scripts
//	<name>.pkg/Bom               bill of materials (made by bomutils' mkbom)
//	<name>.pkg/Payload           gzipped cpio (odc) of the files to install
//	<name>.pkg/Scripts           gzipped cpio (odc) of preinstall/postinstall
package macpkg

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha1" //nolint:gosec // xar checksums are SHA-1 by convention
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Entry is one file or directory in a cpio archive.
type Entry struct {
	Path string // relative, without "./" (e.g. "Applications/SecureTunnel.app")
	Mode uint32 // permission bits plus type: 0o040000 directory, 0o100000 file
	UID  int
	GID  int
	Data []byte // files only
}

const (
	TypeDir  = 0o040000
	TypeFile = 0o100000
)

// CPIO writes entries as a gzipped odc ("070707") cpio archive, the format
// Installer expects for Payload and Scripts. Entries are written in path
// order with "." first.
func CPIO(entries []Entry, mtime time.Time) ([]byte, error) {
	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	var raw bytes.Buffer
	ino := 1
	write := func(name string, mode uint32, uid, gid int, data []byte) {
		nlink := 1
		if mode&0o170000 == TypeDir {
			nlink = 2
		}
		fmt.Fprintf(&raw, "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o",
			0, ino, mode, uid, gid, nlink, 0, mtime.Unix(), len(name)+1, len(data))
		raw.WriteString(name)
		raw.WriteByte(0)
		raw.Write(data)
		ino++
	}
	write(".", TypeDir|0o755, 0, 0, nil)
	for _, e := range sorted {
		if e.Path == "" || e.Path == "." {
			continue
		}
		var data []byte
		if e.Mode&0o170000 == TypeFile {
			data = e.Data
		}
		write("./"+e.Path, e.Mode, e.UID, e.GID, data)
	}
	write("TRAILER!!!", 0, 0, 0, nil)

	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return gz.Bytes(), nil
}

// BomList renders entries in the "lsbom" text format that `mkbom -i` reads:
// path, octal mode, uid/gid, and for files size and POSIX cksum.
func BomList(entries []Entry) string {
	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	var b strings.Builder
	fmt.Fprintf(&b, ".\t%o\t0/0\n", TypeDir|0o755)
	for _, e := range sorted {
		if e.Mode&0o170000 == TypeFile {
			fmt.Fprintf(&b, "./%s\t%o\t%d/%d\t%d\t%d\n", e.Path, e.Mode, e.UID, e.GID, len(e.Data), Cksum(e.Data))
		} else {
			fmt.Fprintf(&b, "./%s\t%o\t%d/%d\n", e.Path, e.Mode, e.UID, e.GID)
		}
	}
	return b.String()
}

// Cksum is the POSIX cksum CRC (what BOM files record for each file).
func Cksum(data []byte) uint32 {
	var crc uint32
	upd := func(b byte) {
		crc ^= uint32(b) << 24
		for i := 0; i < 8; i++ {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	for _, b := range data {
		upd(b)
	}
	for n := len(data); n > 0; n >>= 8 {
		upd(byte(n))
	}
	return ^crc
}

// Stats returns the payload's file count and size in KB for PackageInfo.
func Stats(entries []Entry) (files int, kbytes int) {
	var total int
	for _, e := range entries {
		files++
		total += len(e.Data)
	}
	return files + 1, (total + 1023) / 1024
}

// Info describes the package.
type Info struct {
	Identifier string // e.g. com.securetunnel.agent
	Version    string
	Title      string
	PkgName    string // component name inside the archive, e.g. securetunnel.pkg
	Files      int
	KBytes     int
	HasPre     bool
	HasPost    bool
	MinOS      string // e.g. 12.0
}

// PackageInfo renders <name>.pkg/PackageInfo.
func PackageInfo(i Info) []byte {
	var s strings.Builder
	fmt.Fprintf(&s, `<?xml version="1.0" encoding="utf-8"?>
<pkg-info overwrite-permissions="true" relocatable="false" identifier="%s" postinstall-action="none" version="%s" format-version="2" generator-version="SecureTunnel" install-location="/" auth="root">
    <payload numberOfFiles="%d" installKBytes="%d"/>
    <bundle-version/>
    <upgrade-bundle/>
    <update-bundle/>
    <atomic-update-bundle/>
    <strict-identifier/>
    <relocate/>
`, xmlEsc(i.Identifier), xmlEsc(i.Version), i.Files, i.KBytes)
	if i.HasPre || i.HasPost {
		s.WriteString("    <scripts>\n")
		if i.HasPre {
			s.WriteString(`        <preinstall file="./preinstall"/>` + "\n")
		}
		if i.HasPost {
			s.WriteString(`        <postinstall file="./postinstall"/>` + "\n")
		}
		s.WriteString("    </scripts>\n")
	}
	s.WriteString("</pkg-info>\n")
	return []byte(s.String())
}

// Distribution renders the product archive's Distribution file.
func Distribution(i Info) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>%[1]s</title>
    <options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="%[5]s"/>
        </allowed-os-versions>
    </volume-check>
    <choices-outline>
        <line choice="default">
            <line choice="%[2]s"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="%[2]s" visible="false">
        <pkg-ref id="%[2]s"/>
    </choice>
    <pkg-ref id="%[2]s" version="%[3]s" onConclusion="none" installKBytes="%[6]d">#%[4]s</pkg-ref>
</installer-gui-script>
`, xmlEsc(i.Title), xmlEsc(i.Identifier), xmlEsc(i.Version), xmlEsc(i.PkgName), xmlEsc(i.MinOS), i.KBytes))
}

func xmlEsc(s string) string {
	var b bytes.Buffer
	_ = xmlEscape(&b, s)
	return b.String()
}

func xmlEscape(w io.Writer, s string) error {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	_, err := io.WriteString(w, r.Replace(s))
	return err
}

// Parts are the files of a product archive.
type Parts struct {
	Distribution []byte
	PkgName      string // e.g. securetunnel.pkg
	PackageInfo  []byte
	Bom          []byte
	Payload      []byte
	Scripts      []byte // may be nil
}

// Build writes the product archive (.pkg) as an uncompressed xar file, the
// layout productbuild produces.
func Build(p Parts, now time.Time) ([]byte, error) {
	type file struct {
		name string
		data []byte
		off  int
	}
	top := []file{{name: "Distribution", data: p.Distribution}}
	inner := []file{{name: "Bom", data: p.Bom}, {name: "PackageInfo", data: p.PackageInfo}, {name: "Payload", data: p.Payload}}
	if p.Scripts != nil {
		inner = append(inner, file{name: "Scripts", data: p.Scripts})
	}
	// Heap: 20-byte TOC checksum, then each file's data.
	off := 20
	for i := range top {
		top[i].off = off
		off += len(top[i].data)
	}
	for i := range inner {
		inner[i].off = off
		off += len(inner[i].data)
	}
	ts := now.UTC().Format("2006-01-02T15:04:05Z")
	sum := func(b []byte) string { h := sha1.Sum(b); return hex.EncodeToString(h[:]) } //nolint:gosec
	id := 1
	var toc strings.Builder
	fileXML := func(f file, indent string) {
		fmt.Fprintf(&toc, `%[1]s<file id="%[2]d">
%[1]s <data>
%[1]s  <length>%[3]d</length>
%[1]s  <encoding style="application/octet-stream"/>
%[1]s  <offset>%[4]d</offset>
%[1]s  <size>%[3]d</size>
%[1]s  <extracted-checksum style="sha1">%[5]s</extracted-checksum>
%[1]s  <archived-checksum style="sha1">%[5]s</archived-checksum>
%[1]s </data>
%[1]s <ctime>%[6]s</ctime>
%[1]s <mtime>%[6]s</mtime>
%[1]s <atime>%[6]s</atime>
%[1]s <group>wheel</group>
%[1]s <gid>0</gid>
%[1]s <user>root</user>
%[1]s <uid>0</uid>
%[1]s <mode>0644</mode>
%[1]s <type>file</type>
%[1]s <name>%[7]s</name>
%[1]s</file>
`, indent, id, len(f.data), f.off, sum(f.data), ts, xmlEsc(f.name))
		id++
	}
	toc.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<xar>
 <toc>
  <checksum style="sha1">
   <offset>0</offset>
   <size>20</size>
  </checksum>
  <creation-time>` + ts + `</creation-time>
`)
	for _, f := range top {
		fileXML(f, "  ")
	}
	fmt.Fprintf(&toc, `  <file id="%d">
   <ctime>%[2]s</ctime>
   <mtime>%[2]s</mtime>
   <atime>%[2]s</atime>
   <group>wheel</group>
   <gid>0</gid>
   <user>root</user>
   <uid>0</uid>
   <mode>0755</mode>
   <type>directory</type>
   <name>%[3]s</name>
`, id, ts, xmlEsc(p.PkgName))
	id++
	for _, f := range inner {
		fileXML(f, "   ")
	}
	toc.WriteString("  </file>\n </toc>\n</xar>\n")

	var ztoc bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&ztoc, zlib.BestCompression)
	if _, err := zw.Write([]byte(toc.String())); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	var out bytes.Buffer
	hdr := make([]byte, 28)
	copy(hdr[0:4], "xar!")
	binary.BigEndian.PutUint16(hdr[4:], 28)                     // header size
	binary.BigEndian.PutUint16(hdr[6:], 1)                      // version
	binary.BigEndian.PutUint64(hdr[8:], uint64(ztoc.Len()))     // TOC compressed length
	binary.BigEndian.PutUint64(hdr[16:], uint64(len(toc.String()))) // TOC uncompressed length
	binary.BigEndian.PutUint32(hdr[24:], 1)                     // checksum algorithm: SHA-1
	out.Write(hdr)
	out.Write(ztoc.Bytes())
	tocSum := sha1.Sum(ztoc.Bytes()) //nolint:gosec
	out.Write(tocSum[:])
	for _, f := range top {
		out.Write(f.data)
	}
	for _, f := range inner {
		out.Write(f.data)
	}
	return out.Bytes(), nil
}
