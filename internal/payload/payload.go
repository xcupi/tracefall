// Package payload inspects a suspicious file's bytes without running it.
//
// It answers the questions that can be answered from the bytes alone: what
// the file is (by magic number, not name), its hashes, and for a Windows
// executable its structure -- sections and their entropy, imported and
// exported functions, the signature directory, appended data -- plus the
// readable strings that name a network address, a path, a registry key or a
// command.
//
// # What it does not do
//
// It never executes, loads or emulates anything. It does not decide that a
// file is malicious: an Indicator is a property that malware often has and
// that ordinary software sometimes has too (a packer's entropy, an
// injection API a debugger imports). It does not verify an Authenticode
// signature, only reports that one is present. It does not look the hash
// up anywhere. Its timestamps are what the file claims; a PE header's
// compile time is written by the linker and is trivially forged.
//
// # Bounds
//
// Input is untrusted. Only the first maxInspect bytes are read for
// structure, a section is hashed for entropy up to maxSection bytes, and the
// string scan is capped, so a hostile file cannot make the inspection
// large.
package payload

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxInspect  = 64 << 20
	maxSection  = 16 << 20
	maxStrings  = 40
	minStringLn = 6
)

// SniffType names a file type from its first bytes. It returns "" for
// anything it does not recognise, and never looks at a name.
func SniffType(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("MZ")):
		return "Windows executable (MZ)"
	case bytes.HasPrefix(b, []byte("\x7fELF")):
		return "ELF executable"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")), bytes.HasPrefix(b, []byte("PK\x05\x06")):
		return "ZIP archive"
	case bytes.HasPrefix(b, []byte("\x1f\x8b")):
		return "gzip data"
	case bytes.HasPrefix(b, []byte("Rar!")):
		return "RAR archive"
	case bytes.HasPrefix(b, []byte("7z\xbc\xaf\x27\x1c")):
		return "7-Zip archive"
	case bytes.HasPrefix(b, []byte("%PDF")):
		return "PDF document"
	case bytes.HasPrefix(b, []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")):
		return "OLE2 compound file (legacy Office)"
	case bytes.HasPrefix(b, []byte("\x89PNG")):
		return "PNG image"
	case bytes.HasPrefix(b, []byte("\xff\xd8\xff")):
		return "JPEG image"
	case bytes.HasPrefix(b, []byte("GIF8")):
		return "GIF image"
	case bytes.HasPrefix(b, []byte("#!")):
		return "script with interpreter line"
	case bytes.HasPrefix(b, []byte("<?php")):
		return "PHP script"
	case bytes.HasPrefix(b, []byte("<%")), bytes.HasPrefix(b, []byte("<%@")):
		return "server page (ASP/JSP)"
	}
	return ""
}

// Indicator is a property of the file worth a second look. It is not a
// verdict.
type Indicator struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

// Section is one PE section.
type Section struct {
	Name       string  `json:"name"`
	VirtualSz  uint32  `json:"virtual_size"`
	RawSize    uint32  `json:"raw_size"`
	Entropy    float64 `json:"entropy"`
	Executable bool    `json:"executable"`
	Writable   bool    `json:"writable"`
}

// PEInfo is the structure of a Windows executable.
type PEInfo struct {
	Machine       string    `json:"machine"`
	DLL           bool      `json:"dll"`
	Subsystem     string    `json:"subsystem"`
	EntryRVA      uint32    `json:"entry_rva"`
	ClaimedBuild  time.Time `json:"claimed_build_time"`
	Sections      []Section `json:"sections"`
	ImportDLLs    []string  `json:"import_dlls"`
	ImportCount   int       `json:"import_count"`
	ImpHash       string    `json:"imphash,omitempty"`
	InjectionAPIs []string  `json:"injection_apis,omitempty"`
	Exports       []string  `json:"exports,omitempty"`
	HasSignature  bool      `json:"has_signature_directory"`
	OverlayBytes  int64     `json:"overlay_bytes"`
}

// Report is everything Inspect learned.
type Report struct {
	Type       string      `json:"type"`
	Size       int64       `json:"size"`
	MD5        string      `json:"md5"`
	SHA1       string      `json:"sha1"`
	SHA256     string      `json:"sha256"`
	Entropy    float64     `json:"entropy"`
	PE         *PEInfo     `json:"pe,omitempty"`
	Strings    StringHits  `json:"strings"`
	Indicators []Indicator `json:"indicators"`
	Truncated  bool        `json:"truncated"` // the file is larger than what was inspected
}

// StringHits are the readable strings that name something an analyst can act
// on, each list capped.
type StringHits struct {
	URLs      []string `json:"urls,omitempty"`
	IPv4      []string `json:"ipv4,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	Registry  []string `json:"registry,omitempty"`
	Commands  []string `json:"commands,omitempty"`
	Notable   []string `json:"notable,omitempty"`
	TotalRuns int      `json:"string_runs_scanned"`
}

// Inspect reads up to maxInspect bytes of r and reports on them.
func Inspect(r io.ReaderAt, size int64) (Report, error) {
	rep := Report{Size: size, Indicators: []Indicator{}}
	n := size
	if n > maxInspect {
		n, rep.Truncated = maxInspect, true
	}
	data := make([]byte, n)
	if _, err := r.ReadAt(data, 0); err != nil && err != io.EOF {
		return rep, fmt.Errorf("payload: reading: %w", err)
	}
	m, s1, s256 := md5.Sum(data), sha1.Sum(data), sha256.Sum256(data)
	if !rep.Truncated {
		rep.MD5, rep.SHA1, rep.SHA256 = hex.EncodeToString(m[:]), hex.EncodeToString(s1[:]), hex.EncodeToString(s256[:])
	}
	rep.Type = SniffType(data[:min(len(data), 16)])
	rep.Entropy = round2(entropy(data))
	rep.Strings = scanStrings(data)
	if rep.Type == "Windows executable (MZ)" {
		if info, err := inspectPE(bytes.NewReader(data), data); err == nil {
			rep.PE = info
		} else {
			rep.Indicators = append(rep.Indicators, Indicator{"malformed_pe", "starts with MZ but is not a well-formed PE: " + err.Error()})
		}
	}
	rep.Indicators = append(rep.Indicators, indicators(&rep)...)
	sort.SliceStable(rep.Indicators, func(i, j int) bool { return rep.Indicators[i].ID < rep.Indicators[j].ID })
	return rep, nil
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var e float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		e -= p * math.Log2(p)
	}
	return e
}

var subsystems = map[uint16]string{1: "native", 2: "windows GUI", 3: "windows console", 9: "windows CE", 10: "EFI application", 14: "xbox"}

func inspectPE(ra io.ReaderAt, data []byte) (*PEInfo, error) {
	f, err := pe.NewFile(ra)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info := &PEInfo{Machine: machineName(f.FileHeader.Machine), DLL: f.FileHeader.Characteristics&pe.IMAGE_FILE_DLL != 0}
	if f.FileHeader.TimeDateStamp != 0 {
		info.ClaimedBuild = time.Unix(int64(f.FileHeader.TimeDateStamp), 0).UTC()
	}
	var dirs [16]pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		info.EntryRVA, dirs = oh.AddressOfEntryPoint, oh.DataDirectory
		info.Subsystem = subsystems[oh.Subsystem]
	case *pe.OptionalHeader64:
		info.EntryRVA, dirs = oh.AddressOfEntryPoint, oh.DataDirectory
		info.Subsystem = subsystems[oh.Subsystem]
	}
	var end int64
	for _, s := range f.Sections {
		sec := Section{
			Name: strings.TrimRight(s.Name, "\x00"), VirtualSz: s.VirtualSize, RawSize: s.Size,
			Executable: s.Characteristics&0x20000000 != 0, Writable: s.Characteristics&0x80000000 != 0,
		}
		if e := int64(s.Offset) + int64(s.Size); e > end {
			end = e
		}
		if s.Size > 0 && int64(s.Offset) < int64(len(data)) {
			stop := int64(s.Offset) + int64(min(s.Size, maxSection))
			if stop > int64(len(data)) {
				stop = int64(len(data))
			}
			sec.Entropy = round2(entropy(data[s.Offset:stop]))
		}
		info.Sections = append(info.Sections, sec)
	}
	if end > 0 && int64(len(data)) > end {
		info.OverlayBytes = int64(len(data)) - end
	}
	if syms, err := f.ImportedSymbols(); err == nil {
		info.ImportCount = len(syms)
		seen := map[string]bool{}
		inj := map[string]bool{}
		var parts []string
		for _, s := range syms {
			fn, dll, ok := strings.Cut(s, ":")
			if !ok {
				continue
			}
			for _, api := range injectionAPIs {
				if strings.EqualFold(fn, api) {
					inj[fn] = true
				}
			}
			dll = strings.ToLower(dll)
			if !seen[dll] {
				seen[dll] = true
				info.ImportDLLs = append(info.ImportDLLs, dll)
			}
			base := strings.TrimSuffix(strings.TrimSuffix(dll, ".dll"), ".ocx")
			parts = append(parts, base+"."+strings.ToLower(fn))
		}
		sort.Strings(info.ImportDLLs)
		for fn := range inj {
			info.InjectionAPIs = append(info.InjectionAPIs, fn)
		}
		sort.Strings(info.InjectionAPIs)
		if len(parts) > 0 {
			h := md5.Sum([]byte(strings.Join(parts, ",")))
			info.ImpHash = hex.EncodeToString(h[:])
		}
	}
	info.HasSignature = dirs[4].Size > 0 // IMAGE_DIRECTORY_ENTRY_SECURITY
	info.Exports = exportNames(f, data, dirs[0])
	return info, nil
}

func machineName(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		return "arm"
	}
	return fmt.Sprintf("0x%04x", m)
}

// exportNames reads the export directory. debug/pe does not expose it.
func exportNames(f *pe.File, data []byte, dir pe.DataDirectory) []string {
	if dir.Size == 0 || dir.VirtualAddress == 0 {
		return nil
	}
	rva := func(r uint32) (int, bool) {
		for _, s := range f.Sections {
			if r >= s.VirtualAddress && r < s.VirtualAddress+max(s.VirtualSize, s.Size) {
				off := int(s.Offset) + int(r-s.VirtualAddress)
				return off, off >= 0 && off < len(data)
			}
		}
		return 0, false
	}
	base, ok := rva(dir.VirtualAddress)
	if !ok || base+40 > len(data) {
		return nil
	}
	numNames := binary.LittleEndian.Uint32(data[base+24 : base+28])
	namesRVA := binary.LittleEndian.Uint32(data[base+32 : base+36])
	names, ok := rva(namesRVA)
	if !ok || numNames > 4096 {
		return nil
	}
	var out []string
	for i := uint32(0); i < numNames && len(out) < 256; i++ {
		p := names + int(i)*4
		if p+4 > len(data) {
			break
		}
		nameOff, ok := rva(binary.LittleEndian.Uint32(data[p : p+4]))
		if !ok {
			continue
		}
		end := bytes.IndexByte(data[nameOff:min(len(data), nameOff+256)], 0)
		if end > 0 {
			out = append(out, string(data[nameOff:nameOff+end]))
		}
	}
	sort.Strings(out)
	return out
}

var (
	urlRe   = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>\x00-\x1f]{4,200}`)
	ipRe    = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	pathRe  = regexp.MustCompile(`(?i)(?:\b[a-z]:\\[^\s"'<>|*?\x00-\x1f]{3,200}|\\\\[a-z0-9_.$-]+\\[^\s"'<>|*?\x00-\x1f]{2,200})`)
	regRe   = regexp.MustCompile(`(?i)\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s"'<>\x00-\x1f]{3,200}`)
	cmdRe   = regexp.MustCompile(`(?i)\b(?:cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-|rundll32|regsvr32|wscript|cscript|mshta|schtasks\s+/|netsh\s|net\s+user|certutil\s+-)[^\x00-\x1f]{0,160}`)
	notable = []string{"ReflectiveLoader", "meterpreter", "metasploit", "mimikatz", "sekurlsa", "Invoke-Mimikatz", "beacon.dll", "cobaltstrike", "sqlmap"}
)

// scanStrings finds ASCII and UTF-16LE runs and keeps those that look like
// something to act on. It scans at most maxInspect bytes and keeps maxStrings
// of each kind.
func scanStrings(data []byte) StringHits {
	var hits StringHits
	seen := map[string]bool{}
	add := func(dst *[]string, s string) {
		if len(*dst) < maxStrings && !seen[s] {
			seen[s] = true
			*dst = append(*dst, s)
		}
	}
	handle := func(run string) {
		hits.TotalRuns++
		for _, m := range urlRe.FindAllString(run, 4) {
			add(&hits.URLs, m)
		}
		for _, m := range ipRe.FindAllString(run, 4) {
			if !strings.HasPrefix(m, "0.") && m != "127.0.0.1" {
				add(&hits.IPv4, m)
			}
		}
		for _, m := range pathRe.FindAllString(run, 4) {
			add(&hits.Paths, m)
		}
		for _, m := range regRe.FindAllString(run, 4) {
			add(&hits.Registry, m)
		}
		for _, m := range cmdRe.FindAllString(run, 4) {
			add(&hits.Commands, strings.TrimSpace(m))
		}
		low := strings.ToLower(run)
		for _, n := range notable {
			if strings.Contains(low, strings.ToLower(n)) {
				add(&hits.Notable, n)
			}
		}
	}
	// ASCII runs.
	start := -1
	for i := 0; i <= len(data); i++ {
		printable := i < len(data) && data[i] >= 0x20 && data[i] < 0x7f
		if printable && start < 0 {
			start = i
		}
		if !printable && start >= 0 {
			if i-start >= minStringLn {
				handle(string(data[start:min(i, start+4096)]))
			}
			start = -1
		}
	}
	// UTF-16LE runs: printable byte, zero, printable byte, zero...
	var run []byte
	flush := func() {
		if len(run) >= minStringLn {
			handle(string(run[:min(len(run), 4096)]))
		}
		run = run[:0]
	}
	for i := 0; i+1 < len(data); i += 2 {
		if data[i+1] == 0 && data[i] >= 0x20 && data[i] < 0x7f {
			run = append(run, data[i])
		} else {
			flush()
		}
	}
	flush()
	return hits
}

var injectionAPIs = []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "NtCreateThreadEx", "RtlCreateUserThread"}
var networkDLLs = []string{"wininet.dll", "winhttp.dll", "ws2_32.dll", "wsock32.dll", "urlmon.dll"}

func indicators(r *Report) []Indicator {
	var out []Indicator
	if r.PE != nil {
		p := r.PE
		for _, s := range p.Sections {
			if s.Executable && s.Writable {
				out = append(out, Indicator{"writable_executable_section", fmt.Sprintf("section %q is both writable and executable", s.Name)})
			}
			if s.Executable && s.RawSize >= 4096 && s.Entropy >= 7.2 {
				out = append(out, Indicator{"high_entropy_code", fmt.Sprintf("executable section %q has entropy %.2f, typical of packed or encrypted code", s.Name, s.Entropy)})
			}
		}
		if r.Size > 20<<10 && p.ImportCount > 0 && p.ImportCount < 10 {
			out = append(out, Indicator{"very_few_imports", fmt.Sprintf("only %d imported functions in a %d byte file; packers and loaders resolve the rest at run time", p.ImportCount, r.Size)})
		}
		if p.OverlayBytes > 1024 {
			out = append(out, Indicator{"appended_data", fmt.Sprintf("%d bytes follow the last section; installers and droppers carry a payload there", p.OverlayBytes)})
		}
		for _, e := range p.Exports {
			if strings.EqualFold(e, "ReflectiveLoader") || strings.HasPrefix(e, "ReflectiveLoader@") {
				out = append(out, Indicator{"reflective_loader_export", "exports ReflectiveLoader, the entry point of a reflectively loaded DLL"})
			}
		}
		if len(p.InjectionAPIs) > 0 {
			out = append(out, Indicator{"imports_injection_apis", "imports " + strings.Join(p.InjectionAPIs, ", ") + ", used to write into and run code in another process (debuggers and security tools import them too)"})
		}
		for _, d := range p.ImportDLLs {
			for _, n := range networkDLLs {
				if d == n {
					out = append(out, Indicator{"imports_networking", "imports " + n})
				}
			}
		}
		if !p.HasSignature {
			out = append(out, Indicator{"no_signature_directory", "carries no Authenticode signature directory (which proves nothing by itself)"})
		}
	}
	if len(r.Strings.Notable) > 0 {
		out = append(out, Indicator{"notable_strings", "contains: " + strings.Join(r.Strings.Notable, ", ")})
	}
	if len(r.Strings.URLs)+len(r.Strings.IPv4) > 0 {
		out = append(out, Indicator{"embedded_network_addresses", fmt.Sprintf("%d URL(s) and %d IPv4 address(es) in readable strings", len(r.Strings.URLs), len(r.Strings.IPv4))})
	}
	return out
}
