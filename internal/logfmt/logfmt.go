// Package logfmt reads one line of key=value pairs, the layout Grafana, Go
// services and many container workloads write.
//
// The reader is strict on purpose. A line that mixes free words with pairs, has
// an unterminated quote, or has an empty key is not logfmt, and guessing would
// turn prose into fields. Duplicate keys are all kept; Get returns the first.
package logfmt

import "strings"

// Pairs is the ordered key/value list of one line.
type Pairs struct {
	keys, vals []string
}

// Get returns the first value for k and whether the key was present. A key
// written with an empty value ("referer=") is present with value "".
func (p Pairs) Get(k string) (string, bool) {
	for i, key := range p.keys {
		if key == k {
			return p.vals[i], true
		}
	}
	return "", false
}

// Keys returns the keys in line order, duplicates included.
func (p Pairs) Keys() []string { return append([]string(nil), p.keys...) }

func validKeyByte(c byte) bool {
	return c == '_' || c == '.' || c == '-' || c == ':' || c == '/' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// Parse reads a line. It reports false for anything that is not wholly
// key=value pairs.
func Parse(line string) (Pairs, bool) {
	var p Pairs
	i, n := 0, len(line)
	for i < n {
		for i < n && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' || line[i] == '\n') {
			i++
		}
		if i >= n {
			break
		}
		start := i
		for i < n && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
			if !validKeyByte(line[i]) {
				return Pairs{}, false
			}
			i++
		}
		if i >= n || line[i] != '=' || i == start {
			return Pairs{}, false
		}
		key := line[start:i]
		i++ // '='
		var val string
		if i < n && line[i] == '"' {
			i++
			var b strings.Builder
			closed := false
			for i < n {
				c := line[i]
				if c == '\\' && i+1 < n {
					switch line[i+1] {
					case 'n':
						b.WriteByte('\n')
					case 't':
						b.WriteByte('\t')
					case 'r':
						b.WriteByte('\r')
					default:
						b.WriteByte(line[i+1])
					}
					i += 2
					continue
				}
				if c == '"' {
					closed = true
					i++
					break
				}
				b.WriteByte(c)
				i++
			}
			if !closed {
				return Pairs{}, false
			}
			val = b.String()
		} else {
			s := i
			for i < n && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			val = line[s:i]
		}
		p.keys = append(p.keys, key)
		p.vals = append(p.vals, val)
	}
	if len(p.keys) == 0 {
		return Pairs{}, false
	}
	return p, true
}
