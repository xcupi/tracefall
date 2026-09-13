// Package xmlutil holds the small pieces of XML handling that more than
// one artifact parser needs.
//
// It exists because Windows ships XML evidence in two encodings and the
// standard library decodes only one of them. Task Scheduler writes
// UTF-16LE with a BOM; FileZilla writes UTF-8 and declares it. Both
// arrive at encoding/xml, which rejects any declared charset it does not
// know and cannot see a BOM at all. The two lines that fix this were
// written once for scheduled tasks and are shared from here rather than
// copied into every parser that meets a second encoding.
package xmlutil

import (
	"bytes"
	"encoding/xml"
	"io"
	"unicode/utf16"
)

// DecodeUTF16 converts UTF-16 (LE or BE, detected by BOM) bytes to
// UTF-8. Data without a recognized UTF-16 BOM is returned UNCHANGED and
// unexamined -- there is no heuristic here, because guessing an encoding
// from byte statistics can silently corrupt evidence, and a file with no
// BOM is overwhelmingly already UTF-8 or ASCII.
//
// A UTF-8 BOM, if present, is stripped: encoding/xml treats the three
// bytes preceding the declaration as content and fails on them.
func DecodeUTF16(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}

	var little bool
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		little = true
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		little = false
	default:
		return data
	}

	body := data[2:]
	units := make([]uint16, 0, len(body)/2)
	for i := 0; i+1 < len(body); i += 2 {
		if little {
			units = append(units, uint16(body[i])|uint16(body[i+1])<<8)
		} else {
			units = append(units, uint16(body[i])<<8|uint16(body[i+1]))
		}
	}
	return []byte(string(utf16.Decode(units)))
}

// NewDecoder returns an xml.Decoder over data, with DecodeUTF16 already
// applied and a CharsetReader that accepts whatever charset the document
// declares.
//
// Accepting the declaration is correct here rather than lax: DecodeUTF16
// has already converted the bytes to UTF-8, so a document that truthfully
// said encoding="UTF-16" is now describing an encoding it no longer has.
// Honouring the stale declaration would reject evidence that was decoded
// correctly.
//
// This does NOT transcode any other charset. A document that declares,
// say, windows-1252 is read as the bytes it contains; that mis-decodes
// only characters above U+007F, and reporting them as they were stored is
// better than refusing the file.
func NewDecoder(data []byte) *xml.Decoder {
	dec := xml.NewDecoder(bytes.NewReader(DecodeUTF16(data)))
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	return dec
}
