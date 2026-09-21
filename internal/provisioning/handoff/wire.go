// Package handoff implements the narrow authenticated evidence read boundary.
package handoff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const MaxBytes = 1 << 20

func Digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

// Canonical implements RFC8785 for the contract's integer-only number profile.
// Fractions, negative numbers, and integers beyond I-JSON's exact range fail closed.
func Canonical(b []byte) ([]byte, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("invalid UTF-8")
	}
	// encoding/json replaces lone UTF-16 surrogates; reject these before decoding.
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			break
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return nil, errors.New("invalid unicode escape")
		}
		n, e := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if e != nil {
			return nil, e
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return nil, errors.New("unpaired surrogate")
			}
			m, e := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if e != nil || m < 0xdc00 || m > 0xdfff {
				return nil, errors.New("unpaired surrogate")
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return nil, errors.New("unpaired surrogate")
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, e := parse(d)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return emit(v)
}
func parse(d *json.Decoder) (any, error) {
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	if x, ok := t.(json.Delim); ok {
		switch x {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				s, ok := k.(string)
				if !ok {
					return nil, errors.New("invalid key")
				}
				if _, ok = m[s]; ok {
					return nil, errors.New("duplicate key")
				}
				v, e := parse(d)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			_, e = d.Token()
			return m, e
		case '[':
			a := []any{}
			for d.More() {
				v, e := parse(d)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, e = d.Token()
			return a, e
		default:
			return nil, errors.New("invalid delimiter")
		}
	}
	return t, nil
}
func quote(s string) []byte {
	var b bytes.Buffer
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 32 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.Bytes()
}
func emit(v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		return []byte(strconv.FormatBool(x)), nil
	case string:
		return quote(x), nil
	case json.Number:
		n, e := strconv.ParseUint(string(x), 10, 64)
		if e != nil || n > 9007199254740991 {
			return nil, errors.New("number outside contract profile")
		}
		return []byte(strconv.FormatUint(n, 10)), nil
	case []any:
		b := []byte{'['}
		for i, v := range x {
			if i > 0 {
				b = append(b, ',')
			}
			p, e := emit(v)
			if e != nil {
				return nil, e
			}
			b = append(b, p...)
		}
		return append(b, ']'), nil
	case map[string]any:
		keys := []string{}
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for k := 0; k < len(a) && k < len(b); k++ {
				if a[k] != b[k] {
					return a[k] < b[k]
				}
			}
			return len(a) < len(b)
		})
		b := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, quote(k)...)
			b = append(b, ':')
			p, e := emit(x[k])
			if e != nil {
				return nil, e
			}
			b = append(b, p...)
		}
		return append(b, '}'), nil
	default:
		return nil, errors.New("invalid JSON value")
	}
}
func Decode(b []byte, v any) error {
	if len(b) > MaxBytes {
		return errors.New("response too large")
	}
	if _, e := Canonical(b); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
