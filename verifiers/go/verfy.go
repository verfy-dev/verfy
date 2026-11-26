// Package verfy checks Verfy receipts (format verfy.receipt/1) and ledgers in Go, with only the standard library.
//
// A receipt is signed with Ed25519 over its canonical JSON (keys sorted by UTF-16 code units, no whitespace,
// numbers written the way JavaScript writes them), without its "sig" member. Each receipt carries the SHA-256 of
// the canonical receipt before it in "prev", and "seq" counts from 0, so a ledger cannot be edited, reordered or
// trimmed in the middle without VerifyLedger noticing.
package verfy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Version is the receipt format this package checks.
const Version = "verfy.receipt/1"

// Problem is one thing wrong with a ledger.
type Problem struct {
	Index int    `json:"index"`
	Seq   any    `json:"seq"`
	Error string `json:"error"`
}

// Result is what VerifyLedger found.
type Result struct {
	OK     bool      `json:"ok"`
	Count  int       `json:"count"`
	Head   string    `json:"head"`
	Errors []Problem `json:"errors"`
}

// Canonical returns the bytes Verfy hashes and signs for a decoded JSON value (decode with UseNumber).
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		s, err := number(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case float64:
		s, err := number(json.Number(strconv.FormatFloat(x, 'g', -1, 64)))
		if err != nil {
			return err
		}
		b.WriteString(s)
	case string:
		writeString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("cannot canonicalize %T", v)
	}
	return nil
}

func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// number writes a JSON number the way JavaScript's Number.prototype.toString does.
func number(n json.Number) (string, error) {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			if i == 0 {
				return "0", nil
			}
			if i > -(1<<53) && i < 1<<53 {
				return strconv.FormatInt(i, 10), nil
			}
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("not a finite number: %s", s)
	}
	if f == 0 {
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddddde±XX, shortest digits that round-trip
	mant, expPart, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expPart)
	digits := strings.Replace(mant, ".", "", 1)
	digits = strings.TrimRight(digits, "0")
	if digits == "" {
		digits = "0"
	}
	k, p := len(digits), exp+1
	switch {
	case k <= p && p <= 21:
		return sign + digits + strings.Repeat("0", p-k), nil
	case 0 < p && p <= 21:
		return sign + digits[:p] + "." + digits[p:], nil
	case -6 < p && p <= 0:
		return sign + "0." + strings.Repeat("0", -p) + digits, nil
	}
	es := "+"
	if p-1 < 0 {
		es = "-"
	}
	ea := p - 1
	if ea < 0 {
		ea = -ea
	}
	if k == 1 {
		return sign + digits + "e" + es + strconv.Itoa(ea), nil
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(ea), nil
}

// Digest is "sha256:<hex>" of the canonical form.
func Digest(v any) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// KeyID is the "kid" Verfy derives from a public key.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "atl_" + hex.EncodeToString(h[:])[:16]
}

// PublicKey decodes a base64url public key, as `verfy key` prints it.
func PublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not a base64url Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// VerifyReceipt checks one receipt's version, key id and signature.
func VerifyReceipt(r map[string]any, pub ed25519.PublicKey) bool {
	if r["v"] != Version {
		return false
	}
	sigText, ok := r["sig"].(string)
	if !ok || r["kid"] != KeyID(pub) {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigText)
	if err != nil {
		return false
	}
	body := make(map[string]any, len(r))
	for k, v := range r {
		if k != "sig" {
			body[k] = v
		}
	}
	c, err := Canonical(body)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, c, sig)
}

// VerifyLedger checks every signature and every link, as `verfy verify --ledger` does.
func VerifyLedger(receipts []map[string]any, pub ed25519.PublicKey) Result {
	res := Result{OK: true, Errors: []Problem{}}
	var prev any
	for i, r := range receipts {
		res.Count++
		if !VerifyReceipt(r, pub) {
			res.Errors = append(res.Errors, Problem{i, r["seq"], "bad signature"})
		}
		if n, ok := r["seq"].(json.Number); !ok || n.String() != strconv.Itoa(i) {
			res.Errors = append(res.Errors, Problem{i, r["seq"], fmt.Sprintf("expected seq %d", i)})
		}
		if r["prev"] != prev {
			res.Errors = append(res.Errors, Problem{i, r["seq"], "broken chain: prev does not match the receipt before it"})
		}
		d, err := Digest(r)
		if err != nil {
			res.Errors = append(res.Errors, Problem{i, r["seq"], err.Error()})
		}
		prev = d
		res.Head = d
	}
	res.OK = len(res.Errors) == 0
	return res
}

// ReadLedger reads a JSONL ledger, keeping numbers exact.
func ReadLedger(rd io.Reader) ([]map[string]any, error) {
	var out []map[string]any
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(text))
		dec.UseNumber()
		var r map[string]any
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}
