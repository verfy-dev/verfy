package verfy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var fixtures = filepath.Join("..", "..", "verfy-cli", "tests", "fixtures")

func load(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestCanonical(t *testing.T) {
	var cases []struct {
		Value     any    `json:"value"`
		Canonical string `json:"canonical"`
	}
	load(t, "canonical.json", &cases)
	for i, c := range cases {
		got, err := Canonical(c.Value)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.Canonical {
			t.Errorf("case %d:\n got %s\nwant %s", i, got, c.Canonical)
		}
	}
}

func TestReceiptVectors(t *testing.T) {
	var v struct {
		PublicKey string           `json:"public_key"`
		Kid       string           `json:"kid"`
		Receipts  []map[string]any `json:"receipts"`
		Hashes    []string         `json:"hashes"`
	}
	load(t, "receipts.json", &v)
	pub, err := PublicKey(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if KeyID(pub) != v.Kid {
		t.Fatalf("kid %s, want %s", KeyID(pub), v.Kid)
	}
	for i, r := range v.Receipts {
		if !VerifyReceipt(r, pub) {
			t.Errorf("receipt %d does not verify", i)
		}
		if d, _ := Digest(r); d != v.Hashes[i] {
			t.Errorf("receipt %d hash %s, want %s", i, d, v.Hashes[i])
		}
	}
	res := VerifyLedger(v.Receipts, pub)
	if !res.OK || res.Count != len(v.Receipts) || res.Head != v.Hashes[len(v.Hashes)-1] {
		t.Fatalf("ledger: %+v", res)
	}
	// an edited verdict breaks that receipt's signature and the next one's link
	edited := make([]map[string]any, len(v.Receipts))
	for i, r := range v.Receipts {
		c := map[string]any{}
		for k, x := range r {
			c[k] = x
		}
		edited[i] = c
	}
	dec := map[string]any{}
	for k, x := range edited[1]["decision"].(map[string]any) {
		dec[k] = x
	}
	dec["verdict"] = "allow"
	edited[1]["decision"] = dec
	bad := VerifyLedger(edited, pub)
	if bad.OK || len(bad.Errors) != 2 || bad.Errors[0].Error != "bad signature" {
		t.Fatalf("edited ledger: %+v", bad)
	}
	// a removed receipt breaks the numbering and the chain
	if VerifyLedger(append([]map[string]any{v.Receipts[0]}, v.Receipts[2:]...), pub).OK {
		t.Fatal("a ledger with a receipt taken out verified")
	}
}
