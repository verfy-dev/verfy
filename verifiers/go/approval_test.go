package verfy

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

type passkeyVectors struct {
	Origin     string           `json:"origin"`
	ApprovalID string           `json:"approval_id"`
	ArgsSHA256 string           `json:"args_sha256"`
	Proofs     []map[string]any `json:"proofs"`
}

func clone(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestPasskeyProofs(t *testing.T) {
	var v passkeyVectors
	load(t, "passkey_proofs.json", &v)
	check := func(p map[string]any) []string { return VerifyApprovalProof(p, v.ApprovalID, v.ArgsSHA256, v.Origin) }
	for i, p := range v.Proofs {
		if got := check(p); len(got) != 0 {
			t.Errorf("proof %d (alg %v): %v", i, p["alg"], got)
		}
	}
	es := v.Proofs[0]
	if got := VerifyApprovalProof(es, v.ApprovalID, "sha256:"+strings.Repeat("00", 32), v.Origin); !contains(got, "the passkey signed a different request, arguments or decision") {
		t.Errorf("other arguments: %v", got)
	}
	want := []string{"the passkey was used on 'https://verfy.dev', not 'https://evil.example'", "the passkey belongs to another site"}
	if got := VerifyApprovalProof(es, v.ApprovalID, v.ArgsSHA256, "https://evil.example"); !reflect.DeepEqual(got, want) {
		t.Errorf("other site: %v", got)
	}
	flipped := clone(es)
	flipped["decision"] = "reject"
	if got := check(flipped); !contains(got, "the passkey signed a different request, arguments or decision") {
		t.Errorf("flipped decision: %v", got)
	}
	for _, p := range v.Proofs[:3] {
		sig, _ := base64.RawURLEncoding.DecodeString(p["signature"].(string))
		sig[len(sig)-1] ^= 1
		forged := clone(p)
		forged["signature"] = base64.RawURLEncoding.EncodeToString(sig)
		if got := check(forged); !reflect.DeepEqual(got, []string{"the passkey's signature does not check out"}) {
			t.Errorf("forged alg %v: %v", p["alg"], got)
		}
	}
	if got := check(map[string]any{"v": "x"}); !reflect.DeepEqual(got, []string{"not a Verfy passkey proof"}) {
		t.Errorf("not a proof: %v", got)
	}
}

func TestCheckApprovals(t *testing.T) {
	var v passkeyVectors
	load(t, "passkey_proofs.json", &v)
	ledger := []map[string]any{
		{"seq": 0, "action": map[string]any{"args_sha256": v.ArgsSHA256}, "decision": map[string]any{"approval": map[string]any{"id": v.ApprovalID, "origin": v.Origin, "proofs": []any{v.Proofs[1]}}}},
		{"seq": 1, "decision": map[string]any{}},
	}
	if n, problems := CheckApprovals(ledger); n != 1 || len(problems) != 0 {
		t.Errorf("checked %d, problems %v", n, problems)
	}
	ledger[0]["action"] = map[string]any{"args_sha256": "sha256:" + strings.Repeat("11", 32)}
	if _, problems := CheckApprovals(ledger); len(problems) != 1 || problems[0].Error != "passkey approval: the passkey signed a different request, arguments or decision" {
		t.Errorf("other arguments: %v", problems)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
