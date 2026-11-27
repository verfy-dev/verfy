package verfy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
)

// ApprovalProofVersion is the format of a passkey approval proof in a receipt's decision.approval.proofs.
const ApprovalProofVersion = "verfy.approval-proof/1"

// ApprovalChallenge is what a passkey signs to approve or reject one request: the request id, the hash of the call's
// arguments (the receipt's action.args_sha256) and the decision, for one Verfy user.
func ApprovalChallenge(approvalID, argsSHA256 string, approve bool, userID string) string {
	d := "reject"
	if approve {
		d = "approve"
	}
	sum := sha256.Sum256([]byte("verfy-approval/1\n" + approvalID + "\n" + argsSHA256 + "\n" + d + "\n" + userID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func unb64u(v any) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return b, err == nil
}

// pyRepr writes a value the way the Python CLI's messages do, so all verifiers say the same thing.
func pyRepr(v any) string {
	switch x := v.(type) {
	case string:
		return "'" + x + "'"
	case nil:
		return "None"
	default:
		return fmt.Sprint(x)
	}
}

func intOf(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		if x == float64(int64(x)) {
			return int64(x), true
		}
	}
	return 0, false
}

func verifyPasskeySig(alg int64, jwk map[string]any, msg, sig []byte) bool {
	switch alg {
	case -8:
		x, ok := unb64u(jwk["x"])
		if !ok || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || len(x) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(x), msg, sig)
	case -7:
		x, okx := unb64u(jwk["x"])
		y, oky := unb64u(jwk["y"])
		if !okx || !oky || jwk["kty"] != "EC" || jwk["crv"] != "P-256" || len(x) != 32 || len(y) != 32 {
			return false
		}
		curve := elliptic.P256()
		X, Y := new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
		if !curve.IsOnCurve(X, Y) {
			return false
		}
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: curve, X: X, Y: Y}, h[:], sig)
	case -257:
		n, okn := unb64u(jwk["n"])
		e, oke := unb64u(jwk["e"])
		if !okn || !oke || jwk["kty"] != "RSA" || len(e) == 0 || len(e) > 4 {
			return false
		}
		N := new(big.Int).SetBytes(n)
		E := int(new(big.Int).SetBytes(e).Int64())
		if N.BitLen() < 2048 || E < 3 {
			return false
		}
		h := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(&rsa.PublicKey{N: N, E: E}, crypto.SHA256, h[:], sig) == nil
	}
	return false
}

// VerifyApprovalProof lists what is wrong with one passkey proof; none means the passkey signed this approval (or
// rejection) of exactly these arguments, on origin, with the person verified (Face ID, a fingerprint or a PIN).
// It does not show whose passkey it was: Verfy Cloud registered the key to the account named by user_id.
func VerifyApprovalProof(proof map[string]any, approvalID, argsSHA256, origin string) []string {
	if proof == nil || proof["v"] != ApprovalProofVersion || proof["method"] != "passkey" {
		return []string{"not a Verfy passkey proof"}
	}
	decision, _ := proof["decision"].(string)
	if decision != "approve" && decision != "reject" {
		return []string{"the proof names no decision"}
	}
	clientRaw, ok1 := unb64u(proof["client_data_json"])
	auth, ok2 := unb64u(proof["authenticator_data"])
	sig, ok3 := unb64u(proof["signature"])
	var client map[string]any
	if !ok1 || !ok2 || !ok3 || json.Unmarshal(clientRaw, &client) != nil {
		return []string{"the proof is not readable"}
	}
	var problems []string
	user, _ := proof["user_id"].(string)
	want := ApprovalChallenge(approvalID, argsSHA256, decision == "approve", user)
	if client == nil || client["type"] != "webauthn.get" {
		problems = append(problems, "the browser answered a different WebAuthn call")
	} else if client["challenge"] != want {
		problems = append(problems, "the passkey signed a different request, arguments or decision")
	}
	if client != nil && client["origin"] != origin {
		problems = append(problems, fmt.Sprintf("the passkey was used on %s, not %s", pyRepr(client["origin"]), pyRepr(origin)))
	}
	if client != nil && client["crossOrigin"] == true {
		problems = append(problems, "the passkey was used inside another site's frame")
	}
	rp := ""
	if u, err := url.Parse(origin); err == nil {
		rp = u.Hostname()
	}
	rpHash := sha256.Sum256([]byte(rp))
	switch {
	case len(auth) < 37 || !bytes.Equal(auth[:32], rpHash[:]):
		problems = append(problems, "the passkey belongs to another site")
	case auth[32]&0x01 == 0:
		problems = append(problems, "nobody touched the passkey")
	case auth[32]&0x04 == 0:
		problems = append(problems, "the passkey did not verify the person (Face ID, fingerprint or PIN)")
	}
	alg, isInt := intOf(proof["alg"])
	jwk, _ := proof["public_key"].(map[string]any)
	if !isInt || (alg != -7 && alg != -8 && alg != -257) {
		problems = append(problems, "unknown key type "+pyRepr(proof["alg"]))
	} else {
		cd := sha256.Sum256(clientRaw)
		signed := append(append([]byte{}, auth...), cd[:]...)
		if jwk == nil || !verifyPasskeySig(alg, jwk, signed, sig) {
			problems = append(problems, "the passkey's signature does not check out")
		}
	}
	return problems
}

// CheckApprovals checks every passkey proof in a ledger's decision.approval; checked counts receipts that carry one.
func CheckApprovals(receipts []map[string]any) (checked int, problems []Problem) {
	problems = []Problem{}
	for i, r := range receipts {
		dec, _ := r["decision"].(map[string]any)
		appr, _ := dec["approval"].(map[string]any)
		proofs, _ := appr["proofs"].([]any)
		if len(proofs) == 0 {
			continue
		}
		checked++
		act, _ := r["action"].(map[string]any)
		args, _ := act["args_sha256"].(string)
		id, _ := appr["id"].(string)
		origin, _ := appr["origin"].(string)
		for _, p := range proofs {
			pm, _ := p.(map[string]any)
			for _, e := range VerifyApprovalProof(pm, id, args, origin) {
				problems = append(problems, Problem{i, r["seq"], "passkey approval: " + e})
			}
		}
	}
	return checked, problems
}
