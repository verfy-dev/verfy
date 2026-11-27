//! Passkey approvals in receipts (`decision.approval.proofs`, format `verfy.approval-proof/1`), checked offline the way
//! the Python CLI (`verfy verify`), the JavaScript engine and the Go package check them, with the same messages.
//!
//! A proof is a WebAuthn assertion: the passkey signed `authenticatorData || SHA-256(clientDataJSON)`, and
//! clientDataJSON carries the challenge Verfy Cloud asked for, which binds the request id, the hash of the call's
//! arguments (the receipt's `action.args_sha256`) and the decision. ES256, EdDSA and RS256 keys are checked.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::Problem;

/// The format of one proof.
pub const PROOF_VERSION: &str = "verfy.approval-proof/1";

/// What a passkey signs to approve or reject one request.
pub fn approval_challenge(approval_id: &str, args_sha256: &str, approve: bool, user_id: &str) -> String {
    let d = if approve { "approve" } else { "reject" };
    URL_SAFE_NO_PAD.encode(Sha256::digest(format!("verfy-approval/1\n{}\n{}\n{}\n{}", approval_id, args_sha256, d, user_id).as_bytes()))
}

fn unb64u(v: Option<&Value>) -> Option<Vec<u8>> {
    let s = v?.as_str()?;
    if s.is_empty() {
        return None;
    }
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// A value written the way the Python CLI's messages write it.
fn py_repr(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => format!("'{}'", s),
        None | Some(Value::Null) => "None".into(),
        Some(other) => other.to_string(),
    }
}

/// The host of an origin such as `https://verfy.dev` (what the passkey's relying party id is).
fn host_of(origin: &str) -> String {
    let rest = origin.split_once("://").map(|(_, r)| r).unwrap_or("");
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let host = if authority.starts_with('[') {
        authority.split(']').next().unwrap_or("").trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or("")
    };
    host.to_lowercase()
}

fn verify_signature(alg: i64, jwk: &serde_json::Map<String, Value>, msg: &[u8], sig: &[u8]) -> bool {
    let field = |k: &str| unb64u(jwk.get(k));
    let is = |k: &str, want: &str| jwk.get(k).and_then(Value::as_str) == Some(want);
    match alg {
        -8 => {
            if !is("kty", "OKP") || !is("crv", "Ed25519") {
                return false;
            }
            let (Some(x), Ok(sig)) = (field("x"), <[u8; 64]>::try_from(sig)) else { return false };
            let Ok(x) = <[u8; 32]>::try_from(x.as_slice()) else { return false };
            let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&x) else { return false };
            ed25519_dalek::Verifier::verify(&key, msg, &ed25519_dalek::Signature::from_bytes(&sig)).is_ok()
        }
        -7 => {
            if !is("kty", "EC") || !is("crv", "P-256") {
                return false;
            }
            let (Some(x), Some(y)) = (field("x"), field("y")) else { return false };
            if x.len() != 32 || y.len() != 32 {
                return false;
            }
            let mut sec1 = vec![0x04u8];
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else { return false };
            let Ok(sig) = p256::ecdsa::Signature::from_der(sig) else { return false };
            p256::ecdsa::signature::Verifier::verify(&key, msg, &sig).is_ok()
        }
        -257 => {
            if !is("kty", "RSA") {
                return false;
            }
            let (Some(n), Some(e)) = (field("n"), field("e")) else { return false };
            let n = rsa::BigUint::from_bytes_be(&n);
            let e = rsa::BigUint::from_bytes_be(&e);
            if n.bits() < 2048 || e < rsa::BigUint::from(3u8) {
                return false;
            }
            let Ok(key) = rsa::RsaPublicKey::new(n, e) else { return false };
            let verifier = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key);
            let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig) else { return false };
            rsa::signature::Verifier::verify(&verifier, msg, &sig).is_ok()
        }
        _ => false,
    }
}

/// What is wrong with one proof; empty means the passkey signed this approval (or rejection) of exactly these
/// arguments, on `origin`, with the person verified. It does not show whose passkey it was.
pub fn verify_approval_proof(proof: &Value, approval_id: &str, args_sha256: &str, origin: &str) -> Vec<String> {
    let Some(p) = proof.as_object() else { return vec!["not a Verfy passkey proof".into()] };
    if p.get("v").and_then(Value::as_str) != Some(PROOF_VERSION) || p.get("method").and_then(Value::as_str) != Some("passkey") {
        return vec!["not a Verfy passkey proof".into()];
    }
    let decision = p.get("decision").and_then(Value::as_str).unwrap_or("");
    if decision != "approve" && decision != "reject" {
        return vec!["the proof names no decision".into()];
    }
    let (Some(client_raw), Some(auth), Some(sig)) = (unb64u(p.get("client_data_json")), unb64u(p.get("authenticator_data")), unb64u(p.get("signature"))) else {
        return vec!["the proof is not readable".into()];
    };
    let Ok(client) = serde_json::from_slice::<Value>(&client_raw) else { return vec!["the proof is not readable".into()] };
    let mut problems = Vec::new();
    let user = p.get("user_id").and_then(Value::as_str).unwrap_or("");
    let want = approval_challenge(approval_id, args_sha256, decision == "approve", user);
    let c = client.as_object();
    if c.and_then(|c| c.get("type")).and_then(Value::as_str) != Some("webauthn.get") {
        problems.push("the browser answered a different WebAuthn call".into());
    } else if c.and_then(|c| c.get("challenge")).and_then(Value::as_str) != Some(want.as_str()) {
        problems.push("the passkey signed a different request, arguments or decision".into());
    }
    if let Some(c) = c {
        if c.get("origin").and_then(Value::as_str) != Some(origin) {
            problems.push(format!("the passkey was used on {}, not '{}'", py_repr(c.get("origin")), origin));
        }
        if c.get("crossOrigin") == Some(&Value::Bool(true)) {
            problems.push("the passkey was used inside another site's frame".into());
        }
    }
    let rp_hash = Sha256::digest(host_of(origin).as_bytes());
    if auth.len() < 37 || auth[..32] != rp_hash[..] {
        problems.push("the passkey belongs to another site".into());
    } else if auth[32] & 0x01 == 0 {
        problems.push("nobody touched the passkey".into());
    } else if auth[32] & 0x04 == 0 {
        problems.push("the passkey did not verify the person (Face ID, fingerprint or PIN)".into());
    }
    match p.get("alg").and_then(Value::as_i64).filter(|a| [-7, -8, -257].contains(a)) {
        None => problems.push(format!("unknown key type {}", py_repr(p.get("alg")))),
        Some(alg) => {
            let mut signed = auth.clone();
            signed.extend_from_slice(&Sha256::digest(&client_raw));
            let ok = p.get("public_key").and_then(Value::as_object).map(|jwk| verify_signature(alg, jwk, &signed, &sig)).unwrap_or(false);
            if !ok {
                problems.push("the passkey's signature does not check out".into());
            }
        }
    }
    problems
}

/// Every passkey proof in a ledger, checked; the count is of receipts that carry at least one.
pub fn check_approvals(receipts: &[Value]) -> (usize, Vec<Problem>) {
    let mut checked = 0;
    let mut problems = Vec::new();
    for (i, r) in receipts.iter().enumerate() {
        let appr = &r["decision"]["approval"];
        let Some(proofs) = appr["proofs"].as_array().filter(|p| !p.is_empty()) else { continue };
        checked += 1;
        let args = r["action"]["args_sha256"].as_str().unwrap_or("");
        let id = appr["id"].as_str().unwrap_or("");
        let origin = appr["origin"].as_str().unwrap_or("");
        for proof in proofs {
            for e in verify_approval_proof(proof, id, args, origin) {
                problems.push(Problem { index: i, seq: r.get("seq").and_then(Value::as_i64), error: format!("passkey approval: {}", e) });
            }
        }
    }
    (checked, problems)
}
