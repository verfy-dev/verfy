//! Check Verfy receipts (format `verfy.receipt/1`) and ledgers in Rust.
//!
//! A receipt is signed with Ed25519 over its canonical JSON (keys sorted by UTF-16 code units, no whitespace,
//! numbers written the way JavaScript writes them), without its `sig` member. Each receipt carries the SHA-256 of
//! the canonical receipt before it in `prev`, and `seq` counts from 0, so a ledger cannot be edited, reordered or
//! trimmed in the middle without [`verify_ledger`] noticing.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};

/// The receipt format this crate checks.
pub const VERSION: &str = "verfy.receipt/1";

/// One thing wrong with a ledger.
#[derive(Debug, Clone, PartialEq)]
pub struct Problem {
    pub index: usize,
    pub seq: Option<i64>,
    pub error: String,
}

/// What [`verify_ledger`] found.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub ok: bool,
    pub count: usize,
    pub head: Option<String>,
    pub errors: Vec<Problem>,
}

/// The bytes Verfy hashes and signs for a JSON value.
pub fn canonical(v: &Value) -> Result<String, String> {
    let mut out = String::new();
    write(&mut out, v)?;
    Ok(out)
}

fn write(out: &mut String, v: &Value) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n)?),
        Value::String(s) => string(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(out, x)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(out, k);
                out.push(':');
                write(out, &m[*k])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON number the way JavaScript's `Number.prototype.toString` writes it.
fn number(n: &Number) -> Result<String, String> {
    if let Some(i) = n.as_i64() {
        if i.abs() < (1i64 << 53) {
            return Ok(i.to_string());
        }
    }
    let f = n.as_f64().ok_or("not a number")?;
    if !f.is_finite() {
        return Err("NaN and Infinity cannot be signed".into());
    }
    if f == 0.0 {
        return Ok("0".into());
    }
    let (sign, f) = if f < 0.0 { ("-", -f) } else { ("", f) };
    let e = format!("{:e}", f); // shortest round-trip digits: d.ddde[-]x
    let (mant, exp) = e.split_once('e').ok_or("bad float")?;
    let exp: i32 = exp.parse().map_err(|_| "bad exponent")?;
    let mut digits: String = mant.chars().filter(|c| *c != '.').collect();
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    let k = digits.len() as i32;
    let p = exp + 1;
    if k <= p && p <= 21 {
        return Ok(format!("{}{}{}", sign, digits, "0".repeat((p - k) as usize)));
    }
    if 0 < p && p <= 21 {
        return Ok(format!("{}{}.{}", sign, &digits[..p as usize], &digits[p as usize..]));
    }
    if -6 < p && p <= 0 {
        return Ok(format!("{}0.{}{}", sign, "0".repeat((-p) as usize), digits));
    }
    let es = if p - 1 >= 0 { "+" } else { "-" };
    let ea = (p - 1).abs();
    if k == 1 {
        Ok(format!("{}{}e{}{}", sign, digits, es, ea))
    } else {
        Ok(format!("{}{}.{}e{}{}", sign, &digits[..1], &digits[1..], es, ea))
    }
}

/// `sha256:<hex>` of the canonical form.
pub fn digest(v: &Value) -> Result<String, String> {
    Ok(format!("sha256:{}", hex(&Sha256::digest(canonical(v)?.as_bytes()))))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The `kid` Verfy derives from a public key.
pub fn key_id(public: &[u8; 32]) -> String {
    format!("atl_{}", &hex(&Sha256::digest(public))[..16])
}

/// Decode a base64url public key, as `verfy key` prints it.
pub fn public_key(s: &str) -> Result<[u8; 32], String> {
    let b = URL_SAFE_NO_PAD.decode(s.trim().trim_end_matches('=')).map_err(|_| "not base64url")?;
    b.try_into().map_err(|_| "an Ed25519 public key is 32 bytes".to_string())
}

/// Check one receipt's version, key id and signature.
pub fn verify_receipt(r: &Value, public: &[u8; 32]) -> bool {
    let Some(obj) = r.as_object() else { return false };
    if obj.get("v").and_then(Value::as_str) != Some(VERSION) || obj.get("kid").and_then(Value::as_str) != Some(&key_id(public)) {
        return false;
    }
    let Some(sig) = obj.get("sig").and_then(Value::as_str).and_then(|s| URL_SAFE_NO_PAD.decode(s).ok()) else { return false };
    let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else { return false };
    let body: Map<String, Value> = obj.iter().filter(|(k, _)| k.as_str() != "sig").map(|(k, v)| (k.clone(), v.clone())).collect();
    let Ok(bytes) = canonical(&Value::Object(body)) else { return false };
    let Ok(key) = VerifyingKey::from_bytes(public) else { return false };
    key.verify(bytes.as_bytes(), &Signature::from_bytes(&sig)).is_ok()
}

/// Check every signature and every link, as `verfy verify --ledger` does.
pub fn verify_ledger(receipts: &[Value], public: &[u8; 32]) -> Outcome {
    let mut errors = Vec::new();
    let mut prev: Option<String> = None;
    for (i, r) in receipts.iter().enumerate() {
        let seq = r.get("seq").and_then(Value::as_i64);
        if !verify_receipt(r, public) {
            errors.push(Problem { index: i, seq, error: "bad signature".into() });
        }
        if seq != Some(i as i64) {
            errors.push(Problem { index: i, seq, error: format!("expected seq {}", i) });
        }
        if r.get("prev").and_then(Value::as_str).map(String::from) != prev {
            errors.push(Problem { index: i, seq, error: "broken chain: prev does not match the receipt before it".into() });
        }
        prev = digest(r).ok();
    }
    Outcome { ok: errors.is_empty(), count: receipts.len(), head: prev, errors }
}

/// Read a JSONL ledger.
pub fn read_ledger(text: &str) -> Result<Vec<Value>, String> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| serde_json::from_str(l).map_err(|e| format!("line {}: {}", i + 1, e)))
        .collect()
}
