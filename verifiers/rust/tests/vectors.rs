use serde_json::Value;
use verfy_verify::{canonical, digest, key_id, public_key, verify_ledger, verify_receipt};

fn fixture(name: &str) -> Value {
    let path = format!("{}/../../verfy-cli/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn canonical_json() {
    for case in fixture("canonical.json").as_array().unwrap() {
        assert_eq!(canonical(&case["value"]).unwrap(), case["canonical"].as_str().unwrap());
    }
}

#[test]
fn receipt_vectors() {
    let v = fixture("receipts.json");
    let pk = public_key(v["public_key"].as_str().unwrap()).unwrap();
    assert_eq!(key_id(&pk), v["kid"].as_str().unwrap());
    let receipts = v["receipts"].as_array().unwrap().clone();
    let hashes = v["hashes"].as_array().unwrap();
    for (i, r) in receipts.iter().enumerate() {
        assert!(verify_receipt(r, &pk), "receipt {} does not verify", i);
        assert_eq!(digest(r).unwrap(), hashes[i].as_str().unwrap());
    }
    let res = verify_ledger(&receipts, &pk);
    assert!(res.ok, "{:?}", res);
    assert_eq!(res.head.as_deref(), hashes.last().unwrap().as_str());

    let mut edited = receipts.clone();
    edited[1]["decision"]["verdict"] = Value::from("allow");
    let bad = verify_ledger(&edited, &pk);
    assert!(!bad.ok);
    assert_eq!(bad.errors.len(), 2);
    assert_eq!(bad.errors[0].error, "bad signature");

    let mut cut = vec![receipts[0].clone()];
    cut.extend_from_slice(&receipts[2..]);
    assert!(!verify_ledger(&cut, &pk).ok);
}
