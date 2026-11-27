use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use verfy_verify::{check_approvals, verify_approval_proof};

fn vectors() -> Value {
    let path = format!("{}/../../verfy-cli/tests/fixtures/passkey_proofs.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn proofs_made_with_node_check_out() {
    let v = vectors();
    let (id, args, origin) = (v["approval_id"].as_str().unwrap(), v["args_sha256"].as_str().unwrap(), v["origin"].as_str().unwrap());
    for p in v["proofs"].as_array().unwrap() {
        assert_eq!(verify_approval_proof(p, id, args, origin), Vec::<String>::new(), "alg {}", p["alg"]);
    }
    let es = &v["proofs"][0];
    let other = "sha256:".to_string() + &"00".repeat(32);
    assert!(verify_approval_proof(es, id, &other, origin).contains(&"the passkey signed a different request, arguments or decision".to_string()));
    assert_eq!(
        verify_approval_proof(es, id, args, "https://evil.example"),
        vec!["the passkey was used on 'https://verfy.dev', not 'https://evil.example'".to_string(), "the passkey belongs to another site".to_string()]
    );
    let mut flipped = es.clone();
    flipped["decision"] = json!("reject");
    assert!(verify_approval_proof(&flipped, id, args, origin).contains(&"the passkey signed a different request, arguments or decision".to_string()));
    for p in v["proofs"].as_array().unwrap().iter().take(3) {
        let mut sig = URL_SAFE_NO_PAD.decode(p["signature"].as_str().unwrap()).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 1;
        let mut forged = p.clone();
        forged["signature"] = json!(URL_SAFE_NO_PAD.encode(&sig));
        assert_eq!(verify_approval_proof(&forged, id, args, origin), vec!["the passkey's signature does not check out".to_string()], "alg {}", p["alg"]);
    }
    let mut unknown = es.clone();
    unknown["alg"] = json!(-999);
    assert_eq!(verify_approval_proof(&unknown, id, args, origin), vec!["unknown key type -999".to_string()]);
    assert_eq!(verify_approval_proof(&json!({"v": "x"}), id, args, origin), vec!["not a Verfy passkey proof".to_string()]);
}

#[test]
fn a_ledger_with_approvals() {
    let v = vectors();
    let mut ledger = vec![
        json!({"seq": 0, "action": {"args_sha256": v["args_sha256"]}, "decision": {"approval": {"id": v["approval_id"], "origin": v["origin"], "proofs": [v["proofs"][1]]}}}),
        json!({"seq": 1, "decision": {}}),
    ];
    let (checked, problems) = check_approvals(&ledger);
    assert_eq!((checked, problems.len()), (1, 0));
    ledger[0]["action"]["args_sha256"] = json!("sha256:".to_string() + &"11".repeat(32));
    let (_, problems) = check_approvals(&ledger);
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].error, "passkey approval: the passkey signed a different request, arguments or decision");
}
