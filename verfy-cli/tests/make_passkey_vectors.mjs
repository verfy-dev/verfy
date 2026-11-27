// Writes tests/fixtures/passkey_proofs.json: passkey approval proofs as Verfy Cloud stores them
// (verfy.approval-proof/1), signed by keys node:crypto makes the way a passkey would (ES256, EdDSA, RS256), so the
// pure-Python checks in verfy/passkeys.py are tested against an independent implementation.
//
//   node tests/make_passkey_vectors.mjs
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { writeFileSync } from "node:fs";

const b64u = (b) => Buffer.from(b).toString("base64url");
const sha = (b) => createHash("sha256").update(b).digest();
const ORIGIN = "https://verfy.dev";
const RP = "verfy.dev";
const APPROVAL = "11111111-2222-4333-8444-555555555555";
const ARGS = "sha256:" + "ab".repeat(32);
const USER = "00000000-0000-4000-8000-0000000000a1";

function challenge(approve) {
  return b64u(sha(`verfy-approval/1\n${APPROVAL}\n${ARGS}\n${approve ? "approve" : "reject"}\n${USER}`));
}

function proof(alg, approve = true, count = 7) {
  const k = alg === -8 ? generateKeyPairSync("ed25519") : alg === -7 ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = k.publicKey.export({ format: "jwk" });
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: challenge(approve), origin: ORIGIN, crossOrigin: false }));
  const auth = Buffer.alloc(37);
  sha(RP).copy(auth, 0);
  auth[32] = 0x05; // user present, user verified
  auth.writeUInt32BE(count, 33);
  const data = Buffer.concat([auth, sha(clientData)]);
  const sig = alg === -8 ? sign(null, data, k.privateKey) : sign("sha256", data, k.privateKey); // ES256 comes out DER
  return {
    v: "verfy.approval-proof/1",
    method: "passkey",
    decision: approve ? "approve" : "reject",
    user_id: USER,
    credential_id: b64u(Buffer.from("credential-" + alg)),
    alg,
    public_key: jwk,
    client_data_json: b64u(clientData),
    authenticator_data: b64u(auth),
    signature: b64u(sig),
  };
}

const out = {
  note: "made by tests/make_passkey_vectors.mjs with node:crypto",
  origin: ORIGIN,
  approval_id: APPROVAL,
  args_sha256: ARGS,
  proofs: [proof(-7), proof(-8), proof(-257), proof(-7, false)],
};
writeFileSync(new URL("./fixtures/passkey_proofs.json", import.meta.url), JSON.stringify(out, null, 1) + "\n");
console.log("wrote", out.proofs.length, "proofs");
