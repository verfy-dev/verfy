// Writes tests/fixtures/ap2_jws.json: AP2-style authorizations (compact JWS) signed with node:crypto, ES256 and RS256.
//   node tests/make_ap2_vectors.mjs
import { generateKeyPairSync, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
const b64u = (b) => Buffer.from(b).toString("base64url");
function jws(alg) {
  const k = alg === "ES256" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("rsa", { modulusLength: 2048 });
  const head = b64u(JSON.stringify({ alg, typ: "JWT" }));
  const body = b64u(JSON.stringify({ iss: "merchant.example", cart_hash: "abc", iat: 1795000000, exp: 4102444800 }));
  const data = Buffer.from(head + "." + body);
  const sig = alg === "ES256" ? sign("sha256", data, { key: k.privateKey, dsaEncoding: "ieee-p1363" }) : sign("sha256", data, k.privateKey);
  return { alg, token: head + "." + body + "." + b64u(sig), jwk: k.publicKey.export({ format: "jwk" }) };
}
writeFileSync(new URL("./fixtures/ap2_jws.json", import.meta.url), JSON.stringify({ note: "made by tests/make_ap2_vectors.mjs", tokens: [jws("ES256"), jws("RS256")] }, null, 1) + "\n");
console.log("ok");
