"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");

const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const ok = (r) => {
  assert.ok(r && !r.error, r && r.error);
  return r;
};

// Same vectors the Go tests check, through the WASM build.
module.exports = (pq, root) => {
  const v = JSON.parse(fs.readFileSync(path.join(root, "hybridsig/testdata/vectors.json")));
  let n = 0;
  for (const c of v.valid) {
    assert.strictEqual(ok(pq.hybridsigVerify(hex(v.public_key), c.label, hex(c.msg), hex(c.sig))), true, c.name);
    n++;
  }
  for (const c of v.invalid) {
    assert.ok(pq.hybridsigVerify(hex(v.public_key), c.label, hex(c.msg), hex(c.sig)).error, `${c.name} verified`);
    n++;
  }
  const k = ok(pq.hybridsigGenerate());
  assert.ok(k.id.startsWith("mldsa65+ed25519:"));
  const msg = new TextEncoder().encode("hello from js");
  const sig = ok(pq.hybridsigSign(k.mldsaSeed, k.ed25519Seed, "ky-primitives/pqwasm-test/1", msg));
  assert.strictEqual(sig.length, 16 + 3309 + 64);
  assert.strictEqual(ok(pq.hybridsigVerify(k.publicKey, "ky-primitives/pqwasm-test/1", msg, sig)), true);
  assert.ok(pq.hybridsigVerify(k.publicKey, "ky-primitives/pqwasm-test/2", msg, sig).error, "other label verified");
  assert.ok(pq.hybridsigSign(k.mldsaSeed, k.ed25519Seed, msg, msg).error, "bytes accepted as label");
  return n + 4;
};
