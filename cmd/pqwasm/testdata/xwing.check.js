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
  const v = JSON.parse(fs.readFileSync(path.join(root, "xwing/testdata/vectors.json")));
  let n = 0;
  for (const c of v.valid) {
    const got = ok(pq.xwingOpen(hex(v.seed), hex(c.info), hex(c.aad), hex(c.sealed)));
    assert.deepStrictEqual(Buffer.from(got).toString("hex"), c.msg, c.name);
    n++;
  }
  for (const c of v.invalid) {
    const r = pq.xwingOpen(hex(v.seed), hex(c.info), hex(c.aad), hex(c.sealed));
    assert.ok(r.error, `${c.name} opened`);
    n++;
  }
  const k = ok(pq.xwingGenerate());
  assert.strictEqual(k.publicKey.length, 1216);
  const info = new TextEncoder().encode("ky-primitives/pqwasm-test/1");
  const msg = new TextEncoder().encode("hello from js");
  const sealed = ok(pq.xwingSeal(k.publicKey, info, new Uint8Array(), msg));
  assert.strictEqual(sealed.length, 1 + 1120 + msg.length + 16);
  assert.deepStrictEqual(ok(pq.xwingOpen(k.seed, info, new Uint8Array(), sealed)), msg);
  assert.ok(pq.xwingSeal(k.publicKey, new Uint8Array(), new Uint8Array(), msg).error, "empty label sealed");
  assert.ok(pq.xwingSeal("not bytes", info, info, msg).error, "string accepted as bytes");
  return n + 4;
};
