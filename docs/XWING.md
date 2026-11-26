# X-Wing sealing

[Overview](../README.md) · [Assurance case](ASSURANCE-CASE.md) · [Contributing](../CONTRIBUTING.md) · [Strong cryptography](STRONG-CRYPTO.md) · [Backup container](CAPSULE.md)

## xwing

Seals a message to one recipient's X-Wing public key, so a recorded ciphertext stays
unreadable unless both ML-KEM-768 and X25519 are broken. It is the shared replacement for
the suite's classical key wraps (spec B wave W1): one implementation, one wire format, and
one vector file that browser, Rust or JS ports check against.

```go
priv, err := xwing.Generate()                 // keep priv.Seed() (32 bytes) secret
pub := priv.Public()                          // publish pub.Bytes() (1216 bytes); name it by pub.ID()

sealed, err := xwing.Seal(pub, []byte("kyidentity/ad-password/2"), aad, msg)
msg, err := xwing.Open(priv, []byte("kyidentity/ad-password/2"), aad, sealed)
```

**Suite.** HPKE base mode (RFC 9180) through Go's `crypto/hpke`: KEM `0x647A`
(`MLKEM768X25519`, X-Wing), KDF HKDF-SHA256, AEAD AES-256-GCM. Nothing is negotiated.

**Wire format.** `0x01 ‖ enc (1120 bytes) ‖ HPKE ciphertext (len(msg) + 16)`. The version
byte says "this suite"; `Open` refuses any other value with `ErrVersion` before touching a
key. The suite IDs are already in HPKE's key schedule, so the format adds no crypto of its
own: any HPKE library with X-Wing reads `sealed[1:]`.

**info and aad.** `info` is the HPKE info and must start with the caller's label:
`label` or `label ‖ 0x00 ‖ context`, with a non-empty label such as
`kyidentity/ad-password/2`. `Seal` and `Open` refuse an empty label (`ErrLabel`), so two
callers cannot share a context by accident. `aad` is the AEAD's additional data, for
whatever the ciphertext is stored beside (a record ID, a recipient key ID). A changed byte
in enc, ciphertext, info or aad, or the wrong key, fails as `ErrOpen` and says nothing more.

**Keys.** The keypair is `recoverykey`'s: the same 32-byte seed gives the same 1216-byte
public key, and a message sealed to a `recoverykey` public key opens with that seed here.
`ID()` differs on purpose: it is hex SHA-256(`"ky/xwing/1/key-id"` ‖ 0x00 ‖ public key),
so an xwing key name never collides with a capsule's. `recoverykey` itself is unchanged,
including its wire output (its draft-vector golden tests still pin it), so capsules do not
move.

**Vectors.** `xwing/testdata/vectors.json` holds the draft-ietf-hpke-pq seed, its public key
and ID, valid sealed messages, and refusals (flipped enc or ciphertext byte, changed info
or aad, version 2, empty label, truncation) with the error each must give. They are made
by the production `Seal` with Go's `testing/cryptotest.SetGlobalRandom` fixing the
randomness (`go test ./xwing -run TestVectors -update`; the same Go version rewrites the
same bytes). Readers check that `Open` gives each `msg` and refuses each invalid case.

**Browsers.** `cmd/pqwasm` exports `xwingGenerate`, `xwingSeal` and `xwingOpen` over
`Uint8Array` when built with `GOOS=js GOARCH=wasm`. `TestWASMUnderNode` builds it and runs
the vector file through it in Node with Go's `lib/wasm/wasm_exec_node.js`; CI's `wasm` job
runs it on Node 26.
