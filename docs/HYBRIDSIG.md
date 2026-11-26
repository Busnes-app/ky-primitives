# Hybrid signatures

[Overview](../README.md) · [Assurance case](ASSURANCE-CASE.md) · [Contributing](../CONTRIBUTING.md) · [Strong cryptography](STRONG-CRYPTO.md)

## hybridsig

Signs with ML-DSA-65 and Ed25519 together. A signature verifies only if both halves do,
so it holds while either algorithm holds. It is the shared signer for Ky-internal objects
(spec B wave W2: master and device keys, pinned identities, signed statements). It needs
Go 1.27 for `crypto/mldsa`; on Go 1.26 the package builds to nothing.

```go
priv, err := hybridsig.Generate()            // keep priv.Seeds() (2 × 32 bytes) secret
pub := priv.Public()                         // publish pub.Bytes() (2000 bytes); name it by pub.ID()

sig, err := priv.Sign("kymessages/device-cross-sign/1", msg)
err = pub.Verify("kymessages/device-cross-sign/1", msg, sig)
```

**Construction.** Lifted from kyguard-server's `internal/pqcrypto/sig.go` (@ `37b302b`) and
kept as it is. Both halves sign the same digest `D = SHA-256(label ‖ 0x00 ‖ msg)`:
ML-DSA-65 (FIPS 204, hedged, empty context) and pure Ed25519. `Verify` always checks both
and returns one `ErrSignature` if either fails. The label names the caller and purpose;
an empty label, or one containing 0x00 (which could shift bytes between label and
message), is refused with `ErrLabel`. kyguard's digest is this one with the label
`kyguard/1/<type>` and the JCS bytes as `msg`, so kyguard can import this package without
changing a signature; `TestKyguardConstructionVerifies` checks that.

**Encodings.** Each starts with the algorithm tag `mldsa65+ed25519` and a 0x00:

| Value | Bytes |
|---|---|
| Public key | tag ‖ ML-DSA-65 public key (1952) ‖ Ed25519 public key (32) = 2000 |
| Signature | tag ‖ ML-DSA-65 signature (3309) ‖ Ed25519 signature (64) = 3389 |
| Key ID | `mldsa65+ed25519:` ‖ hex SHA-256(`"ky/hybridsig/1/key-id"` ‖ 0x00 ‖ public key) |
| Private key | two 32-byte seeds, ML-DSA-65 and Ed25519 (`Seeds`, `FromSeeds`) |

A key or signature with any other tag fails as `ErrAlg`; there is no negotiation.

**Not a standard format.** This is a Ky-internal encoding. It is not the RFC 10073 X.509
composite signature and not the draft JOSE composite: neither reads it and it reads
neither. Where a standard must interoperate (X.509, JWS), use ML-DSA-65 in that standard's
own format instead.

**Vectors.** `hybridsig/testdata/vectors.json` holds fixed seeds, the public key and ID,
valid signatures, and refusals (either half flipped, other label or message, other tag,
truncation, empty label) with the error each must give. They are made by the production
`Sign` with Go's `testing/cryptotest.SetGlobalRandom` fixing ML-DSA's hedging randomness
(`go test ./hybridsig -run TestVectors -update`; the same Go version rewrites the same
bytes). Readers check that every valid case verifies and every invalid case is refused.

**Browsers.** `cmd/pqwasm` exports `hybridsigGenerate`, `hybridsigSign` and
`hybridsigVerify` (byte arguments as `Uint8Array`, labels as strings) when built with
`GOOS=js GOARCH=wasm`. `TestWASMUnderNode` runs the vector file through it in Node with
Go's `lib/wasm/wasm_exec_node.js`; CI's `wasm` job runs it on Node 26.
