//go:build go1.27

package capsule_test

import (
	"bytes"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

func testHybridSigner(t *testing.T) *hybridsig.PrivateKey {
	t.Helper()
	k, err := hybridsig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type rawContainer struct {
	Format            string          `json:"format"`
	Manifest          json.RawMessage `json:"manifest"`
	Ciphertext        string          `json:"ciphertext"`
	ManifestSignature string          `json:"manifest_signature,omitempty"`
}

func decodeContainer(t *testing.T, raw []byte) rawContainer {
	t.Helper()
	var c rawContainer
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal container: %v", err)
	}
	return c
}

func encodeContainer(t *testing.T, c rawContainer) []byte {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal container: %v", err)
	}
	return b
}

func flipByte(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 0x01
	return c
}

func sealSignedOne(t *testing.T, to recoverykey.PublicKey, signer *hybridsig.PrivateKey) ([]byte, capsule.Manifest) {
	t.Helper()
	raw, m, err := capsule.SealSigned("kysignon", "2.1.0",
		[]capsule.File{
			{Path: "config.json", Content: []byte(`{"ok":true}`), Mode: 0o600},
			{Path: "keys/signing.key", Content: []byte("secret-key-material"), Mode: 0o600},
		},
		map[string]any{"db": "sqlite"},
		map[string]any{"check": "healthz"},
		2, 3, to, signer)
	if err != nil {
		t.Fatal(err)
	}
	return raw, m
}

func TestSealSignedRoundTrip(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)

	raw, sealed, err := capsule.SealSigned("kysignon", "2.1.0",
		[]capsule.File{
			{Path: "config.json", Content: []byte(`{"ok":true}`), Mode: 0o600},
			{Path: "keys/signing.key", Content: []byte("secret-key-material"), Mode: 0o644},
		},
		map[string]any{"db": "sqlite"},
		map[string]any{"check": "healthz"},
		2, 3, rec.Public(), signer)
	if err != nil {
		t.Fatalf("SealSigned: %v", err)
	}

	if sealed.SignerKeyID != signer.Public().ID() {
		t.Fatalf("SignerKeyID = %q, want %q", sealed.SignerKeyID, signer.Public().ID())
	}
	if sealed.RecoveryKeyID != rec.Public().ID() {
		t.Fatalf("RecoveryKeyID = %q, want %q", sealed.RecoveryKeyID, rec.Public().ID())
	}

	// The returned Manifest re-marshals to the exact bytes embedded in the container,
	// and manifest_signature decodes to a full hybridsig signature.
	c := decodeContainer(t, raw)
	if c.Format != capsule.KycapFileFormat {
		t.Fatalf("format = %q, want %q", c.Format, capsule.KycapFileFormat)
	}
	gotManifestBytes, err := json.Marshal(sealed.UnverifiedManifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotManifestBytes, c.Manifest) {
		t.Fatalf("returned manifest bytes differ from container manifest:\n got: %s\nwant: %s", gotManifestBytes, c.Manifest)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(c.ManifestSignature)
	if err != nil {
		t.Fatalf("manifest_signature is not standard base64: %v", err)
	}
	if len(sigBytes) != hybridsig.SignatureBytes {
		t.Fatalf("signature length = %d, want %d", len(sigBytes), hybridsig.SignatureBytes)
	}

	// Keyless verification (as performed by a blind backup store like KyRecovery).
	vm, err := capsule.VerifyManifest(raw, signer.Public())
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	if vm.CapsuleID != sealed.CapsuleID || vm.ServiceName != "kysignon" || vm.AppVersion != "2.1.0" {
		t.Fatalf("verified manifest metadata mismatch: %+v", vm)
	}
	if vm.RecoveryKeyID != rec.Public().ID() || vm.SignerKeyID != signer.Public().ID() {
		t.Fatalf("verified manifest key IDs mismatch: %+v", vm)
	}
	if len(vm.Files) != 0 {
		t.Fatalf("keyless VerifyManifest returned %d file entries, want 0", len(vm.Files))
	}

	// Full verified open into a target directory.
	target := filepath.Join(t.TempDir(), "restore")
	opened, files, err := capsule.OpenSigned(raw, rec, signer.Public(), target)
	if err != nil {
		t.Fatalf("OpenSigned: %v", err)
	}
	if opened.CapsuleID != sealed.CapsuleID || opened.SignerKeyID != signer.Public().ID() {
		t.Fatalf("OpenSigned manifest mismatch: %+v", opened)
	}
	if len(files) != 2 || len(opened.Files) != 2 {
		t.Fatalf("OpenSigned returned %d files / %d entries, want 2", len(files), len(opened.Files))
	}
	onDisk, err := os.ReadFile(filepath.Join(target, "keys", "signing.key"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(onDisk) != "secret-key-material" {
		t.Fatalf("restored content = %q", onDisk)
	}

	// Backward compatibility: Open without a signer public key still opens signed capsules.
	compat, compatFiles, err := capsule.Open(raw, rec, "")
	if err != nil {
		t.Fatalf("Open on signed capsule: %v", err)
	}
	if compat.CapsuleID != sealed.CapsuleID || len(compatFiles) != 2 {
		t.Fatalf("Open returned unexpected result: %+v (%d files)", compat, len(compatFiles))
	}
}

func TestUnsignedCapsulesRemainBackwardCompatible(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)

	raw, sealed, err := capsule.Seal("kysignon", "2.1.0",
		[]capsule.File{{Path: "a.txt", Content: []byte("hello"), Mode: 0o600}},
		nil, nil, 2, 3, rec.Public())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Unsigned capsules omit both new optional JSON fields.
	if bytes.Contains(raw, []byte(`"manifest_signature"`)) {
		t.Fatal("unsigned capsule unexpectedly contains manifest_signature")
	}
	if bytes.Contains(raw, []byte(`"signer_key_id"`)) {
		t.Fatal("unsigned capsule unexpectedly contains signer_key_id")
	}
	if sealed.SignerKeyID != "" {
		t.Fatalf("unsigned capsule SignerKeyID = %q, want empty", sealed.SignerKeyID)
	}

	// Existing Open and ReadUnverifiedManifest keep working unchanged.
	if _, _, err := capsule.Open(raw, rec, ""); err != nil {
		t.Fatalf("Open unsigned: %v", err)
	}
	if _, err := capsule.ReadUnverifiedManifest(raw); err != nil {
		t.Fatalf("ReadUnverifiedManifest unsigned: %v", err)
	}

	// Callers requiring a signature reject unsigned capsules with ErrMissingSignature.
	if _, err := capsule.VerifyManifest(raw, signer.Public()); !errors.Is(err, capsule.ErrMissingSignature) {
		t.Fatalf("VerifyManifest on unsigned: got %v, want ErrMissingSignature", err)
	}
	target := filepath.Join(t.TempDir(), "restore")
	if _, _, err := capsule.OpenSigned(raw, rec, signer.Public(), target); !errors.Is(err, capsule.ErrMissingSignature) {
		t.Fatalf("OpenSigned on unsigned: got %v, want ErrMissingSignature", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("OpenSigned created target dir on unsigned capsule: %v", err)
	}

	// Committed unsigned golden fixtures also report ErrMissingSignature when verified.
	for _, p := range fixturePaths(t) {
		fixRaw, fixKey := loadFixture(t, p)
		if _, err := capsule.VerifyManifest(fixRaw, signer.Public()); !errors.Is(err, capsule.ErrMissingSignature) {
			t.Fatalf("%s VerifyManifest: got %v, want ErrMissingSignature", p, err)
		}
		if _, _, err := capsule.OpenSigned(fixRaw, fixKey, signer.Public(), ""); !errors.Is(err, capsule.ErrMissingSignature) {
			t.Fatalf("%s OpenSigned: got %v, want ErrMissingSignature", p, err)
		}
	}
}

func TestVerifyAndOpenSignedRejectTamperedManifest(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)
	raw, sealed := sealSignedOne(t, rec.Public(), signer)

	// Rewriting any field or even inserting insignificant whitespace changes the raw
	// manifest bytes that were signed.
	mutateField := func(field string, val any) []byte {
		return rewriteManifest(t, raw, field, val)
	}
	addWhitespace := func() []byte {
		out := bytes.Replace(raw, []byte(`"service_name":"`), []byte(`"service_name" : "`), 1)
		if bytes.Equal(out, raw) {
			t.Fatal("test setup: failed to insert whitespace into raw manifest")
		}
		return out
	}

	cases := map[string][]byte{
		"service_name":        mutateField("service_name", "kydrive"),
		"app_version":         mutateField("app_version", "9.9.9"),
		"capsule_id":          mutateField("capsule_id", "cap-forged-1"),
		"payload_hash":        mutateField("payload_hash", strings.Repeat("0", 64)),
		"threshold":           mutateField("threshold", 1),
		"total_shares":        mutateField("total_shares", 1),
		"recovery_key_id":     mutateField("recovery_key_id", testRecoveryKey(t).Public().ID()),
		"encapsulated_key":    mutateField("encapsulated_key", base64.StdEncoding.EncodeToString(make([]byte, recoverykey.EncapsulationBytes))),
		"signer_key_id":       sameLengthEdit(t, raw, sealed.SignerKeyID, testHybridSigner(t).Public().ID()),
		"verification_recipe": mutateField("verification_recipe", map[string]any{"check": "evil"}),
		"whitespace":          addWhitespace(),
	}

	for name, tampered := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := capsule.VerifyManifest(tampered, signer.Public()); !errors.Is(err, capsule.ErrInvalidSignature) || !errors.Is(err, hybridsig.ErrSignature) {
				t.Fatalf("VerifyManifest: got %v, want ErrInvalidSignature wrapping hybridsig.ErrSignature", err)
			}
			if _, _, err := capsule.OpenSigned(tampered, rec, signer.Public(), ""); !errors.Is(err, capsule.ErrInvalidSignature) || !errors.Is(err, hybridsig.ErrSignature) {
				t.Fatalf("OpenSigned: got %v, want ErrInvalidSignature wrapping hybridsig.ErrSignature", err)
			}
		})
	}
}

// Both halves of the hybrid signature (ML-DSA-65 and Ed25519) must verify. Tampering
// with either half independently, splicing halves across keys, altering the algorithm
// tag, truncating, or corrupting the base64 encoding must all be rejected.
func TestVerifyAndOpenSignedRejectTamperedSignatureHalves(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)
	other := testHybridSigner(t)

	raw, _ := sealSignedOne(t, rec.Public(), signer)
	c := decodeContainer(t, raw)

	sig, err := base64.StdEncoding.DecodeString(c.ManifestSignature)
	if err != nil {
		t.Fatal(err)
	}
	otherSig, err := other.Sign(capsule.ManifestSignatureLabel, c.Manifest)
	if err != nil {
		t.Fatal(err)
	}

	const tagLen = len(hybridsig.Alg) + 1
	const mlEnd = tagLen + mldsa.MLDSA65SignatureSize

	withSigBytes := func(b []byte) []byte {
		cp := c
		cp.ManifestSignature = base64.StdEncoding.EncodeToString(b)
		return encodeContainer(t, cp)
	}
	withSigString := func(s string) []byte {
		cp := c
		cp.ManifestSignature = s
		return encodeContainer(t, cp)
	}

	cases := []struct {
		name        string
		raw         []byte
		wantWrapped error
	}{
		{"ml-dsa first byte flipped", withSigBytes(flipByte(sig, tagLen)), hybridsig.ErrSignature},
		{"ml-dsa middle byte flipped", withSigBytes(flipByte(sig, tagLen+500)), hybridsig.ErrSignature},
		{"ml-dsa last byte flipped", withSigBytes(flipByte(sig, mlEnd-1)), hybridsig.ErrSignature},
		{"ed25519 first byte flipped", withSigBytes(flipByte(sig, mlEnd)), hybridsig.ErrSignature},
		{"ed25519 middle byte flipped", withSigBytes(flipByte(sig, mlEnd+32)), hybridsig.ErrSignature},
		{"ed25519 last byte flipped", withSigBytes(flipByte(sig, len(sig)-1)), hybridsig.ErrSignature},
		{"ml-dsa from another key", withSigBytes(append(bytes.Clone(otherSig[:mlEnd]), sig[mlEnd:]...)), hybridsig.ErrSignature},
		{"ed25519 from another key", withSigBytes(append(bytes.Clone(sig[:mlEnd]), otherSig[mlEnd:]...)), hybridsig.ErrSignature},
		{"wrong algorithm tag", withSigBytes(append([]byte("mldsa87+ed25519\x00"), sig[tagLen:]...)), hybridsig.ErrAlg},
		{"truncated signature", withSigBytes(sig[:len(sig)-1]), hybridsig.ErrSignature},
		{"extended signature", withSigBytes(append(bytes.Clone(sig), 0x00)), hybridsig.ErrSignature},
		{"raw-url base64", withSigString(base64.RawURLEncoding.EncodeToString(sig)), nil},
		{"malformed base64", withSigString("not-valid-base64!!!"), nil},
		{"embedded newline in base64", withSigString(c.ManifestSignature[:40] + "\n" + c.ManifestSignature[40:]), nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, op := range []struct {
				label string
				fn    func() error
			}{
				{"VerifyManifest", func() error { _, err := capsule.VerifyManifest(tc.raw, signer.Public()); return err }},
				{"OpenSigned", func() error { _, _, err := capsule.OpenSigned(tc.raw, rec, signer.Public(), ""); return err }},
			} {
				err := op.fn()
				if !errors.Is(err, capsule.ErrInvalidSignature) {
					t.Fatalf("%s: got %v, want ErrInvalidSignature", op.label, err)
				}
				if tc.wantWrapped != nil && !errors.Is(err, tc.wantWrapped) {
					t.Fatalf("%s: got %v, want wrapped %v", op.label, err, tc.wantWrapped)
				}
			}
		})
	}
}

func TestVerifyAndOpenSignedRejectWrongSignerKey(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)
	wrong := testHybridSigner(t)

	raw, _ := sealSignedOne(t, rec.Public(), signer)

	if _, err := capsule.VerifyManifest(raw, wrong.Public()); !errors.Is(err, capsule.ErrInvalidSignature) || !errors.Is(err, hybridsig.ErrSignature) {
		t.Fatalf("VerifyManifest with wrong key: got %v, want ErrInvalidSignature wrapping hybridsig.ErrSignature", err)
	}
	if _, _, err := capsule.OpenSigned(raw, rec, wrong.Public(), ""); !errors.Is(err, capsule.ErrInvalidSignature) || !errors.Is(err, hybridsig.ErrSignature) {
		t.Fatalf("OpenSigned with wrong key: got %v, want ErrInvalidSignature wrapping hybridsig.ErrSignature", err)
	}
}

func TestVerifyAndOpenSignedRejectWrongDomain(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)

	raw, _ := sealSignedOne(t, rec.Public(), signer)
	c := decodeContainer(t, raw)

	for _, wrongDomain := range []string{
		"kycap/3",
		"kycap/2/manifest",
		"kycap/3/manifestx",
		"kyguard/1/tx",
	} {
		t.Run(wrongDomain, func(t *testing.T) {
			wrongSig, err := signer.Sign(wrongDomain, c.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			// Sanity check: the signature is cryptographically valid under wrongDomain.
			if err := signer.Public().Verify(wrongDomain, c.Manifest, wrongSig); err != nil {
				t.Fatalf("test setup: wrong-domain signature did not self-verify: %v", err)
			}
			cp := c
			cp.ManifestSignature = base64.StdEncoding.EncodeToString(wrongSig)
			badRaw := encodeContainer(t, cp)

			if _, err := capsule.VerifyManifest(badRaw, signer.Public()); !errors.Is(err, capsule.ErrInvalidSignature) || !errors.Is(err, hybridsig.ErrSignature) {
				t.Fatalf("VerifyManifest: got %v, want ErrInvalidSignature wrapping hybridsig.ErrSignature", err)
			}
			if _, _, err := capsule.OpenSigned(badRaw, rec, signer.Public(), ""); !errors.Is(err, capsule.ErrInvalidSignature) || !errors.Is(err, hybridsig.ErrSignature) {
				t.Fatalf("OpenSigned: got %v, want ErrInvalidSignature wrapping hybridsig.ErrSignature", err)
			}
		})
	}
}

func TestVerifyAndOpenSignedRejectMismatchedSignerKeyID(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)
	claimed := testHybridSigner(t)

	// Take a signed capsule, rewrite signer_key_id to another key ID, then sign the
	// rewritten manifest bytes validly with signer. Even though signer's signature over
	// those bytes verifies cryptographically, VerifyManifest and OpenSigned must refuse
	// the mismatch between signer_key_id and the verifying key.
	raw, _ := sealSignedOne(t, rec.Public(), signer)
	rewritten := rewriteManifest(t, raw, "signer_key_id", claimed.Public().ID())
	c := decodeContainer(t, rewritten)
	sig, err := signer.Sign(capsule.ManifestSignatureLabel, c.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	c.ManifestSignature = base64.StdEncoding.EncodeToString(sig)
	badRaw := encodeContainer(t, c)

	if _, err := capsule.VerifyManifest(badRaw, signer.Public()); !errors.Is(err, capsule.ErrInvalidSignature) {
		t.Fatalf("VerifyManifest: got %v, want ErrInvalidSignature", err)
	}
	if _, _, err := capsule.OpenSigned(badRaw, rec, signer.Public(), ""); !errors.Is(err, capsule.ErrInvalidSignature) {
		t.Fatalf("OpenSigned: got %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyManifestAcceptsValidSignatureWhenSignerKeyIDOmitted(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)

	// Start with an unsigned capsule (which omits signer_key_id) and attach a valid
	// signature over its raw manifest bytes.
	raw, _, err := capsule.Seal("kysignon", "2.1.0",
		[]capsule.File{{Path: "a.txt", Content: []byte("ok"), Mode: 0o600}},
		nil, nil, 2, 3, rec.Public())
	if err != nil {
		t.Fatal(err)
	}
	c := decodeContainer(t, raw)
	sig, err := signer.Sign(capsule.ManifestSignatureLabel, c.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	c.ManifestSignature = base64.StdEncoding.EncodeToString(sig)
	signedRaw := encodeContainer(t, c)

	vm, err := capsule.VerifyManifest(signedRaw, signer.Public())
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	if vm.SignerKeyID != "" {
		t.Fatalf("SignerKeyID = %q, want empty", vm.SignerKeyID)
	}
	if _, _, err := capsule.OpenSigned(signedRaw, rec, signer.Public(), ""); err != nil {
		t.Fatalf("OpenSigned: %v", err)
	}
}

func TestOpenSignedVerifiesSignatureBeforeDecapsulationAndWritesNothing(t *testing.T) {
	rec := testRecoveryKey(t)
	wrongRec := testRecoveryKey(t)
	signer := testHybridSigner(t)

	raw, _ := sealSignedOne(t, rec.Public(), signer)
	c := decodeContainer(t, raw)
	sig, err := base64.StdEncoding.DecodeString(c.ManifestSignature)
	if err != nil {
		t.Fatal(err)
	}
	c.ManifestSignature = base64.StdEncoding.EncodeToString(flipByte(sig, len(sig)-1))
	badRaw := encodeContainer(t, c)

	target := filepath.Join(t.TempDir(), "restore")
	// Even with the wrong recovery key, OpenSigned fails on the invalid signature first,
	// before checking RecoveryKeyID or decapsulating.
	_, _, err = capsule.OpenSigned(badRaw, wrongRec, signer.Public(), target)
	if !errors.Is(err, capsule.ErrInvalidSignature) {
		t.Fatalf("got %v, want ErrInvalidSignature before ErrWrongRecoveryKey", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("failed OpenSigned created target directory: %v", err)
	}
}

func TestOpenSignedRejectsTamperedCiphertextEvenWithValidManifestSignature(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)

	raw, _ := sealSignedOne(t, rec.Public(), signer)
	c := decodeContainer(t, raw)
	ct, err := capsule.DecodeCiphertext(c.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	c.Ciphertext = capsule.EncodeCiphertext(flipByte(ct, len(ct)/2))
	tampered := encodeContainer(t, c)

	// Manifest bytes were not modified, so keyless VerifyManifest still verifies the manifest.
	if _, err := capsule.VerifyManifest(tampered, signer.Public()); err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	// OpenSigned decrypts and must fail at AEAD authentication, not silently open.
	_, _, err = capsule.OpenSigned(tampered, rec, signer.Public(), "")
	if err == nil {
		t.Fatal("OpenSigned accepted a capsule with tampered ciphertext")
	}
	if errors.Is(err, capsule.ErrInvalidSignature) {
		t.Fatalf("tampered ciphertext was misreported as ErrInvalidSignature: %v", err)
	}
}

func TestZeroAndNilHybridKeysAreErrors(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)
	raw, _ := sealSignedOne(t, rec.Public(), signer)
	files := []capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0o600}}

	for name, badSigner := range map[string]*hybridsig.PrivateKey{
		"nil signer":  nil,
		"zero signer": {},
	} {
		t.Run("SealSigned "+name, func(t *testing.T) {
			if _, _, err := capsule.SealSigned("t", "1", files, nil, nil, 2, 3, rec.Public(), badSigner); !errors.Is(err, hybridsig.ErrUninitializedKey) {
				t.Fatalf("got %v, want hybridsig.ErrUninitializedKey", err)
			}
		})
	}

	for name, badPub := range map[string]*hybridsig.PublicKey{
		"nil pub":  nil,
		"zero pub": {},
	} {
		t.Run("VerifyManifest "+name, func(t *testing.T) {
			if _, err := capsule.VerifyManifest(raw, badPub); !errors.Is(err, hybridsig.ErrUninitializedKey) {
				t.Fatalf("got %v, want hybridsig.ErrUninitializedKey", err)
			}
		})
		t.Run("OpenSigned "+name, func(t *testing.T) {
			if _, _, err := capsule.OpenSigned(raw, rec, badPub, ""); !errors.Is(err, hybridsig.ErrUninitializedKey) {
				t.Fatalf("got %v, want hybridsig.ErrUninitializedKey", err)
			}
		})
	}

	// Valid signer key + zero recovery private key still reports recoverykey.ErrUninitializedKey.
	if _, _, err := capsule.OpenSigned(raw, recoverykey.PrivateKey{}, signer.Public(), ""); !errors.Is(err, recoverykey.ErrUninitializedKey) {
		t.Fatalf("OpenSigned with zero recovery key: got %v, want recoverykey.ErrUninitializedKey", err)
	}
}

func TestOversizedManifestSignatureAndNullManifestAreRejected(t *testing.T) {
	rec := testRecoveryKey(t)
	signer := testHybridSigner(t)

	raw, _ := sealSignedOne(t, rec.Public(), signer)
	c := decodeContainer(t, raw)
	c.ManifestSignature = strings.Repeat("A", 9<<10)
	oversized := encodeContainer(t, c)

	if _, err := capsule.ReadUnverifiedManifest(oversized); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("ReadUnverifiedManifest oversized sig: got %v, want ErrCorruptCapsule", err)
	}
	if _, _, err := capsule.Open(oversized, rec, ""); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("Open oversized sig: got %v, want ErrCorruptCapsule", err)
	}
	if _, err := capsule.VerifyManifest(oversized, signer.Public()); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("VerifyManifest oversized sig: got %v, want ErrCorruptCapsule", err)
	}
	if _, _, err := capsule.OpenSigned(oversized, rec, signer.Public(), ""); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("OpenSigned oversized sig: got %v, want ErrCorruptCapsule", err)
	}

	nullManifest := []byte(`{"format":"kycap/3","manifest":null,"ciphertext":"AAAA"}`)
	if _, err := capsule.ReadUnverifiedManifest(nullManifest); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("ReadUnverifiedManifest null manifest: got %v, want ErrCorruptCapsule", err)
	}
	if _, _, err := capsule.Open(nullManifest, rec, ""); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("Open null manifest: got %v, want ErrCorruptCapsule", err)
	}
	if _, err := capsule.VerifyManifest(nullManifest, signer.Public()); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("VerifyManifest null manifest: got %v, want ErrCorruptCapsule", err)
	}
	if _, _, err := capsule.OpenSigned(nullManifest, rec, signer.Public(), ""); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("OpenSigned null manifest: got %v, want ErrCorruptCapsule", err)
	}
}
