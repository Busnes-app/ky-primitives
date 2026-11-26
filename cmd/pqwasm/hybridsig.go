//go:build js && wasm && go1.27

package main

import (
	"syscall/js"

	"github.com/Busnes-app/ky-primitives/hybridsig"
)

// labelArgs splits (bytes..., label string, bytes...) calls: the argument at i must be a string.
func labelArgs(args []js.Value, n, i int) ([][]byte, string, error) {
	if len(args) != n || args[i].Type() != js.TypeString {
		return nil, "", errArgs
	}
	label := args[i].String()
	b, err := bytesArgs(append(append([]js.Value{}, args[:i]...), args[i+1:]...), n-1)
	return b, label, err
}

func init() {
	// hybridsigGenerate() -> {mldsaSeed, ed25519Seed, publicKey, id}
	fns["hybridsigGenerate"] = func(args []js.Value) (any, error) {
		if _, err := bytesArgs(args, 0); err != nil {
			return nil, err
		}
		k, err := hybridsig.Generate()
		if err != nil {
			return nil, err
		}
		ms, es := k.Seeds()
		return map[string]any{"mldsaSeed": u8(ms), "ed25519Seed": u8(es), "publicKey": u8(k.Public().Bytes()), "id": k.Public().ID()}, nil
	}
	// hybridsigSign(mldsaSeed, ed25519Seed, label, msg) -> sig
	fns["hybridsigSign"] = func(args []js.Value) (any, error) {
		b, label, err := labelArgs(args, 4, 2)
		if err != nil {
			return nil, err
		}
		k, err := hybridsig.FromSeeds(b[0], b[1])
		if err != nil {
			return nil, err
		}
		sig, err := k.Sign(label, b[2])
		if err != nil {
			return nil, err
		}
		return u8(sig), nil
	}
	// hybridsigVerify(publicKey, label, msg, sig) -> true, or {error}
	fns["hybridsigVerify"] = func(args []js.Value) (any, error) {
		b, label, err := labelArgs(args, 4, 1)
		if err != nil {
			return nil, err
		}
		p, err := hybridsig.ParsePublicKey(b[0])
		if err != nil {
			return nil, err
		}
		if err := p.Verify(label, b[1], b[2]); err != nil {
			return nil, err
		}
		return true, nil
	}
}
