//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/Busnes-app/ky-primitives/xwing"
)

func init() {
	// xwingGenerate() -> {seed, publicKey, id}
	fns["xwingGenerate"] = func(args []js.Value) (any, error) {
		if _, err := bytesArgs(args, 0); err != nil {
			return nil, err
		}
		k, err := xwing.Generate()
		if err != nil {
			return nil, err
		}
		return map[string]any{"seed": u8(k.Seed()), "publicKey": u8(k.Public().Bytes()), "id": k.Public().ID()}, nil
	}
	// xwingSeal(publicKey, info, aad, msg) -> sealed
	fns["xwingSeal"] = func(args []js.Value) (any, error) {
		b, err := bytesArgs(args, 4)
		if err != nil {
			return nil, err
		}
		pub, err := xwing.ParsePublicKey(b[0])
		if err != nil {
			return nil, err
		}
		ct, err := xwing.Seal(pub, b[1], b[2], b[3])
		if err != nil {
			return nil, err
		}
		return u8(ct), nil
	}
	// xwingOpen(seed, info, aad, sealed) -> msg
	fns["xwingOpen"] = func(args []js.Value) (any, error) {
		b, err := bytesArgs(args, 4)
		if err != nil {
			return nil, err
		}
		k, err := xwing.FromSeed(b[0])
		if err != nil {
			return nil, err
		}
		msg, err := xwing.Open(k, b[1], b[2], b[3])
		if err != nil {
			return nil, err
		}
		return u8(msg), nil
	}
}
