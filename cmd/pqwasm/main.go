//go:build js && wasm

// Command pqwasm is ky-primitives' post-quantum helpers built for GOOS=js GOARCH=wasm, so a
// browser runs the same code and passes the same vectors as the servers. Load it with Go's
// lib/wasm/wasm_exec.js; it sets globalThis.pqwasm. Byte arguments and results are
// Uint8Array, labels are strings. A failed call returns {error: "..."} instead of throwing.
// pqwasm.exit() stops the Go program.
package main

import (
	"errors"
	"sync"
	"syscall/js"
)

// fns holds the exported functions; each helper's file adds its own in init.
var fns = map[string]func(args []js.Value) (any, error){}

func main() {
	obj := js.Global().Get("Object").New()
	for name, f := range fns {
		obj.Set(name, js.FuncOf(func(_ js.Value, args []js.Value) any {
			v, err := f(args)
			if err != nil {
				return map[string]any{"error": err.Error()}
			}
			return v
		}))
	}
	done := make(chan struct{})
	var once sync.Once
	obj.Set("exit", js.FuncOf(func(js.Value, []js.Value) any {
		once.Do(func() { close(done) })
		return nil
	}))
	js.Global().Set("pqwasm", obj)
	<-done
}

var errArgs = errors.New("pqwasm: wrong number or type of arguments")

// bytesArgs copies every argument out of a Uint8Array, refusing anything else.
func bytesArgs(args []js.Value, n int) ([][]byte, error) {
	if len(args) != n {
		return nil, errArgs
	}
	u8 := js.Global().Get("Uint8Array")
	out := make([][]byte, n)
	for i, a := range args {
		if !a.InstanceOf(u8) {
			return nil, errArgs
		}
		out[i] = make([]byte, a.Length())
		js.CopyBytesToGo(out[i], a)
	}
	return out, nil
}

// u8 copies b into a new Uint8Array.
func u8(b []byte) js.Value {
	v := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(v, b)
	return v
}
