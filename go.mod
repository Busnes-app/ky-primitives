module github.com/Busnes-app/ky-primitives

go 1.26.6

require golang.org/x/crypto v0.57.0

require golang.org/x/sys v0.48.0 // indirect

retract v0.2.0 // Publishes per-member paths, sizes and SHA-256 digests in the plaintext manifest; use v0.3.0.
