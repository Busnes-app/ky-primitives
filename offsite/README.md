# offsite

`offsite` copies opaque objects to one of four target types behind the same
interface:

```go
type Target interface {
	Put(context.Context, string, io.Reader, int64) error
	Get(context.Context, string) (io.ReadCloser, error)
	Test(context.Context) error
}
```

Products keep target records, seal credentials, schedule work, and write audit
or sync logs themselves.

## Targets

| URL | Credential fields | Notes |
|---|---|---|
| `s3://bucket/prefix` | `AccessKey`, `Secret` | AWS by default; set `S3Endpoint` for R2 or MinIO and `S3Region` when needed. |
| `sftp://user@host:22/dir` | `Secret`, `HostKey` | The path is relative to the SFTP account root. `AccessKey` may supply the user instead. |
| `smb://host/share/dir` | `AccessKey`, `Secret` | `AccessKey` may be `DOMAIN\user`; SMB1 is never negotiated. |
| `file:///absolute/path` | none | Writes owner-only files by temporary file and rename. |

Passwords in URLs are rejected. SMB rejects all userinfo because endpoints are
commonly logged. SFTP never connects successfully without a pinned SHA256 host
fingerprint. Calling `Test` without a pin returns `UnknownHostKeyError` carrying
the fingerprint the operator must verify out of band.

SFTP explicitly uses `ssh.SupportedAlgorithms()` for key exchange, ciphers, MACs
and host signatures. SHA-1 key exchange/signatures, DSA and truncated HMAC-SHA1-96
are refused, without a legacy-algorithm fallback. RSA host, certificate-authority
and configured client keys must be at least 2048 bits; supported EC keys must be
at least 224 bits, and Ed25519 uses its fixed size. Certificate signatures and RSA
client authentication use supported non-SHA-1 algorithms too. A matching host pin
does not exempt an undersized key. Replace old server/client keys or update an
old SSH server before upgrading; compare the new host fingerprint out of band
and update the pin explicitly. Existing pins and credential records are not
rewritten automatically.

Object names are relative slash-separated paths. Absolute paths, backslashes,
empty components, `.` and `..` are rejected for every target. `Get` returns an
error matching `os.ErrNotExist` only when the object is absent. Callers must
close a successful `Get`; for network targets that also closes the session.
Local targets resolve every operation through `os.Root`, so a symlink beneath
the configured directory cannot escape it. SFTP and SMB reserve random
`.ky-offsite-tmp-*` names for staging; callers cannot address that namespace.

SMB cannot safely replace an existing path because `go-smb2` does not expose
replace-on-rename. Its `Put` returns `ErrObjectExists` instead of deleting the
previous replica. Use immutable object names, as capsule and content-addressed
blob IDs do.

SMB object-name components are limited to lowercase ASCII letters, digits,
dot, underscore, and hyphen. Trailing dots, Windows device names, and `~` are
also rejected. This canonical grammar prevents case folding, NTFS alternate
streams, trailing-dot/space handling, and short-name rules from making two
admitted logical names address the same SMB object.

`Test` writes `.ky-offsite-ping`. Local, SFTP, and SMB remove it; S3 overwrites
the same probe object on later tests.

## SMB limitation

The client requires message signing and `go-smb2` supports only SMB 2 and 3.
However, `go-smb2` can accept an unsigned guest session granted by the server.
An impersonating server could swallow uploads while observing the NTLMv2
exchange. Use SMB only on a trusted network and verify replicas independently.
A share mounted by the host and addressed with `file://` avoids this library
limitation.

SMB is an explicitly selected compatibility destination, using NTLMv2 password
authentication. Its protocol mechanisms include MD4/MD5-derived authentication
values and RC4 session-key exchange; message signing does not remove those
limitations. For a strong-cryptography deployment, choose pinned SFTP or HTTPS
S3 instead of this SMB transport (and keep S3's HTTP endpoint override disabled).
Where compatibility requires SMB, use a trusted isolated network, a dedicated
long random password, and verify replica contents independently. Keep capsule
payloads sealed; this client never makes plaintext backups confidential by itself.

## Release

This nested module uses namespaced repository tags such as `offsite/v0.1.0`:

```sh
go get github.com/Busnes-app/ky-primitives/offsite@v0.1.0
```
