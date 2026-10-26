# Verifying releases

[Overview](../README.md) · [Release notes](../CHANGELOG.md) · [Assurance case](ASSURANCE-CASE.md) · [Contributing](../CONTRIBUTING.md)

ky-primitives is a Go library. A release is a git tag, and nothing else is published: there
are no GitHub Releases, no binaries and no container images.

| Module | Tag | Example |
|---|---|---|
| `github.com/Busnes-app/ky-primitives` | `vX.Y.Z` | `v0.10.0` |
| `github.com/Busnes-app/ky-primitives/offsite` | `offsite/vX.Y.Z` | `offsite/v0.2.2` |

`cmd/kyauditverify` is not shipped as a binary. `go install
github.com/Busnes-app/ky-primitives/cmd/kyauditverify@vX.Y.Z` builds it from the same
verified module source as a library import.

## What protects a release

- **The Go checksum database** (`sum.golang.org`). The first time anyone fetches a version,
  its hash goes into a public, append-only log. From then on every `go` command checks the
  hash it downloads against that log and refuses a mismatch. If a tag were moved or the module
  proxy served different bytes, every consumer would get an error instead of the new code.
- **Your `go.sum`.** Once a version is in `go.sum`, the `go` command refuses any other bytes
  for it, whatever the proxy or the log says.

Tags are **not** GPG-signed. Every tag except `v0.2.0` and `v0.3.0` points at a pull-request
merge commit, which GitHub signs (the commit API reports `verified: true` for each). The
checksum database is what makes a version immutable, not a signature on the tag.

This protection is lost if you turn it off. Do not list this module in `GONOSUMDB` or
`GOPRIVATE`, and do not set `GOSUMDB=off`.

## Check what you already have

In a module that depends on this library:

```bash
go mod verify
```

It prints `all modules verified` when the module cache still matches `go.sum`. Any other
output means a cached file was changed after download; delete the module cache and download
again.

## Check a release against this repository

This command does not trust the module proxy. It hashes the tag straight from GitHub, looks
the version up in the checksum database, and requires the two to match. Name the tag
yourself. You need `go`, `git`, `curl` and `jq`.

```bash
tag=<release tag, e.g. v0.10.0 or offsite/v0.2.2>
case $tag in offsite/*) m=github.com/Busnes-app/ky-primitives/offsite ;; *) m=github.com/Busnes-app/ky-primitives ;; esac
v=${tag##*/}
tmp=$(mktemp -d)
from_git=$(GOFLAGS=-modcacherw GOPROXY=direct GONOSUMDB=$m GOMODCACHE=$tmp go mod download -json "$m@$v" | jq -er .Sum) \
  && in_log=$(curl -fsS "https://sum.golang.org/lookup/github.com/!busnes-app/${m#github.com/Busnes-app/}@$v" | awk -v m="$m" -v v="$v" '$1==m && $2==v {print $3}') \
  && commit=$(git ls-remote https://github.com/Busnes-app/ky-primitives.git "refs/tags/$tag" "refs/tags/$tag^{}" | tail -1 | cut -f1) \
  && echo "from git: $from_git" && echo "in log:   $in_log" \
  && [ -n "$from_git" ] && [ "$from_git" = "$in_log" ] \
  && echo "OK: $m@$v is commit $commit, and the checksum database holds the same hash"
rm -rf "$tmp"
```

`GONOSUMDB` here only stops this one download from checking the log, because the point is to
compute the hash independently and compare it with the log yourself. The temporary
`GOMODCACHE` makes Go fetch from git instead of reusing a cached copy.

If the command prints no `OK:` line, do not use that version. The commit it prints is the one
the tag points at today; compare it with the commit you reviewed.

Run against `v0.9.0`, `v0.10.0` and `offsite/v0.2.2` on 2026-10-23, it printed `OK:` for each:
`v0.10.0` is commit `5fe62dbb…` with hash `h1:CMgfkyGErsNHMLq6BYH+S6fW6fXEJX/Ukdk4rN4bK/o=`, and
`offsite/v0.2.2` is commit `ae8888d0…` with hash `h1:pUeAs7ah8cHGzGqH/2kXWWZO4mpKDmGUUwjXwn0TliI=`.
A tag that does not exist printed no `OK:` line.

## Rebuilding

There is no binary to compare. A consumer compiles this library as part of its own build, so
reproducing a consumer's binary is that consumer's job. The module source is what you verify,
and the command above does that.
