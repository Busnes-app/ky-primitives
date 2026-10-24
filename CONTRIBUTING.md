# Contributing

[Overview](README.md) · [Assurance case](docs/ASSURANCE-CASE.md) · [Verifying releases](docs/VERIFYING-RELEASES.md)

## How changes land

- Open a pull request against `master`. Every change goes through one; `master` is protected.
- CI (`.github/workflows/ci.yml`) must be green. It builds, vets and race-tests both modules on
  Linux and macOS with Go 1.26 and the latest stable Go, and runs `govulncheck` on both. The
  branch ruleset requires the `test` and `vulncheck` jobs; the `offsite` job is not required
  by the ruleset, so check it yourself before merging an `offsite/` change.
- Report bugs and propose features in [GitHub issues](https://github.com/Busnes-app/ky-primitives/issues).
  Report vulnerabilities privately, as the organisation's
  [security policy](https://github.com/Busnes-app/.github/blob/main/SECURITY.md) explains.
- A change that may break a consumer: see [README, Contributing](README.md#contributing) for the
  consumer compatibility workflows and how to run them before merging.

## Tests

A change in behaviour comes with a test that fails without it. For a security property, the
README names the test that pins it; keep that list current. The package rules in
[AGENTS.md](AGENTS.md) say which tests a change to `oidcverify` or the dependency budget must
keep passing.

Run what CI runs:

```bash
go build ./... && go vet ./... && go test -race -count=1 ./...
(cd offsite && test -z "$(gofmt -l .)" && go build ./... && go vet ./... && go test -race -count=1 ./...)
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

## Coding standard

Contributions follow these style guides. CI enforces the parts a tool can check.

| Language | Style guide | Enforced by |
|---|---|---|
| Go | [Effective Go](https://go.dev/doc/effective_go) and the [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments) | `go vet ./...` in the `test` job (root module) and the `offsite` job; `gofmt -l` must print nothing in the `offsite` job |

The root module's formatting is not checked by CI. Run `gofmt -l .` before you push; it prints
nothing on `master` today.

Beyond what the tools check: the root module stays inside its dependency budget
(`nodeps_test.go`), packages other than `password` use only the standard library, and comments
explain why a check exists, as the existing code does.
