# AGENTS.md

## Cursor Cloud specific instructions

`go-libp2p` is a Go library (module `github.com/libp2p/go-libp2p`), not a deployable
service. There is no web server, database, or long-running application to start. The
Go version is pinned by the `go` directive in `go.mod` (currently Go 1.25.x); the Go
toolchain auto-downloads the pinned version on first use.

This repo contains multiple independent Go modules. The most relevant ones for
development are the root module (`/`) and `examples/` (each has its own `go.mod`).
Other modules (`test-plans/`, `examples/pubsub/chat/`, `examples/ipfs-camp-2019/`,
`examples/pubsub/basic-chat-with-rendezvous/`, `scripts/test_analysis/`) are only
needed for their specific niche use cases.

### Build / lint / test

- Build: `go build ./...` (run separately inside `examples/` for that module).
- Lint: `golangci-lint run ./...`. The config (`.golangci.yml`) uses the v2 schema,
  so golangci-lint **v2** is required (v1 will not parse the config). It is installed
  to `$(go env GOPATH)/bin`, which is on `PATH`.
- Test: `go test ./...`. The full suite is large and spins up in-memory hosts +
  loopback connections, so **no external services (DB/Redis/Docker) are required**
  for core/package tests. Some transport tests bind to loopback TCP/UDP ports. For a
  quick sanity check use a subset, e.g. `go test ./core/... .`.
  Note: a handful of tests are known to be flaky upstream (see the FlakyTests badge
  in `README.md`); a single flaky failure is not necessarily a regression.

### Running the "application" (examples)

The runnable programs live in `examples/`. They are standalone `go run` / `go build`
tutorials (echo, chat, pubsub, relay, http-proxy, etc.). To demo end to end, e.g. the
echo example (from `examples/echo/`):

```
go build -o /tmp/echo .
/tmp/echo -l 10000                 # listener; prints its /ip4/.../p2p/<id> multiaddr
/tmp/echo -l 10001 -d <multiaddr>  # dialer; sends "Hello, world!" and reads the echo
```

### Optional tooling (not needed for normal dev)

- `test-plans/` transport interop tests require Redis (`redis_addr=localhost:6379`)
  and Docker; see `test-plans/README.md`.
- `dashboards/` Grafana/Prometheus stack is optional observability; see
  `dashboards/`.
- Regenerating protobufs uses `scripts/gen-proto.sh` (auto-downloads `protoc`); not
  needed to build/test the checked-in code.

### Pre-commit hook

`.githooks/pre-commit` runs `go mod tidy` inside `test-plans/` and fails if
`go.mod`/`go.sum` there change. Only relevant if you edit `test-plans/` dependencies.
