# AGENTS.md

This file provides guidance to coding agents (e.g. Claude Code, claude.ai/code) when working with code in this repository.

## Repository purpose

Go module `go.bytebuilders.dev/cloudflare-dns-proxy` — an HTTP proxy that fronts the Cloudflare DNS API and centralizes credential storage so downstream consumers (cert-manager `cert-manager-webhook-ace`, external-dns operators, etc.) don't each need a Cloudflare API token. Authenticates clients and performs the Cloudflare API call on their behalf.

The produced binary is `cloudflare-dns-proxy`.

## Architecture

- `cmd/cloudflare-dns-proxy/` — entry point.
- `pkg/cmds/`:
  - `root.go` — Cobra root.
  - `run.go` — `run` subcommand that starts the HTTP server.
- `Dockerfile.in` (PROD, distroless), `Dockerfile.dbg` (debian), `Dockerfile.ubi` (Red Hat certified).
- `hack/`, `Makefile` — AppsCode build harness.
- `vendor/` — checked-in deps.

## Common commands

- `make ci` — full CI pipeline.
- `make build` / `make all-build` — host or all-platform build.
- `make fmt`, `make lint`, `make unit-tests` / `make test` — standard.
- `make verify` — codegen + module-tidy verification.
- `make container` / `make push` / `make release` — image build/publish flow.

## Conventions

- Module path is `go.bytebuilders.dev/cloudflare-dns-proxy` (vanity URL); imports must use that.
- License: `LICENSE`. Sign off commits (`git commit -s`).
- Vendor directory is checked in; keep `go mod tidy && go mod vendor` clean.
- Cloudflare API tokens live **only** in the proxy's environment / mounted secrets — never relay them to clients. Clients authenticate with their own credentials and the proxy mediates.
- Consumers depend on the proxy's HTTP surface (used by `cert-manager-webhook-ace` and similar) — keep that contract stable.
- Three Dockerfiles, one binary — keep `Dockerfile.in`, `Dockerfile.dbg`, and `Dockerfile.ubi` in sync.
