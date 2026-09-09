# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0]

Adds **key domains**: a named set of age recipients plus the private keys
the server holds for them. One server process can now serve several
independent recipient sets, and — the reason this is a minor rather than a
patch — mutations no longer silently change who can read a file.

Existing single-recipient deployments need no configuration change. The
v1 environment variables become a domain called `default`.

### Fixed

- **Re-encryption no longer drops recipients.** Every mutation decrypts,
  changes and re-encrypts; re-encryption used the server's configured
  recipients, so a file encrypted to two parties handled by a server that
  knew about one came back readable by one, with no error. Mutations now
  compare the file's actual recipients against the resolved domain and
  refuse on any difference, pointing at `sops_rekey`.
- **Private keys no longer leak between key sets.** sops inherited
  `SOPS_AGE_KEY` from the server process and fell back to
  `~/.config/sops/age/keys.txt`. Each invocation now gets an environment
  carrying only the keys of the domain for that call, with every other age
  key variable stripped and `HOME` / `XDG_CONFIG_HOME` pointed at an empty
  directory.

### Added

- `SOPS_MCP_DOMAINS_FILE` — YAML defining named domains, each with
  `recipients` and optional `keys` / `key_file`. A domain with no keys can
  encrypt but never decrypt. Files holding key material must be mode 0600
  and owned by the server's user.
- `SOPS_MCP_REQUIRE_DOMAIN` — require every call to name its domain
  instead of falling back to `default`.
- `sops_list_domains` — report configured domains, their recipients, and
  whether each can decrypt. Never returns private key material.
- `sops_rekey` — re-encrypt a file onto its domain's current recipient
  list. This is the `sops updatekeys` workflow, and the way to clear the
  new mismatch refusal. Requires an explicit `domain`; it cannot move a
  file between domains.
- Every other tool takes an optional `domain` argument.
- `_meta_unencrypted.domain` records which domain a file belongs to. It is
  a hint for resolution, not an authority — the recipient check is what
  makes trusting it safe. Files without it resolve to `default`.
- `sops_list_secrets` reports the domain, recipient count, and any
  mismatch, still without needing a private key.
- Startup validates every recipient and private key, and rejects a domain
  whose private key does not belong to it.
- `docs/design/domains.md` — design, threat model, and the deferred phase 2
  (binding SSE bearer tokens to domains for real tenant isolation).

### Changed

- **Behaviour change.** A file whose recipients do not match the resolved
  domain is now refused rather than silently re-encrypted. This is the bug
  fix above; the only way to hit it is a configuration that was already
  losing recipients. Run `sops_rekey` to reconcile.
- `cryptography` is now a direct dependency (it was already present
  transitively via `mcp`). It is used to derive an age recipient from an
  identity during startup validation.
- `SopsEncryptor(age_public_key, sops_binary)` is now
  `SopsEncryptor(sops_binary)`, with `encrypt` / `decrypt` taking a
  `Domain`. `SopsMcpServer` takes a domain mapping.

### Security

- Domains separate key sets, not callers. On the SSE transport one API
  token still reaches every domain the server holds; two mutually
  distrusting parties need separate processes. Documented in SECURITY.md.
- Corrected a prior audit note: SOPS's MAC *does* cover unencrypted
  values, so a tampered `_meta_unencrypted` block fails to decrypt. Pinned
  by a test so `--mac-only-encrypted` cannot be introduced silently. Paths
  that read metadata without decrypting remain unverified, which is why
  recipients are checked independently.

## [0.10.1]

Dependency / security maintenance release. Regenerates `requirements.lock.txt`
to move every transitive dependency flagged by Dependabot onto a patched
release, clearing all 17 open alerts. No changes to the tool surface, the
metadata schema, or the "no plaintext crosses the MCP boundary" property.

Most of the flagged code was never on a path sops-mcp executes — the alerts
came from `mcp`'s hard requirement on its HTTP-server + `pyjwt[crypto]` auth
stack, while sops-mcp uses stdio plus a thin SSE transport with a static
bearer-token compare (no JWT verification, no multipart form parsing). The
bump removes the noise regardless.

### Security

- **Upgraded locked dependencies to patched versions** (via `pip-compile
  --upgrade`): `starlette` 0.52.1 → 1.3.1, `pyjwt` 2.12.1 → 2.13.0,
  `python-multipart` 0.0.27 → 0.0.32, `cryptography` 46.0.7 → 49.0.0,
  `pydantic-settings` 2.13.1 → 2.14.2, `idna` 3.11 → 3.18. Also pulls
  `mcp` 1.27 → 1.28 plus `uvicorn`, `sse-starlette`, and `anyio`. Full
  test suite (incl. transport-security) green and the supply-chain lock
  gate verifies under the upgraded stack.

## [0.10.0]

Supply-chain hardening release. Migrates the published Docker image to a
Chainguard / Wolfi Python base for a signed origin and a distroless
runtime. Python 3.13 minimum runtime in the published image; the library
itself still supports 3.11+. No changes to the tool surface or to the
"no plaintext crosses the MCP boundary" property.

### Changed

- **Base image switched to `cgr.dev/chainguard/python`** (Wolfi). The
  build stage uses `:latest-dev` (with apk + shell + build toolchain);
  the runtime stage uses `:latest` (distroless: no shell, no apk, no
  package manager). Both are digest-pinned in `base-images.lock.json`
  and cosign-verified by the supply-chain workflow. Wins: signed origin
  via Chainguard's release identity, smaller surface, glibc-based (so
  no Alpine/musl gotchas).
- **Container runs as Chainguard's built-in `nonroot` user (uid 65532)**
  instead of a custom uid 10001. No bind mounts in the supported
  deployment, so this is documentation-only for most users; deployments
  that mount host directories into the container will need to chown.
- **`sops` and `age` binaries now come from Wolfi's apk repo** (signed
  by Chainguard) rather than separately curl-downloaded with pinned
  checksums. They are pinned transitively by the digest of the build
  base image — re-pinning the base also re-pins these binaries.
- **Published image runtime is Python 3.13.** The library's
  `requires-python` is unchanged (`>=3.11`); only the Docker runtime
  bumped. CI matrix expanded to test 3.11, 3.12, and 3.13.
- **CMD → ENTRYPOINT.** The container now uses an ENTRYPOINT pointing
  at the venv-installed console script for clearer container semantics.

### Added

- **`cgr.dev` registry support in `lib/pin_base_images.py`** so the
  digest-pin/cosign-verify pipeline works for Chainguard images.

## [0.9.1]

Security hardening release. Fixes two transitive CVEs and tightens defaults
for the SSE-over-HTTP transport. No changes to the core tool surface or to
the "no plaintext crosses the MCP boundary" property.

### Security

- **Upgrade `mcp` to >=1.23.0** (GHSA — DNS rebinding protection not enabled
  by default in earlier versions of the MCP Python SDK). The low-level
  `SseServerTransport` in this server is now constructed with explicit
  `TransportSecuritySettings` that validate the `Host` header on every
  request.
- **Upgrade `python-multipart` to >=0.0.26** (GHSA — DoS via inefficient
  parsing of crafted multipart preamble/epilogue data).
- **Refuse to bind SSE transport to `0.0.0.0` without `SOPS_MCP_API_TOKEN`.**
  The server now raises `RuntimeError` at startup rather than silently
  exposing an unauthenticated interface on all network interfaces.
- **Flip `SOPS_MCP_HOST` default from `0.0.0.0` to `127.0.0.1`** for the
  direct `python -m sops_mcp` entrypoint. The published container still
  binds `0.0.0.0` (because that's what makes a container reachable), which
  combined with the above refusal means containerized deployments must now
  set `SOPS_MCP_API_TOKEN`.
- **Non-root Dockerfile.** The container runs as a dedicated UID (10001)
  instead of root. Shrinks the blast radius of any remote-code-execution
  class bug inside the server.

### Added

- `SOPS_MCP_ALLOWED_HOSTS` env var (comma-separated) to configure the
  `Host`-header allowlist for the SSE transport. Defaults to loopback only;
  deployments behind a reverse proxy or with non-loopback binds must set
  this explicitly.

## [0.9.0]

Release candidate for the first open-source release. Adds a third secret source
type and per-key CRUD tools that preserve the existing "no plaintext crosses the
MCP boundary" security property. Promotes to 1.0.0 after a verification period.

### Added

- **`derived` source type** — A secret computed from another key in the same
  file via a named transform. Initial transforms: `pbkdf2_sha512_authelia` and
  `sha256_hex`. Rotating a generated source automatically recomputes derived
  values in topological order; renaming a source updates `from:` references;
  deleting a source is rejected while dependents still exist.
- **`sops_delete_secrets`** — Remove one or more keys from a file. Enforces
  derivation dependencies (a source cannot be deleted while a derived secret
  references it, unless both are deleted together).
- **`sops_rename_secret`** — Rename a key while preserving its value, source
  type, and metadata. Updates `from:` references in any dependent derived
  secrets.
- **`sops_update_external`** — Replace the value of an `external` secret (for
  when the user has rotated an upstream credential). Rejects attempts to update
  `generated` or `derived` secrets. Triggers a cascade recompute of any derived
  secrets that reference the updated key.
- **End-to-end integration tests** exercising the real `sops` binary with a
  throwaway age keypair. Test count: 29 (was 12).
- `Apache-2.0` LICENSE.

### Changed

- **`sops_create_oidc_secret`** is now a thin convenience wrapper around
  `sops_create_secrets` with a `generated` + `derived` pair. The encrypted file
  now contains both `KEY_NAME` and `KEY_NAME_HASH`; the hash is still returned
  in the response for pasting into Authelia's `configuration.yml`. Rotation of
  the base secret automatically refreshes the hash.
- `sops_add_metadata` now accepts `derived` entries (with `transform` and
  `from` fields) for retrofitting metadata onto legacy files.
- `sops_add_secrets` now supports adding `derived` secrets that reference
  either newly-added or existing keys.

## [0.1.0]

Initial release (internal).

### Added

- `sops_create_secrets` — Create a new encrypted file with `generated` and/or
  `external` secrets. Stores a `_meta_unencrypted` block alongside the
  encrypted values for decryption-free metadata access.
- `sops_list_secrets` — List keys and metadata without decrypting.
- `sops_rotate_generated` — Regenerate all `generated` secrets in a file while
  preserving `external` values.
- `sops_add_secrets` — Append new secrets to an existing file (rejects
  collisions).
- `sops_add_metadata` — Retrofit `_meta_unencrypted` onto legacy files.
- `sops_create_oidc_secret` — Authelia-specific OIDC client secret with
  PBKDF2-SHA512 hash generation.
- Supply-chain protections: Docker base image digest pinning, binary checksum
  verification, Python dependency hash locking, CI verification gate.
- SSE-over-HTTP transport with optional bearer-token auth.
- stdio transport for direct Claude Code integration.
