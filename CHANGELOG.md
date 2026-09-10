# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0]

### Fixed (post-merge)

- **Lockfile moved off two versions with published advisories.**
  `cryptography` 49.0.0 (PYSEC-2026-3552) and `mcp` 1.28.0
  (PYSEC-2026-3483) are now 50.0.1 and 1.30.0. Both pins predate this
  release; they surfaced when the publish workflow's audit ran on `main`.
- **The dependency audit now runs on pull requests.** It lived only in the
  publish workflow, which runs on pushes to `main` and on tags, so a
  lockfile with a known advisory could merge unseen and fail only after
  landing. `supply-chain.yml` runs the same gate on every pull request.
- **`lib/compile_requirements.sh` takes `--upgrade`.** Without it
  `pip-compile` keeps every pin it already finds, which is why
  regenerating the lockfile never moved these two forward.

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

- `SOPS_MCP_DOMAINS` — the same domains document inline, as YAML or
  compact JSON, for domains that hold no private key. A domains file is
  the only place key material may live, because it is the only source
  that can be permission-checked; that is a poor fit for a public
  recipient set, and deployments that cannot easily write a file (a
  distroless image with no shell, an orchestrator with no inline-file
  primitive) had to mount a volume to deliver two lines of public key
  material. A domain defined here may not set `keys` or `key_file` and
  the server refuses to start if one does — an environment variable is
  visible to `docker inspect` and `/proc/<pid>/environ` and carries none
  of a file's ownership and mode checks. The two sources are merged, so
  key-holding domains can stay in a file while public ones live inline;
  a name defined by more than one source is fatal rather than silently
  resolved.
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

- **Lint coverage widened.** ruff now runs bugbear, bandit, pylint,
  pyupgrade, simplify, perf, logging and pytest rule families instead of
  its small default set, with the deliberate patterns in this codebase
  (`/dev/shm` temp files, fixed-argv subprocess calls, long linear tool
  handlers) exempted with reasons in `pyproject.toml`. Internal only; no
  behaviour change.
- **Python 3.14 is supported and tested.** Added to the CI matrix and the
  package classifiers. The published Docker image still runs 3.13; that is
  tracked separately.
- **An unmatched private key no longer stops the server booting.** A key
  whose public half is not in its domain's recipient list is the normal
  state mid recipient-rotation, and it still opens files encrypted before
  the change. It is now a warning, and `sops_rekey` migrates those files.
- **`SOPS_MCP_REQUIRE_DOMAIN` now means what its name says.** It was
  checked only after the file's recorded domain, so a call omitting
  `domain` still succeeded whenever the client-supplied content named
  one. The flag now requires the caller to name the domain.
- **Key-file permission rules fit container secrets.** A file holding
  private keys may be group-readable, with a warning, and may be owned by
  root as well as by the server's user. World-readable and group-writable
  remain fatal. The previous rules rejected the Docker secret path the
  README documents.
- **`sops_list_secrets` honours its `domain` argument.** It advertised one
  and ignored it, reporting a mismatch against `default` for a file the
  caller had asked about under another domain.
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

- **Files with `mac_only_encrypted` are refused.** That option makes sops
  MAC the ciphertext alone, leaving the plaintext `_meta_unencrypted`
  block unauthenticated — so a file's recorded domain, and each secret's
  `source`, could be rewritten by anyone able to edit the file. Since
  `source` decides whether a value may be overwritten in place, a forged
  one would let `sops_update_external` overwrite a generated secret.
- **Every sops invocation is pinned to an empty `--config`.** sops
  discovers a `.sops.yaml` by walking up from its working directory,
  which is this server's — typically the user's project, where a sops
  user very likely keeps one. Its creation rules could break every
  encrypt: a `path_regex` that misses the temp file fails the call, and
  an `encrypted_regex` collides with the `--unencrypted-suffix` this
  server relies on. Recipients were never at risk, since `--age` wins.
- **`sops_rekey`'s cross-domain guard now covers unlabelled files.** It
  fired only when the file recorded a domain, so it was dead for any file
  an older version had round-tripped. Where a rekey would revoke a reader
  and another domain's recipients match the file exactly, it is refused.
- **Files this server cannot faithfully re-encrypt are refused.** It
  always re-encrypts to a flat age recipient list, so a file carrying
  another master key (`pgp`, `kms`, `gcp_kms`, `azure_kv`, `hc_vault`)
  would come back with that holder dropped, and a Shamir file
  (`key_groups` + `shamir_threshold`) would have its n-of-m threshold
  flattened into a list any single holder could open. Both are silent
  downgrades. Mutations refuse them and `sops_list_secrets` flags them.
- **`sops_rekey` refuses to move a file between domains.** Two domains
  sharing a private key would otherwise let a file be moved quietly,
  dropping the recipients the target domain does not have — decryption
  succeeds, so nothing else catches it.
- **The domains file is integrity-checked even without inline keys.** It
  decides which recipients everything is encrypted to, so a
  group-writable one let a local attacker add their own recipient. The
  server now refuses to start on a domains file writable by group or
  other, or owned by a third party, regardless of whether it holds key
  material.
- **Private keys reach the sops subprocess only when decrypting.**
  Encryption takes its recipients from the command line, so an encrypt
  call no longer carries an identity in the child environment where
  `/proc/<pid>/environ` would expose it.
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
