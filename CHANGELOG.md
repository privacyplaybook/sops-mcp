# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
