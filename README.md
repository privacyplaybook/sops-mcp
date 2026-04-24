# sops-mcp

MCP server for creating and managing [SOPS](https://github.com/getsops/sops)-encrypted secret files using [age](https://github.com/FiloSottile/age) encryption.

Designed for Claude Code (or any MCP client) to produce encrypted `secrets.enc.yaml` files without the model ever seeing plaintext values. All file content is passed as text parameters and returned as text — the server has no filesystem access to the client.

## Why

**Keep secrets in your source tree without leaking them.** For a small project, running a full secrets manager (Vault, AWS Secrets Manager, etc.) is overkill for a handful of credentials. Encrypting secrets at rest in git and decrypting them in your CI/CD pipeline at deploy time is much cheaper:

1. Create `secrets.enc.yaml` via this server — age-encrypted against your public key, safe to commit.
2. Commit it alongside your code.
3. Your CI/CD pipeline holds the age private key, decrypts at deploy time, and injects plaintext as environment variables into your container orchestrator.

The age private key lives in exactly one place: your CI/CD secrets store. Everywhere else — your laptop, your git remote, your container images — sees only ciphertext. The MCP client also never sees plaintext: you give the server the public key, and even mutations that regenerate values return only metadata. See the [worked example](#example-integrating-with-a-cicd-deployment-pipeline) below.

This pattern assumes a single age recipient (the one CI private key). For multi-recipient / team key management, use the `sops` CLI directly for recipient rotations and this server for content management.

## Design

Three ideas shape the tool surface:

1. **No plaintext crosses the MCP boundary.** Generated secret values are never returned to the client. There is deliberately no "decrypt this one key" tool. If you need plaintext, run `sops decrypt` yourself with the age private key.
2. **Metadata in plaintext.** A `_meta_unencrypted` block sits alongside the encrypted values (using SOPS's `unencrypted_suffix` feature) and records each secret's source, how it was generated, and when it was last rotated. This lets the server list and rotate secrets without decrypting.
3. **No in-place value update for generated or derived secrets.** Those change only via rotation — the mutation model is deliberate, not accidental. External secrets (e.g. an upstream API key the user controls) can be updated with `sops_update_external`.

## Secret sources

Every secret is one of three sources, recorded in `_meta_unencrypted`:

- **`generated`** — Cryptographically random values (Python `secrets` / OS CSPRNG). You specify length and charset; the server stores both so it can regenerate on rotation.
- **`external`** — User-provided values encrypted as-is (SMTP credentials, third-party API keys, etc.). Preserved across rotation. Updated via `sops_update_external`.
- **`derived`** — Computed from another key in the same file via a named transform. When the source is rotated (or an external source is updated), the derived value is automatically recomputed in topological order. Useful for things like Authelia's PBKDF2 hashes of OIDC client secrets.

### Transforms (for `derived` secrets)

| Transform | Purpose | Deterministic |
|-----------|---------|---------------|
| `pbkdf2_sha512_authelia` | PBKDF2-SHA512 hash in Authelia's `configuration.yml` format (`$pbkdf2-sha512$310000$...`) | No — random salt per call |
| `sha256_hex` | Hex-encoded SHA-256 digest | Yes |

## Tools

### Creation and listing

| Tool | What it does |
|------|--------------|
| `sops_create_secrets` | Create a new encrypted file with one or more secrets (any mix of sources). |
| `sops_list_secrets` | List keys, sources, and descriptions from a file **without decrypting**. |
| `sops_create_oidc_secret` | Convenience: create an Authelia OIDC client secret as a `generated` + `derived` (`pbkdf2_sha512_authelia`) pair in one call. The hash is returned in the response for pasting into `configuration.yml`. |

### Mutation (require `SOPS_AGE_KEY`)

| Tool | What it does |
|------|--------------|
| `sops_rotate_generated` | Regenerate all `generated` secrets. Derived secrets whose source was rotated are recomputed; others are preserved. External secrets are preserved. |
| `sops_add_secrets` | Add new secrets to an existing file. Supports all three sources. Rejects collisions with existing keys. |
| `sops_update_external` | Replace the value of an `external` secret. Cascades to any derived secrets that reference it. Rejects attempts to update `generated` or `derived`. |
| `sops_rename_secret` | Rename a key, preserving its value and metadata. Updates `from:` references in any derived secrets. |
| `sops_delete_secrets` | Remove one or more keys. Rejects deleting a secret that another derived secret still references (unless the dependent is deleted in the same call). |
| `sops_add_metadata` | Retrofit `_meta_unencrypted` onto a legacy SOPS file that lacks it. Supports `generated`, `external`, and `derived` entries. |

## Setup

### Prerequisites

- Python 3.11+
- [sops](https://github.com/getsops/sops) CLI binary
- An age keypair (see below)

### Generating an age keypair

If you don't already have one, install [age](https://github.com/FiloSottile/age) and run:

```bash
age-keygen -o age-key.txt
```

The file looks like:

```
# created: 2026-04-22T12:34:56Z
# public key: age1abc...xyz
AGE-SECRET-KEY-1HH...
```

- **Public key** (`age1...`) — pass to this server as `SOPS_MCP_AGE_PUBLIC_KEY`. Safe to share anywhere.
- **Private key** (`AGE-SECRET-KEY-...`) — store as a CI/CD secret (commonly named `SOPS_AGE_KEY`). Never commit to source control. Anyone with this key can decrypt every `secrets.enc.yaml` encrypted to the matching public key.

Back up the private key somewhere safe (password manager, hardware token). Losing it means losing access to every secret you've encrypted.

### Installation

```bash
git clone <repo-url>
cd sops-mcp
python3 -m venv .venv
.venv/bin/pip install -e .
```

### Claude Code configuration

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "sops-mcp": {
      "command": "/path/to/sops-mcp/.venv/bin/python",
      "args": ["-m", "sops_mcp"],
      "env": {
        "SOPS_MCP_SOPS_BINARY": "/path/to/sops",
        "SOPS_MCP_AGE_PUBLIC_KEY": "<your-age-public-key>"
      }
    }
  }
}
```

### Environment variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `SOPS_MCP_AGE_PUBLIC_KEY` | Yes* | Age public key for encryption |
| `SOPS_AGE_RECIPIENTS` | Yes* | Alternative to `SOPS_MCP_AGE_PUBLIC_KEY` |
| `SOPS_MCP_SOPS_BINARY` | No | Path to sops binary (default: `sops`) |
| `SOPS_MCP_LOG_LEVEL` | No | Log level (default: `WARNING`) |
| `SOPS_AGE_KEY` | Sometimes | Age private key — required for any mutation tool (rotate, add, update, rename, delete) |
| `SOPS_MCP_TRANSPORT` | No | `stdio` (default) or `sse` |
| `SOPS_MCP_HOST` / `SOPS_MCP_PORT` | No | Bind host/port for SSE transport (default: `0.0.0.0:55090`) |
| `SOPS_MCP_API_TOKEN` | No | If set, SSE transport requires `Authorization: Bearer <token>` |

\* One of `SOPS_MCP_AGE_PUBLIC_KEY` or `SOPS_AGE_RECIPIENTS` must be set.

## Security

- **No filesystem access** — The server never reads from or writes to the client filesystem. All content is passed as text parameters and returned as text.
- **No private key for normal use** — Encryption uses only the public key. The private key is needed only for mutation tools.
- **No plaintext in responses** — Generated secret values are never returned. Derived values are returned because they're meant to be pasted into config files (e.g. an Authelia PBKDF2 hash) — don't derive values you don't intend to publish.
- **Secure temp files** — Used only for sops CLI invocation. Created with 0600 permissions, overwritten with zeros before deletion, cleanup guaranteed by `finally` block.
- **OS-level entropy** — Secret generation uses Python's `secrets` module (backed by `/dev/urandom`).
- **stdio transport by default** — No network exposure; runs as a client child process.
- **Input validation** — Key names must match `^[A-Z][A-Z0-9_]*$`.

## Encrypted file format

```yaml
DB_PASSWORD: ENC[AES256_GCM,data:...,tag:...,type:str]
SMTP_USER: ENC[AES256_GCM,data:...,tag:...,type:str]
DB_PASSWORD_HASH: ENC[AES256_GCM,data:...,tag:...,type:str]
_meta_unencrypted:
    version: 1
    secrets:
        DB_PASSWORD:
            source: generated
            description: Database password
            generation:
                length: 32
                charset: alphanumeric
            last_rotated: "2026-04-21T15:30:00Z"
        SMTP_USER:
            source: external
            description: SMTP username
        DB_PASSWORD_HASH:
            source: derived
            derivation:
                transform: sha256_hex
                from: DB_PASSWORD
            last_rotated: "2026-04-21T15:30:00Z"
sops:
    age:
        - recipient: age1...
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            ...
    unencrypted_suffix: _unencrypted
```

Secret values are AES-256-GCM encrypted. The `_meta_unencrypted` block is stored in plaintext (using SOPS's `unencrypted_suffix` feature) so metadata is readable without decryption.

## Why these tools and not others

**Per-key read (decrypt-one-secret):** intentionally absent. Returning plaintext over the MCP boundary would give the model access to secret material during tool calls — an accidental exfiltration vector. If you need a plaintext value, run `sops decrypt` yourself with the age private key.

**Per-key in-place update for generated/derived secrets:** intentionally absent. `sops_rotate_generated` is the one path that changes those values, so rotations leave an audit trail (`last_rotated` timestamp) and cascade cleanly to derived secrets.

**Multi-recipient / team key management (`.sops.yaml`, `updatekeys`):** planned for a future release. v1 assumes a single age recipient. For multi-recipient setups, use the `sops` CLI directly for recipient rotations and this server for content management.

**Other source types (imported, templated):** out of scope. Those are orchestration concerns — fetch values from Vault or compose URLs in your deployment templating layer, then pass the result here as an `external` secret.

## Supply chain integrity

The Docker build is hardened with three layers of verification, enforced by a CI gate.

### Base image digest pinning

The Dockerfile pins `python:3.12-slim` by SHA-256 digest (`@sha256:...`) so Docker always pulls the exact image that was audited, not whatever the `slim` tag currently points to. The digest and cosign signature status are tracked in `base-images.lock.json`.

Update the base image (when upstream publishes security patches):

```bash
pip install requests  # one-time
python3 lib/pin_base_images.py
```

### Binary checksum verification

The `sops` and `age` binaries downloaded in the Dockerfile are verified with `sha256sum -c` against checksums from the official release pages. A tampered binary fails the build.

### Python dependency hash pinning

Runtime dependencies are installed from `requirements.lock.txt` with `pip install --require-hashes`, which rejects any package whose content doesn't match the recorded SHA-256 hashes. This prevents dependency hijacking and typosquatting.

Update dependencies after editing `requirements.in`:

```bash
pip install pip-tools  # one-time
lib/compile_requirements.sh
```

### CI verification

The `supply-chain.yml` workflow runs `lib/verify_requirements.py` and `lib/verify_base_images.py` on every push and PR. It checks that all lockfiles are well-formed and all Dockerfile `FROM` lines are digest-pinned.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
pytest tests/ -v  # 29 tests including end-to-end sops round-trip
ruff check src/ tests/
```

## Example: integrating with a CI/CD deployment pipeline

A common pattern: use this server to produce `secrets.enc.yaml` files committed to your infrastructure repo, then decrypt them in CI and inject the plaintext values as environment variables to a container orchestrator (Portainer, Kubernetes, Nomad).

1. [Generate an age keypair](#generating-an-age-keypair) once. Give the private key to your CI as a secret (e.g. `SOPS_AGE_KEY`), the public key to Claude Code as `SOPS_MCP_AGE_PUBLIC_KEY`.
2. Ask the model to produce a `secrets.enc.yaml` with `sops_create_secrets`.
3. Commit the encrypted file.
4. In your deploy workflow, run `sops decrypt secrets.enc.yaml > .env` (or equivalent) and pass the result to your orchestrator.
5. When secrets need rotating, ask the model to run `sops_rotate_generated` or `sops_update_external`; commit and redeploy.

The `_meta_unencrypted` block lets your tools filter out the metadata (keys starting with `_`) when pushing values to an orchestrator, so metadata never leaks into environment variables.

## License

Apache-2.0. See [LICENSE](./LICENSE).
