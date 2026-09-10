# sops-mcp

<!-- mcp-name: io.github.privacyplaybook/sops-mcp -->

MCP server for creating and managing [SOPS](https://github.com/getsops/sops)-encrypted secret files using [age](https://github.com/FiloSottile/age) encryption.

Designed for Claude Code (or any MCP client) to produce encrypted `secrets.enc.yaml` files without the model ever seeing plaintext values. All file content is passed as text parameters and returned as text — the server has no filesystem access to the client.

## Why

Two goals drive the design:

**1. Keep secrets in your source tree without leaking them.** For a small project, running a full secrets manager (Vault, AWS Secrets Manager, etc.) is overkill for a handful of credentials. Encrypting secrets at rest in git and decrypting them in your CI/CD pipeline at deploy time is much cheaper:

1. Create `secrets.enc.yaml` via this server — age-encrypted against your public key, safe to commit.
2. Commit it alongside your code.
3. Your CI/CD pipeline holds the age private key, decrypts at deploy time, and injects plaintext as environment variables into your container orchestrator.

The age private key lives in exactly one place: your CI/CD secrets store. Everywhere else — your laptop, your git remote, your container images — sees only ciphertext. See the [worked example](#example-integrating-with-a-cicd-deployment-pipeline) below.

**2. Let an AI coding agent generate secrets it can never read.** Claude (or any MCP client) can create passwords, rotate them, derive hashes, rename and delete them — but plaintext values never cross the MCP boundary back to the model. The server holds the encryption key; the client only submits requests and receives metadata. There is deliberately no "decrypt this one secret" tool. If a prompt injection or a misbehaving agent tried to exfiltrate a secret via tool output, there is no tool output to exfiltrate.

The simplest setup uses a single age recipient (the one CI private key). If you need several — a CI key plus an operator's key, or separate key sets for separate parties — see [Key domains](#key-domains).

## Design

Three ideas shape the tool surface:

1. **No plaintext crosses the MCP boundary.** Generated secret values are never returned to the client. There is deliberately no "decrypt this one key" tool. If you need plaintext, run `sops decrypt` yourself with the age private key.
2. **Metadata in plaintext.** A `_meta_unencrypted` block sits alongside the encrypted values (using SOPS's `unencrypted_suffix` feature) and records each secret's source, how it was generated, when it was last rotated, and which [key domain](#key-domains) it belongs to. This lets the server list and rotate secrets without decrypting. SOPS's MAC covers these values by default, so a tampered block fails to decrypt. Files that switch that off with `mac_only_encrypted` are refused. Tools that read the block *without* a key still cannot check the MAC, which is why recipients are verified separately.
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
| `sops_list_domains` | List the configured key domains, their age recipients, and whether each can decrypt or only encrypt. Never returns private key material. |

### Mutation (require a private key for the target domain)

| Tool | What it does |
|------|--------------|
| `sops_rotate_generated` | Regenerate all `generated` secrets. Derived secrets whose source was rotated are recomputed; others are preserved. External secrets are preserved. |
| `sops_add_secrets` | Add new secrets to an existing file. Supports all three sources. Rejects collisions with existing keys. |
| `sops_update_external` | Replace the value of an `external` secret. Cascades to any derived secrets that reference it. Rejects attempts to update `generated` or `derived`. |
| `sops_rename_secret` | Rename a key, preserving its value and metadata. Updates `from:` references in any derived secrets. |
| `sops_delete_secrets` | Remove one or more keys. Rejects deleting a secret that another derived secret still references (unless the dependent is deleted in the same call). |
| `sops_add_metadata` | Retrofit `_meta_unencrypted` onto a legacy SOPS file that lacks it. Supports `generated`, `external`, and `derived` entries. |
| `sops_rekey` | Re-encrypt a file onto its domain's current recipient list. Run this after a domain's recipients change, or to clear a "recipients do not match" refusal. Requires an explicit `domain`. Leaves a legacy file without a metadata block untouched in that respect, so `sops_add_metadata` still works on it. |

Every tool takes a `domain` argument except `sops_list_domains`, which needs none. It is optional everywhere but `sops_rekey`, where it is required because the call changes who can read the file. See [Key domains](#key-domains).

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
| `SOPS_AGE_KEY` | Sometimes | Age private key for the `default` domain — required to mutate a file belonging to it. Named domains take their keys from the domains file instead. |
| `SOPS_MCP_DOMAINS_FILE` | No | Path to a YAML file defining named [key domains](#key-domains). Use when one server needs more than one recipient set. |
| `SOPS_MCP_DOMAINS` | No | The same domains document [inline](#defining-domains-without-a-file), as YAML or compact JSON. Public recipient sets only — a domain here may not carry `keys` or `key_file`. Merged with `SOPS_MCP_DOMAINS_FILE`. |
| `SOPS_MCP_REQUIRE_DOMAIN` | No | Set to `1` to require every tool call to name its domain. The file's recorded domain and the `default` fallback are both disabled. |
| `SOPS_MCP_TRANSPORT` | No | `stdio` (default) or `sse` |
| `SOPS_MCP_HOST` / `SOPS_MCP_PORT` | No | Bind host/port for SSE transport (default: `127.0.0.1:55090`). Binding to `0.0.0.0` requires `SOPS_MCP_API_TOKEN` — the server refuses to start otherwise. |
| `SOPS_MCP_ALLOWED_HOSTS` | No | Comma-separated allowlist for the SSE `Host` header (DNS rebinding protection). Default: `127.0.0.1,127.0.0.1:*,localhost,localhost:*`. Set explicitly when binding to a non-loopback address — e.g. `mcp.example.com,mcp.example.com:*`. |
| `SOPS_MCP_API_TOKEN` | Sometimes | Required when SSE transport binds to `0.0.0.0`; otherwise optional. When set, SSE requires `Authorization: Bearer <token>`. |

\* One of `SOPS_MCP_AGE_PUBLIC_KEY` or `SOPS_AGE_RECIPIENTS` must be set, unless `SOPS_MCP_DOMAINS_FILE` or `SOPS_MCP_DOMAINS` supplies at least one domain. The server refuses to start with no domains at all.

Both recipient variables accept a comma-separated list, and `SOPS_AGE_KEY` accepts several newline-separated keys. Together they form the `default` domain.

## Key domains

A **domain** is a named set of age recipients plus, optionally, the private keys the server holds for them. It is the unit the server encrypts to and decrypts with.

You do not need to configure one. The environment variables above become a domain called `default`, and a single-recipient setup never has to mention domains again.

### Why they exist

Every mutation tool decrypts, changes, and re-encrypts. Re-encryption uses the server's configured recipients — so if a file was encrypted to a CI key *and* an operator key, but the server only knows about CI, the operator used to be dropped from the file silently. Domains fix that by making the recipient set a named, checked thing:

- A mutation compares the file's actual recipients against the domain's. If they differ it refuses, rather than quietly changing who can read the file.
- One server process can hold several independent key sets.
- `sops_rekey` performs a deliberate recipient change, which is the `sops updatekeys` workflow.

### Several recipients, one domain

The common case needs no domains file. List every recipient in the usual variable:

```bash
SOPS_MCP_AGE_PUBLIC_KEY="age1ci...,age1operator..."
SOPS_AGE_KEY="AGE-SECRET-KEY-1CI..."
```

Files are now encrypted to both, and mutations keep both. The server only needs whichever private key it will actually decrypt with.

### Several domains

Point `SOPS_MCP_DOMAINS_FILE` at a YAML file:

```yaml
version: 1
domains:
  homelab:
    recipients:
      - age1ci...          # CI runner
      - age1operator...    # operator laptop
    keys:
      - AGE-SECRET-KEY-1CI...
  client-acme:
    recipients:
      - age1acme...
    key_file: /run/secrets/acme.agekey   # an age keys file
  archive:
    recipients:
      - age1archive...
    # no keys: this domain can encrypt but never decrypt
```

The domains file must not be writable by group or other, and must be owned by the user the server runs as or by root. That check applies whether or not it holds key material, because the file decides which recipients everything is encrypted to.

A file holding private keys — the domains file with inline `keys:`, or any `key_file` — must additionally not be world-readable. Group-readable is allowed with a warning, so a container secret mounted root-owned and readable by the runtime group works. In the published image the server runs as uid 65532, so a Docker or compose secret needs a `uid:`/`gid:`/`mode:` that lets that user read it; `mode: 0640` with a matching group is the usual answer.

Startup checks that every private key parses, and warns about any whose public half is not in its domain's recipient list. That is a warning rather than an error because it is the normal state mid recipient-rotation: the old key still opens files encrypted before the change, and `sops_rekey` is how those get migrated.

### Defining domains without a file

A domains file is the only place private keys may live, because it is the
only one that can be permission-checked. That is a poor fit for a domain
that has no private key at all — a recipient set you encrypt *to*, where
someone else holds the key. Deployments where writing a file is awkward
(a distroless image with no shell, an orchestrator with no inline-file
primitive) then have to mount a volume to deliver two lines of public
key material.

`SOPS_MCP_DOMAINS` takes the same document inline:

```bash
SOPS_MCP_DOMAINS='{"version":1,"domains":{"archive":{"recipients":["age1archive..."]}}}'
```

YAML works too; JSON is simply the form that survives environments where
a multi-line value is inconvenient, and it parses because YAML is a
superset of JSON.

A domain defined here **may not set `keys` or `key_file`** and the server
refuses to start if one does. An environment variable is visible to
`docker inspect` and `/proc/<pid>/environ`, and carries none of the
ownership and mode checks a file gets, so it is the wrong place for a
private key.

The two sources are **merged**, so a deployment can keep its
key-holding domains in a file and its public ones inline. A domain name
defined by more than one source is fatal rather than silently resolved —
the same rule that already applies when a file defines `default`
alongside the v1 environment variables.

### Which domain does a tool use?

In order: the `domain` argument, then the domain recorded in the file's `_meta_unencrypted` block, then `default`. Set `SOPS_MCP_REQUIRE_DOMAIN=1` to remove the last step and force every call to be explicit.

The recorded name is a hint. The check is the recipient list in the file's own SOPS envelope, which is why a mislabelled file is refused rather than re-keyed.

### Recipient rotation

Adding or removing a recipient is a two-step operation:

1. Edit the domain's recipient list and restart the server.
2. Run `sops_rekey` on each affected file, naming the domain.

Until a file is rekeyed, mutations on it are refused with a message pointing here. `sops_list_secrets` reports the mismatch too, and needs no private key to do it.

`sops_rekey` will not move a file between domains. A file that records a domain can only be rekeyed onto that same domain's current recipient list; naming a different one is refused. This matters when two domains share a private key, where decryption would otherwise succeed and quietly drop the recipients the other domain does not have. Moving secrets between domains is deliberately manual: decrypt with the `sops` CLI, then `sops_create_secrets` into the new domain.

### Files this server will not touch

SOPS can protect a file in ways this server cannot reproduce, because it always re-encrypts to a flat age recipient list:

- **Another master key alongside age** (`pgp`, `kms`, `gcp_kms`, `azure_kv`, `hc_vault`). Re-encrypting would drop that holder.
- **Shamir key groups** (`key_groups` with a `shamir_threshold`). Re-encrypting would flatten an n-of-m threshold into a list any single holder could open.
- **`mac_only_encrypted`**. It leaves the plaintext metadata block unauthenticated, so a file's recorded domain and each secret's `source` could be rewritten by anyone who can edit the file.

Both are silent downgrades, so every mutation refuses these files and `sops_list_secrets` flags them. Manage them with the `sops` CLI.

### Running mixed versions

A file this version writes stays readable and writable by sops-mcp 0.10.1 and earlier. The older version does not know about the `domain` field, so it drops it the next time it mutates the file, leaving a file with no recorded domain. That resolves to `default` here, and the recipient check still protects it either way. Re-record the domain by passing `domain` explicitly on any later call, or with `sops_rekey`.

### What domains are not

Domains separate key sets, not callers. On the SSE transport a single API token reaches every domain the server holds. If you need two parties that must not read each other's secrets, run a server process each.

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
    domain: default
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

Every `sops` call this server makes is pinned to an empty `--config`, so a `.sops.yaml` in the directory the server was started from cannot change how files are encrypted. Recipients come from the domain, and nothing else.

The `sops:` block above is abridged. A real file also carries `lastmodified`, a `mac`, a `version`, and empty lists for the master-key types this server does not use (`pgp`, `kms`, `gcp_kms`, `azure_kv`, `hc_vault`). The MAC covers unencrypted values too, so an edited `_meta_unencrypted` block fails to decrypt. If any of those other key lists is non-empty, this server refuses to mutate the file — it encrypts to age alone and would otherwise drop that key holder silently.

## Why these tools and not others

**Per-key read (decrypt-one-secret):** intentionally absent. Returning plaintext over the MCP boundary would give the model access to secret material during tool calls — an accidental exfiltration vector. If you need a plaintext value, run `sops decrypt` yourself with the age private key.

**Per-key in-place update for generated/derived secrets:** intentionally absent. `sops_rotate_generated` is the one path that changes those values, so rotations leave an audit trail (`last_rotated` timestamp) and cascade cleanly to derived secrets.

**`.sops.yaml` creation rules:** out of scope. The server has no view of your filesystem, so path-based creation rules cannot apply. Recipients come from [key domains](#key-domains) instead, and `sops_rekey` covers the `updatekeys` workflow.

**Tenant isolation on the SSE transport:** not yet. Domains separate key *sets*, not *callers*. A single `SOPS_MCP_API_TOKEN` grants every domain the server holds, so do not put two mutually distrusting parties behind one SSE server. Run one process each.

**Other source types (imported, templated):** out of scope. Those are orchestration concerns — fetch values from Vault or compose URLs in your deployment templating layer, then pass the result here as an `external` secret.

## Supply chain integrity

The Docker build is hardened with three layers of verification, enforced by a CI gate.

### Base image digest pinning

The Dockerfile builds on `cgr.dev/chainguard/python` (Wolfi), pinned by SHA-256 digest (`@sha256:...`) so Docker always pulls the exact image that was audited rather than whatever the tag currently points to. Two stages are pinned separately: `:latest-dev` for the build stage, which has apk, a shell and a build toolchain, and `:latest` for the runtime stage, which is distroless — no shell, no package manager. Both digests and their cosign signature status are tracked in `base-images.lock.json`.

Update the base image (when upstream publishes security patches):

```bash
pip install requests  # one-time; cosign on PATH is needed for the signature checks
python3 lib/pin_base_images.py
```

### Signed binaries from Wolfi

The `sops` and `age` binaries are installed with `apk` from Wolfi's package repository, whose index is signed by Chainguard. They are pinned transitively through the base image digest, so re-pinning the base image also re-pins these binaries.

### Python dependency hash pinning

Runtime dependencies are installed from `requirements.lock.txt` with `pip install --require-hashes`, which rejects any package whose content doesn't match the recorded SHA-256 hashes. This prevents dependency hijacking and typosquatting.

Update dependencies after editing `requirements.in`:

```bash
pip install pip-tools  # one-time
lib/compile_requirements.sh
```

### CI verification

The `supply-chain.yml` workflow runs `lib/verify_requirements.py`, `lib/verify_base_images.py` and `lib/verify_version.py`, then audits the lockfile for known advisories. It runs on every pull request to `main`, and on pushes to `main` that touch the Dockerfile, a lockfile, `pyproject.toml`, `server.json` or `lib/`. It checks that lockfiles are well-formed, that every Dockerfile `FROM` line is digest-pinned, that `server.json` matches the version in `pyproject.toml`, and that no pinned dependency has a published vulnerability.

The audit is the same gate the publish workflow runs, so a lockfile that would block a release now blocks the pull request instead. Because it queries live advisory data, an unrelated pull request can start failing when a new advisory lands against a pinned dependency. That is the intended trade-off; the fix is to refresh the lockfile.

Note that `pip-compile` keeps existing pins unless told otherwise, so regenerating after an advisory needs the upgrade flag:

```bash
lib/compile_requirements.sh --upgrade
```

## Verifying a published release

Every container image published to GHCR is signed by this repo's publish workflow using keyless [cosign](https://github.com/sigstore/cosign) via sigstore, and ships with SLSA v1.0 build provenance and an SPDX SBOM attached as OCI artifacts. Every commit on `main` and every release tag is SSH-signed. You can verify all of this without holding any long-lived key material — the signatures are anchored in sigstore's public transparency log.

Install cosign: https://docs.sigstore.dev/system_config/installation

**Verify the image signature.** A successful verification proves the image was built by this repository's `publish.yml` workflow, not just that its digest matches a reference someone sent you.

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/privacyplaybook/sops-mcp/\.github/workflows/publish\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/privacyplaybook/sops-mcp:<tag>
```

**Inspect the attestations.**

```bash
# List all artifacts attached to the image
cosign tree ghcr.io/privacyplaybook/sops-mcp:<tag>

# Download the SBOM (SPDX JSON)
cosign download sbom ghcr.io/privacyplaybook/sops-mcp:<tag>

# Verify the SLSA build provenance
cosign verify-attestation --type slsaprovenance1 \
  --certificate-identity-regexp 'https://github.com/privacyplaybook/sops-mcp/\.github/workflows/publish\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/privacyplaybook/sops-mcp:<tag>
```

**Verify git tags and commits.** The simplest check is the green **Verified** badge on the github.com [commits](https://github.com/privacyplaybook/sops-mcp/commits/main) and [tags](https://github.com/privacyplaybook/sops-mcp/tags) pages.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
pytest tests/ -v  # unit tests plus end-to-end sops round-trips
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
