# Security

## Reporting a vulnerability

Please report security issues privately via GitHub's
[**Report a vulnerability**](https://github.com/privacyplaybook/sops-mcp/security/advisories/new)
form. This opens a private security advisory visible only to you and the
maintainers; do not open a public GitHub issue for suspected vulnerabilities.

Expect an initial acknowledgement within a few days. Once a fix is ready we'll
coordinate a disclosure window before any public write-up.

## Threat model

This server creates and manages SOPS-encrypted secrets on behalf of an MCP
client (typically an AI agent). The security model assumes **the MCP client is
untrusted** — it may attempt to exfiltrate plaintext, escalate to keys it
shouldn't see, or rotate values to attacker-chosen content.

The single hard rule: **plaintext secret values never cross the MCP boundary
back to the client.** Generated and rotated values stay on the server side;
only their existence and metadata are observable. Derived values (e.g.
PBKDF2-SHA512 hashes intended for an Authelia config file) are returned
because they're meant to be pasted into config — don't derive values you
don't intend to publish.

See the [Security section of the README](./README.md#security) for the
full defence-in-depth list (no client filesystem access, public-key-only
encryption for normal use, secure temp files, OS-level entropy, key-name
input validation).

## Out of scope

- Compromise of the host running the MCP server itself (e.g. root access,
  process-memory inspection). The age private key is provided via the
  `SOPS_AGE_KEY` environment variable on mutating operations; anyone with
  read access to that env var can decrypt.
- Multi-recipient / team key management (`.sops.yaml`, `updatekeys`) is
  intentionally deferred to the upstream `sops` CLI — recipient rotation,
  key splitting, and shared-secret workflows are not supported in v1.
- Denial-of-service by a client with valid credentials. The SSE transport
  has bearer-token auth and Host-header allowlisting (DNS-rebinding
  protection), but does not enforce per-client rate limits.
- Attacks that depend on a malicious `sops` binary on the server's
  `PATH`. Supply-chain integrity for the published Docker image is
  covered by digest-pinned base images and cosign-signed releases (see
  README "Verifying a published release"); deployments outside the
  published image are responsible for their own toolchain integrity.
