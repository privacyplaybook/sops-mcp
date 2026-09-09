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

### Key material handling

Private keys are supplied per operation rather than inherited from the
process environment. A decrypt invocation gets an environment carrying
only the keys of the domain for that call; an encrypt invocation carries
none at all, since it takes its recipients from the command line. Every
other age key variable is stripped, and `HOME` / `XDG_CONFIG_HOME` point
at an empty directory so that `~/.config/sops/age/keys.txt` cannot widen
a domain's reach. Key material is never logged, never included in an error message,
and never returned across the MCP boundary — `sops_list_domains` reports
public recipients and a count.

The domains file is checked for integrity whether or not it holds key
material, because it decides which recipients every secret is encrypted
to: the server refuses to start if it is writable by group or other, or
owned by anyone but the server's user or root. A file holding private
keys — the domains file with inline `keys:`, or any `key_file` it names —
must additionally not be world-readable; group-readable earns a warning
rather than a refusal, because container secret mounts commonly arrive
that way and refusing them pushes operators back to environment
variables, which `/proc/<pid>/environ` and `docker inspect` both
expose.

### Metadata authentication

SOPS's MAC covers unencrypted values, so the `_meta_unencrypted` block
cannot be edited without breaking decryption. That protects every mutation
tool, since all of them decrypt. It does *not* protect read-only paths:
`sops_list_secrets` reports metadata without a key and therefore without
verification, so a tampered file can mislead a listing. Acting on it fails.
Mutations additionally verify a file's real recipients against the named
domain before trusting the recorded domain name, and refuse any file
whose access rules this server cannot reproduce. It re-encrypts to a flat
age recipient list, so a file carrying another master key (`pgp`, `kms`,
`gcp_kms`, `azure_kv`, `hc_vault`) would come back with that holder
dropped, and a Shamir file (`key_groups`, `shamir_threshold`) would have
its n-of-m threshold flattened into a list any single holder could open.
Both are silent downgrades, so such files are refused outright.

See the [Security section of the README](./README.md#security) for the
full defence-in-depth list (no client filesystem access, public-key-only
encryption for normal use, secure temp files, OS-level entropy, key-name
input validation).

## Out of scope

- Compromise of the host running the MCP server itself (e.g. root access,
  process-memory inspection). Private keys reach the server through
  `SOPS_AGE_KEY` or a domains file, and are passed to `sops` in the child
  environment when decrypting; anyone who can read that process's
  environment or those files can decrypt.
- `.sops.yaml` creation rules are not supported; the server has no view of
  the client filesystem. Multiple recipients and recipient rotation are
  handled by key domains and `sops_rekey` (see the README).
- **Tenant isolation between callers.** Key domains separate key sets, not
  callers. On the SSE transport a single `SOPS_MCP_API_TOKEN` reaches every
  domain the server holds, so two mutually distrusting parties must not
  share one server process. Binding tokens to domains is designed but not
  implemented; see `docs/design/domains.md`.
- Denial-of-service by a client with valid credentials. The SSE transport
  has bearer-token auth and Host-header allowlisting (DNS-rebinding
  protection), but does not enforce per-client rate limits.
- Attacks that depend on a malicious `sops` binary on the server's
  `PATH`. Supply-chain integrity for the published Docker image is
  covered by digest-pinned base images and cosign-signed releases (see
  README "Verifying a published release"); deployments outside the
  published image are responsible for their own toolchain integrity.
