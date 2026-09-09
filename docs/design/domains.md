# Design: Key domains

| | |
|---|---|
| Status | Implemented (phase 1) |
| Date | 2026-09-09 |
| Scope | `src/sops_mcp/sops.py`, `src/sops_mcp/server.py`, `_meta_unencrypted` schema, README / SECURITY |
| Supersedes | The "single age recipient" assumption in README.md and CLAUDE.md |

## Summary

Introduce a **domain**: a named, server-side bundle of one or more age
recipients plus, optionally, the matching private key(s). Every tool takes
an optional `domain` argument. Encryption uses the domain's recipient list.
Decryption injects the domain's private key into the `sops` subprocess for
that one call. Files record which domain they belong to, and the server
refuses to mutate a file whose actual recipients do not match that domain.

The work is split into two phases. Phase 1 makes domains a key-management
concept and fixes a latent recipient-dropping bug. Phase 2, only needed for
shared SSE deployments, binds bearer tokens to domains so that domains
become a tenant-isolation boundary.

## Problem

### v1 has exactly one key set per process

`create_server` reads `SOPS_MCP_AGE_PUBLIC_KEY` once and hands it to
`sops encrypt --age <value>` verbatim. Decryption relies on `sops` reading
`SOPS_AGE_KEY` from the inherited process environment. Serving a second
recipient set means running a second server process with a different
environment, which for Claude Code means a second MCP server entry with a
different name.

### Re-encryption silently drops recipients

Every mutation tool is decrypt, modify, re-encrypt from scratch. The
re-encrypt step uses only the server's configured recipients. A file that
arrives encrypted to recipients A and B, handled by a server configured
with A alone, comes back encrypted to A only. B loses access with no error
and no log line. The reverse is also true: a server configured with A,B
adds B to any file it touches.

Because `--age` accepts a comma-separated list and `SOPS_AGE_KEY` accepts
multiple keys, multi-recipient use "works" today by pass-through. It is
undocumented, untested, and subject to the bug above. This doc turns that
accident into a supported feature with a defined contract.

### Metadata is trusted on read

The 2026-04-27 audit recorded `_meta_unencrypted` as unauthenticated. That
turns out to be only half right, and the correction shaped this design.

Measured against sops 3.9.4: the MAC covers **all** values in the tree,
unencrypted ones included. A one-character edit to `domain:` or to a
secret's `source:` makes `sops decrypt` fail with a MAC mismatch. Turning
that off needs `--mac-only-encrypted`, which this server does not pass.
`tests/test_domain_isolation.py` pins the behaviour so the flag cannot be
introduced silently.

What remains unauthenticated is metadata read **without** decrypting.
`sops_list_secrets` never holds a key, and the recipient check necessarily
runs before decryption. So the design still treats the recorded domain as
a hint rather than an authority — the MAC is a second line, not the
first.

## Goals

- One server process can encrypt to, and decrypt with, several independent
  key sets.
- A file's recipient set is preserved across mutations. Changing it is an
  explicit operation, never a side effect.
- Existing single-key configurations keep working with no config change and
  no change to the files they produce.
- Recipient rotation (the `sops updatekeys` use case) becomes possible
  without leaving the server.
- Nothing in this design weakens the hard rule: plaintext secret values
  never cross the MCP boundary. Private keys never cross it either.

## Non-goals

- `.sops.yaml` creation rules, path-regex matching, or any other config the
  `sops` CLI reads from the working directory. The server has no view of
  the client's filesystem and this design keeps it that way.
- KMS, PGP, or any non-age key type. The domain model is agnostic, but only
  age is implemented.
- Per-user identity or audit logging in phase 1.
- Sharing a single file between domains. A file belongs to exactly one
  domain; a domain may have many recipients.

## The domain model

```
Domain
  name        ^[a-z][a-z0-9-]{0,62}$   (lowercase, DNS-label-like)
  recipients  [age1..., age1..., ...]  non-empty, deduplicated, order-preserved
  keys        [AGE-SECRET-KEY-..., ...] optional; zero or more private keys
```

A domain with no private keys is **encrypt-only**. It can serve
`sops_create_secrets` and `sops_list_secrets` and nothing else. This mirrors
the current contract where `SOPS_AGE_KEY` is only needed for mutation tools.

A domain's private keys do not have to correspond one-to-one with its
recipients. A CI server might hold one private key for a domain with three
recipients (CI, two humans). `sops` tries each key it is given and succeeds
on the first that unwraps the data key.

### Configuration

Two sources, merged at startup:

1. **The `default` domain from environment variables.** This is exactly the
   v1 contract, so existing deployments need no change.

   | Env var | Maps to |
   |---|---|
   | `SOPS_MCP_AGE_PUBLIC_KEY` or `SOPS_AGE_RECIPIENTS` | `default.recipients` (comma-split, trimmed) |
   | `SOPS_AGE_KEY` | `default.keys` (newline-split, trimmed) |

2. **A domains file, `SOPS_MCP_DOMAINS_FILE`.** YAML, read once at startup.
   Defines any number of named domains. May also define `default`, in which
   case the env vars for `default` must be unset (conflict is a startup
   error, not a merge).

   ```yaml
   version: 1
   domains:
     homelab:
       recipients:
         - age1ci000...            # CI runner
         - age1owen0...            # operator laptop
       keys:
         - AGE-SECRET-KEY-1CI...   # inline
     client-acme:
       recipients:
         - age1acme0...
       key_file: /run/secrets/acme.agekey   # age keys file, same format sops accepts
     archive:
       recipients:
         - age1arch0...
       # no keys: encrypt-only
   ```

   `key_file` is read at startup and its contents are treated like inline
   `keys`. Both may be given. The file must be mode 0600 or 0400 and owned
   by the server's uid; anything more permissive is a startup error.

Startup validation, all fatal:

- Every recipient parses as an age X25519 recipient (`age1` + bech32).
- Every private key parses as `AGE-SECRET-KEY-1...`.
- Every private key's derived recipient appears in the same domain's
  `recipients`. A key that cannot decrypt anything the domain encrypts is
  a misconfiguration, not a feature.
- At least one domain exists.
- Domain names match the regex and are unique.

The server logs, at INFO, one line per domain: name, recipient count,
key count, and whether it is encrypt-only. Never the key material.

### Key injection at call time

`SopsEncryptor` becomes domain-aware. Instead of one `age_public_key`
string, it takes a `Domain` per call:

```python
def encrypt(self, data: dict, domain: Domain) -> str
def decrypt(self, encrypted_content: str, domain: Domain) -> dict
```

`encrypt` passes `",".join(domain.recipients)` to `--age`.

`decrypt` builds a subprocess environment by copying `os.environ`,
**removing** `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, and
`SOPS_AGE_SSH_PRIVATE_KEY_FILE`, then setting `SOPS_AGE_KEY` to
`"\n".join(domain.keys)`. This is the load-bearing change: today the
inherited environment decides what can be decrypted, so a process holding
several keys would let any domain decrypt any file. After this change, a
call in domain X can only ever be given domain X's keys.

If `domain.keys` is empty, `decrypt` raises `SopsError` with the same
wording as today's missing-`SOPS_AGE_KEY` error, so client-facing behaviour
for encrypt-only setups is unchanged.

### Binding a file to a domain

Two pieces of information identify a file's domain:

- **The recorded name.** `_meta_unencrypted.domain: <name>`. Written on
  create, retrofit by `sops_add_metadata`, carried through every mutation.
  Optional in the schema so v1 files stay valid; the metadata `version`
  stays at 1.
- **The actual recipients.** `sops.age[].recipient` in the SOPS envelope.
  This list is what `sops` really encrypted to. The `sops` branch is
  excluded from the MAC, but an attacker who edits it cannot grant
  themselves access: adding a recipient entry without a valid wrapped data
  key produces an entry that cannot decrypt, and removing one only revokes
  that party.

The recorded name is a **hint**. The recipient list is the **check**.

Resolution order for every tool call:

1. If the caller passed `domain`, use it.
2. Else if the file has `_meta_unencrypted.domain`, use it.
3. Else use `default`.
4. If the resolved name is not configured, fail with
   `Unknown domain '<name>'. Configured: a, b, c.`

Then, for any tool that will **re-encrypt** the file (everything except
`sops_list_secrets` and `sops_create_secrets`):

5. Compare `set(sops.age[].recipient)` with `set(domain.recipients)`. If
   they differ, refuse:

   ```
   File is encrypted to 2 recipient(s) that do not match domain 'homelab'
   (3 configured). Refusing to re-encrypt because that would change who can
   read the file. Run sops_rekey to move the file onto the domain's current
   recipient list.
   ```

   The message deliberately counts rather than lists recipients so a wrong
   domain name does not enumerate another domain's public keys. Public keys
   are not secret, but this keeps the tool surface from being a probe.

Rule 5 is what makes the metadata hint safe, and it is deliberately
independent of the MAC. A tampered `domain` field can only steer
re-encryption if the two domains have identical recipient sets, in which
case nothing changes. Reaching decryption at all would additionally trip
the MAC. The value of checking first is a precise, actionable error
instead of an opaque `MAC mismatch`, and coverage of the paths that never
decrypt.

`sops_list_secrets` reports the resolved domain name, the recipient count
from the envelope, and a boolean `recipients_match_domain`, so a user can
spot a mismatch before attempting a mutation. It still needs no private
key.

### New tools

**`sops_list_domains`** (read-only, no key needed)

Returns each configured domain's name, recipient list, key count, and
`encrypt_only` flag. Recipients are public keys and are safe to surface.
Private key material is never included in any response, log line, or error
message.

**`sops_rekey`** (mutation, needs a key)

Input: `encrypted_content`, `domain` (required, no inference). Decrypts
with the domain's keys and re-encrypts to the domain's current recipient
list, updating `_meta_unencrypted.domain` to match. This is the one tool
exempt from rule 5, because changing the recipient set is its purpose.

It is also the migration path when a domain's recipient list changes in
config: edit the domains file, restart, run `sops_rekey` on each file. That
is the `sops updatekeys` workflow without the `.sops.yaml`.

`sops_rekey` does not need the file's old recipients to match anything.
It only needs a key that can decrypt the file. That key must belong to the
target domain (rule from "Key injection"), which means you cannot use
domain A's key to move a file into domain B. Moving a file between domains
is a two-step operation the user performs deliberately: decrypt with the
`sops` CLI, then `sops_create_secrets` in the new domain. This is
intentional. A single tool that reads with one key set and writes with
another is the one operation this design should make hard.

### Changes to existing tools

Every tool gains an optional `domain: string` input. Descriptions change
from "Requires `SOPS_AGE_KEY` env var" to "Requires a domain with a
private key". `sops_create_secrets` writes `_meta_unencrypted.domain`.
`sops_add_metadata` accepts and writes it. `_process_batch` is unaffected;
it operates on plaintext dicts and never touches keys.

## Phase 2: tenant isolation for SSE

Phase 1 domains are a convenience, not a boundary. In stdio mode that is
fine: there is one client and it is the operator. In SSE mode with a single
`SOPS_MCP_API_TOKEN`, every caller who has the token can name any domain
and therefore reach every private key the server holds.

If a shared SSE server is ever wanted, add:

```yaml
# in the domains file
tokens:
  - sha256: 9f86d081...        # sha256 of the bearer token, never the token
    domains: [homelab]
  - sha256: 2c26b46b...
    domains: [client-acme, archive]
```

- `SOPS_MCP_API_TOKEN` remains supported and grants all domains, for
  backward compatibility and single-tenant use.
- With a `tokens` block present, `handle_sse` resolves the caller's token
  to an allowed-domains set and attaches it to the session. Rule 4 in
  resolution gains a clause: a domain outside the allowed set is reported
  as unknown, identically to a domain that does not exist.
- `sops_list_domains` lists only the caller's allowed domains.
- Token comparison uses `hmac.compare_digest` on the hash, as the current
  bearer check should already.

Phase 2 is deliberately small because it reuses everything from phase 1.
It is out of scope until someone actually has two parties on one server.
Until then README and SECURITY state plainly that domains do not isolate
tenants.

## Security considerations

**Private keys at rest.** Today the private key lives in the process
environment, which is visible in `/proc/<pid>/environ` to the same uid and
in `docker inspect` to anyone with socket access. A domains file mounted
from a secrets store (`/run/secrets/...`) is an improvement for the Docker
image. For stdio use, the env var path stays available. SECURITY.md's
threat model gets a paragraph on the domains file: it is as sensitive as
the keys it holds, and the mode check at startup is a guard rail, not a
substitute for a proper secret mount.

**Key material in errors and logs.** `sops` writes to stderr on failure and
the server forwards `result.stderr` into `SopsError`. Audit the failure
paths once more when implementing: `sops` does not echo private keys, but
the per-call env now carries them, and a future `subprocess` debugging
aid must never log the environment.

**Metadata trust.** Better than the audit assumed. Every metadata field is
inside the MAC, so a tampered file cannot be decrypted at all — the
mutation tools, which all decrypt, are covered. The exposure that remains
is read-only: `sops_list_secrets` reports `source`, `description` and the
recorded domain without a key and therefore without verification. A
tampered file can mislead that listing, but any attempt to act on it
fails. This is worth restating in SECURITY.md rather than fixing.

**Enumeration.** Unknown-domain and mismatch errors count rather than list.
`sops_list_domains` is the only place recipients are listed, and in phase
2 it is scoped to the caller's domains.

**Encrypt-only domains.** A domain with recipients but no keys is useful
(a laptop that seeds secrets for CI) and safe: it can produce files it
cannot read, which is the current v1 posture when `SOPS_AGE_KEY` is unset.

## Backward compatibility

| v1 behaviour | After phase 1 |
|---|---|
| `SOPS_MCP_AGE_PUBLIC_KEY=age1...` | Becomes `default.recipients`. Unchanged. |
| `SOPS_MCP_AGE_PUBLIC_KEY=age1a,age1b` | Becomes a two-recipient `default`. Previously accidental, now supported. |
| `SOPS_AGE_KEY` in env | Becomes `default.keys`. Still read; no longer inherited by `sops` directly. |
| Files without `_meta_unencrypted.domain` | Resolve to `default`. Rule 5 still applies, so a v1 file encrypted to a different key than the server's `default` is now **refused** rather than silently rekeyed. |
| Tool calls without `domain` | Unchanged when only `default` exists. |

The last row is the only behaviour change a v1 user can hit, and it is the
bug fix. The error message points at `sops_rekey`. CHANGELOG entry goes
under a minor bump (0.11.0), not a patch.

## Implementation plan

Phase 1, in dependency order. Each step is a reviewable PR.

1. **`domains.py`**: `Domain` dataclass, config loading from env and file,
   validation, age recipient/key parsing. Unit tests for every fatal
   startup condition. No server change yet.
2. **`sops.py`**: `encrypt(data, domain)` / `decrypt(content, domain)` with
   per-call env construction. Add `recipients_of(encrypted_content)` that
   reads `sops.age[].recipient` without decrypting. Integration test:
   two domains, one file each, assert cross-domain decrypt fails and
   same-domain succeeds; assert `SOPS_AGE_KEY` in the parent env is
   ignored.
3. **`server.py`**: domain resolution helper, rule 5 check, `domain` input
   on every tool, `_meta_unencrypted.domain` write on create and retrofit.
   Integration test: mismatch refusal; metadata hint honoured; explicit
   `domain` arg overrides hint.
4. **New tools**: `sops_list_domains`, `sops_rekey`. Integration test:
   rekey after adding a recipient; rekey cannot cross domains.
5. **Docs**: README (env var table, new tools, a "Domains" section
   replacing the single-recipient caveat), SECURITY.md threat model,
   CLAUDE.md (drop the deferred note, add the rule 5 invariant to
   "Mutation rules"), CHANGELOG.

Phase 2 is a single PR on top: token table in config, session-scoped
allowed set, scoped `sops_list_domains`, docs.

## Open questions

- **Should `sops_rekey` require the caller to pass the recipient count it
  expects?** A `confirm_recipients: 3` argument would guard against a
  config edit the caller did not know about. Leaning no: the config is
  operator-controlled and the tool's description is explicit.
- **Should the default domain be nameable?** An operator with a domains
  file might prefer no `default` at all, forcing every call to be explicit.
  Leaning yes: `SOPS_MCP_REQUIRE_DOMAIN=1` makes rule 3 an error.
- **age plugin recipients** (`age1yubikey...`, `age1tpm...`) do not parse as
  X25519 and cannot have their private key validated at startup. Support
  would mean relaxing the validation in step 1 to "starts with `age1`" and
  skipping the key-to-recipient check. Not needed now; noting it so the
  regex in step 1 is not made stricter than necessary.
