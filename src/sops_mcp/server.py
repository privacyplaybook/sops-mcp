"""MCP server for SOPS-encrypted secrets management."""

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Sequence

import yaml
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Mount, Route

from .secrets_derive import (
    TRANSFORMS,
    VALID_TRANSFORMS,
    dependents_of,
    derive_secret,
    topological_order,
)
from .secrets_generator import CHARSETS, generate_secret
from .sops import SopsEncryptor, SopsError

logger = logging.getLogger(__name__)

KEY_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")

VALID_SOURCES = ("generated", "external", "derived")
VALID_CHARSETS = tuple(CHARSETS.keys())


def _validate_key_name(name: str) -> None:
    if not KEY_NAME_PATTERN.match(name):
        raise ValueError(
            f"Invalid key name {name!r}. "
            "Must match ^[A-Z][A-Z0-9_]*$ (e.g. DB_PASSWORD)"
        )


SECRET_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "key_name": {
            "type": "string",
            "description": (
                "Environment variable name (e.g. DB_PASSWORD). "
                "Must match ^[A-Z][A-Z0-9_]*$"
            ),
        },
        "source": {
            "type": "string",
            "enum": list(VALID_SOURCES),
            "description": (
                "'generated' (random), 'external' (user-provided), "
                "or 'derived' (computed from another key via a transform)"
            ),
        },
        "value": {
            "type": "string",
            "description": "Plaintext value (required for external secrets)",
        },
        "length": {
            "type": "integer",
            "default": 32,
            "description": "Length for generated secrets (1-1024)",
        },
        "charset": {
            "type": "string",
            "enum": list(VALID_CHARSETS),
            "default": "alphanumeric",
            "description": "Character set for generated secrets",
        },
        "exclude_chars": {
            "type": "string",
            "description": "Characters to exclude from generation",
        },
        "transform": {
            "type": "string",
            "enum": list(VALID_TRANSFORMS),
            "description": (
                "Transform name for derived secrets. "
                "Available: " + ", ".join(
                    f"{name} ({spec['description']})"
                    for name, spec in TRANSFORMS.items()
                )
            ),
        },
        "from": {
            "type": "string",
            "description": (
                "Source key name for derived secrets. Must reference "
                "another key in this file (not itself a derived secret "
                "that depends on this one)."
            ),
        },
        "description": {
            "type": "string",
            "description": "Human-readable note",
        },
    },
    "required": ["key_name", "source"],
}


def _validate_secret_spec(spec: dict, known_keys: set[str]) -> None:
    """Validate a single secret spec. `known_keys` must include all keys that
    will exist in the final file (existing + newly added in this batch), so
    derived `from` references can be resolved."""
    key_name = spec["key_name"]
    source = spec["source"]
    _validate_key_name(key_name)
    if source not in VALID_SOURCES:
        raise ValueError(
            f"Invalid source {source!r} for {key_name}. "
            f"Must be one of: {', '.join(VALID_SOURCES)}"
        )
    if source == "external" and not spec.get("value"):
        raise ValueError(
            f"External secret {key_name} requires a 'value'"
        )
    if source == "derived":
        transform = spec.get("transform")
        if not transform:
            raise ValueError(
                f"Derived secret {key_name} requires 'transform'"
            )
        if transform not in VALID_TRANSFORMS:
            raise ValueError(
                f"Unknown transform {transform!r} for {key_name}. "
                f"Valid options: {', '.join(sorted(VALID_TRANSFORMS))}"
            )
        from_key = spec.get("from")
        if not from_key:
            raise ValueError(
                f"Derived secret {key_name} requires 'from'"
            )
        if from_key == key_name:
            raise ValueError(
                f"Derived secret {key_name} cannot reference itself"
            )
        if from_key not in known_keys:
            raise ValueError(
                f"Derived secret {key_name}: source key "
                f"{from_key!r} does not exist"
            )


def _build_meta_entry(spec: dict, now: str) -> dict[str, Any]:
    """Build the _meta_unencrypted entry for a newly-added secret."""
    source = spec["source"]
    entry: dict[str, Any] = {"source": source}
    if spec.get("description"):
        entry["description"] = spec["description"]
    if source == "generated":
        entry["generation"] = {
            "length": spec.get("length", 32),
            "charset": spec.get("charset", "alphanumeric"),
        }
        if spec.get("exclude_chars"):
            entry["generation"]["exclude_chars"] = spec["exclude_chars"]
        entry["last_rotated"] = now
    elif source == "derived":
        entry["derivation"] = {
            "transform": spec["transform"],
            "from": spec["from"],
        }
        entry["last_rotated"] = now
    return entry


def _compute_value(spec: dict, resolved: dict[str, str]) -> str:
    """Compute the plaintext value for a secret spec.

    For derived secrets, `resolved` must already contain the source value.
    """
    source = spec["source"]
    if source == "external":
        return spec["value"]
    if source == "generated":
        return generate_secret(
            spec.get("length", 32),
            spec.get("charset", "alphanumeric"),
            spec.get("exclude_chars", ""),
        )
    if source == "derived":
        return derive_secret(resolved[spec["from"]], spec["transform"])
    raise ValueError(f"Unknown source {source!r}")


def _process_batch(
    specs: list[dict],
    existing_values: dict[str, str],
    existing_meta: dict[str, dict],
    now: str,
) -> tuple[dict[str, str], dict[str, dict], list[str], list[str]]:
    """Process a batch of new secret specs.

    Validates the specs, orders derived ones topologically, computes values
    against a combined pool of existing + newly-added values, and returns
    (merged_values, merged_meta, generated_summary_lines, derived_plaintexts).

    `derived_plaintexts` is a list of "KEY = value" lines for each derived
    secret in this batch, so callers can surface them to the user.
    """
    new_keys = {s["key_name"] for s in specs}
    known_keys = set(existing_values.keys()) | new_keys

    for spec in specs:
        _validate_secret_spec(spec, known_keys)

    spec_by_key = {s["key_name"]: s for s in specs}

    # Build a topological order of keys in this batch: generated/external
    # first, then derived, ordered so each derived key's source precedes it.
    ordered: list[str] = []
    pending_derived: dict[str, str] = {}
    resolved: dict[str, str] = dict(existing_values)

    for spec in specs:
        if spec["source"] != "derived":
            ordered.append(spec["key_name"])

    for spec in specs:
        if spec["source"] == "derived":
            pending_derived[spec["key_name"]] = spec["from"]

    # Compute non-derived values first.
    for key in ordered:
        resolved[key] = _compute_value(spec_by_key[key], resolved)

    # Iteratively resolve derived values.
    while pending_derived:
        progressed = False
        for key in list(pending_derived):
            src = pending_derived[key]
            if src in resolved:
                resolved[key] = _compute_value(spec_by_key[key], resolved)
                ordered.append(key)
                del pending_derived[key]
                progressed = True
        if not progressed:
            raise ValueError(
                "Circular or unresolvable derivations in batch: "
                + ", ".join(f"{k}->{src}" for k, src in pending_derived.items())
            )

    merged_meta = dict(existing_meta)
    for spec in specs:
        merged_meta[spec["key_name"]] = _build_meta_entry(spec, now)

    summary: list[str] = []
    derived_plaintexts: list[str] = []
    for spec in specs:
        key = spec["key_name"]
        meta = merged_meta[key]
        source = meta["source"]
        desc = meta.get("description", "")
        desc_str = f" - {desc}" if desc else ""
        if source == "generated":
            gen = meta["generation"]
            summary.append(
                f"  {key}: generated "
                f"({gen['length']} chars, {gen['charset']}){desc_str}"
            )
        elif source == "derived":
            deriv = meta["derivation"]
            summary.append(
                f"  {key}: derived "
                f"({deriv['transform']} of {deriv['from']}){desc_str}"
            )
            derived_plaintexts.append(f"{key} = {resolved[key]}")
        else:
            summary.append(f"  {key}: external{desc_str}")

    return resolved, merged_meta, summary, derived_plaintexts


class SopsMcpServer:
    """MCP server that creates and manages SOPS-encrypted secrets."""

    def __init__(self, encryptor: SopsEncryptor):
        self.encryptor = encryptor
        self.server = Server("sops-mcp")
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="sops_create_secrets",
                    description=(
                        "Generate and encrypt secrets as SOPS YAML. "
                        "Returns encrypted content for the client to write "
                        "to disk. Supports three sources: 'generated' "
                        "(cryptographic randomness), 'external' "
                        "(user-provided values), and 'derived' (computed "
                        "from another key in the same file via a transform "
                        "such as pbkdf2_sha512_authelia). Derived secret "
                        "plaintexts are returned in the response so they "
                        "can be copied into config files."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "secrets": {
                                "type": "array",
                                "description": "List of secrets to create",
                                "items": SECRET_ITEM_SCHEMA,
                            },
                        },
                        "required": ["secrets"],
                    },
                ),
                Tool(
                    name="sops_list_secrets",
                    description=(
                        "List key names and metadata from a SOPS-encrypted file. "
                        "No decryption needed — reads key names from encrypted "
                        "YAML and metadata from the _meta_unencrypted block."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "encrypted_content": {
                                "type": "string",
                                "description": (
                                    "Contents of a secrets.enc.yaml file"
                                ),
                            },
                        },
                        "required": ["encrypted_content"],
                    },
                ),
                Tool(
                    name="sops_rotate_generated",
                    description=(
                        "Re-generate 'generated' secrets with new random values "
                        "while preserving 'external' secrets. Requires "
                        "SOPS_AGE_KEY env var for decryption."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "encrypted_content": {
                                "type": "string",
                                "description": (
                                    "Contents of an existing secrets.enc.yaml file"
                                ),
                            },
                        },
                        "required": ["encrypted_content"],
                    },
                ),
                Tool(
                    name="sops_add_secrets",
                    description=(
                        "Add new secrets to an existing SOPS-encrypted file. "
                        "Decrypts the file, merges in new secrets, and "
                        "re-encrypts — preserving all existing values and "
                        "metadata. Rejects keys that already exist in the "
                        "file. Supports generated, external, and derived "
                        "sources. Requires SOPS_AGE_KEY env var."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "encrypted_content": {
                                "type": "string",
                                "description": (
                                    "Contents of an existing secrets.enc.yaml file"
                                ),
                            },
                            "secrets": {
                                "type": "array",
                                "description": "New secrets to add",
                                "items": SECRET_ITEM_SCHEMA,
                            },
                        },
                        "required": ["encrypted_content", "secrets"],
                    },
                ),
                Tool(
                    name="sops_add_metadata",
                    description=(
                        "Add _meta_unencrypted metadata to an existing "
                        "SOPS-encrypted file that lacks it. Decrypts the "
                        "file, adds metadata, and re-encrypts preserving "
                        "original plaintext values. Requires SOPS_AGE_KEY "
                        "env var for decryption."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "encrypted_content": {
                                "type": "string",
                                "description": (
                                    "Contents of a secrets.enc.yaml file"
                                ),
                            },
                            "secret_metadata": {
                                "type": "object",
                                "description": (
                                    "Mapping of key names to metadata. "
                                    "Each value has 'source' "
                                    "('generated', 'external', or "
                                    "'derived') and optional "
                                    "'description'. For 'derived', also "
                                    "provide 'transform' and 'from'."
                                ),
                                "additionalProperties": {
                                    "type": "object",
                                    "properties": {
                                        "source": {
                                            "type": "string",
                                            "enum": list(VALID_SOURCES),
                                        },
                                        "description": {
                                            "type": "string",
                                        },
                                        "transform": {
                                            "type": "string",
                                            "enum": list(VALID_TRANSFORMS),
                                        },
                                        "from": {
                                            "type": "string",
                                        },
                                    },
                                    "required": ["source"],
                                },
                            },
                        },
                        "required": ["encrypted_content", "secret_metadata"],
                    },
                ),
                Tool(
                    name="sops_delete_secrets",
                    description=(
                        "Delete one or more keys from an existing "
                        "SOPS-encrypted file. Removes both the encrypted "
                        "value and the _meta_unencrypted entry. Rejects "
                        "deletion of keys that other derived secrets "
                        "depend on unless those dependents are also in "
                        "the delete list. Requires SOPS_AGE_KEY env var."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "encrypted_content": {
                                "type": "string",
                                "description": (
                                    "Contents of an existing "
                                    "secrets.enc.yaml file"
                                ),
                            },
                            "key_names": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Keys to delete",
                            },
                        },
                        "required": ["encrypted_content", "key_names"],
                    },
                ),
                Tool(
                    name="sops_rename_secret",
                    description=(
                        "Rename a key in an existing SOPS-encrypted "
                        "file. Preserves the value, source type, and "
                        "metadata. Updates 'from' references in any "
                        "derived secrets that depend on the renamed "
                        "key. Requires SOPS_AGE_KEY env var."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "encrypted_content": {
                                "type": "string",
                                "description": (
                                    "Contents of an existing "
                                    "secrets.enc.yaml file"
                                ),
                            },
                            "old_name": {
                                "type": "string",
                                "description": "Current key name",
                            },
                            "new_name": {
                                "type": "string",
                                "description": (
                                    "New key name (must match "
                                    "^[A-Z][A-Z0-9_]*$ and not collide "
                                    "with an existing key)"
                                ),
                            },
                        },
                        "required": [
                            "encrypted_content", "old_name", "new_name",
                        ],
                    },
                ),
                Tool(
                    name="sops_update_external",
                    description=(
                        "Replace the value of an 'external' secret "
                        "(e.g. after the user rotated an upstream API "
                        "key). Rejects attempts to update 'generated' "
                        "or 'derived' secrets — use sops_rotate_generated "
                        "for those. Recomputes any derived secrets that "
                        "reference this key. Requires SOPS_AGE_KEY env var."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "encrypted_content": {
                                "type": "string",
                                "description": (
                                    "Contents of an existing "
                                    "secrets.enc.yaml file"
                                ),
                            },
                            "key_name": {
                                "type": "string",
                                "description": "Key to update",
                            },
                            "value": {
                                "type": "string",
                                "description": "New plaintext value",
                            },
                        },
                        "required": [
                            "encrypted_content", "key_name", "value",
                        ],
                    },
                ),
                Tool(
                    name="sops_create_oidc_secret",
                    description=(
                        "Convenience tool: create an Authelia-compatible "
                        "OIDC client secret. Generates KEY_NAME as a "
                        "64-char alphanumeric 'generated' secret AND "
                        "KEY_NAME_HASH as a 'derived' PBKDF2-SHA512 hash "
                        "of it, stored together in a new encrypted file. "
                        "The hash is returned in the response for pasting "
                        "into Authelia's configuration.yml. Equivalent to "
                        "calling sops_create_secrets with one generated "
                        "and one derived (pbkdf2_sha512_authelia) entry."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "key_name": {
                                "type": "string",
                                "description": (
                                    "Base name for the plaintext secret "
                                    "(e.g. GRAFANA_OIDC_CLIENT_SECRET). "
                                    "The hash will be stored as "
                                    "KEY_NAME_HASH. Must match "
                                    "^[A-Z][A-Z0-9_]*$."
                                ),
                            },
                            "description": {
                                "type": "string",
                                "description": (
                                    "Human-readable note "
                                    "(e.g. 'OIDC client secret for Grafana')"
                                ),
                            },
                        },
                        "required": ["key_name"],
                    },
                ),
            ]

        @self.server.call_tool()
        async def call_tool(
            name: str, arguments: dict[str, Any]
        ) -> Sequence[TextContent]:
            try:
                if name == "sops_create_secrets":
                    return await self._create_secrets(arguments)
                elif name == "sops_list_secrets":
                    return await self._list_secrets(arguments)
                elif name == "sops_rotate_generated":
                    return await self._rotate_generated(arguments)
                elif name == "sops_add_secrets":
                    return await self._add_secrets(arguments)
                elif name == "sops_add_metadata":
                    return await self._add_metadata(arguments)
                elif name == "sops_delete_secrets":
                    return await self._delete_secrets(arguments)
                elif name == "sops_rename_secret":
                    return await self._rename_secret(arguments)
                elif name == "sops_update_external":
                    return await self._update_external(arguments)
                elif name == "sops_create_oidc_secret":
                    return await self._create_oidc_secret(arguments)
                else:
                    return [TextContent(type="text", text=f"Unknown tool: {name}")]
            except (ValueError, SopsError) as e:
                return [TextContent(type="text", text=f"Error: {e}")]
            except Exception as e:
                logger.exception("Unexpected error handling %s", name)
                return [TextContent(type="text", text=f"Internal error: {e}")]

    async def _create_secrets(
        self, arguments: dict[str, Any]
    ) -> Sequence[TextContent]:
        secrets_list = arguments.get("secrets", [])
        if not secrets_list:
            raise ValueError("No secrets provided")

        now = datetime.now(timezone.utc).isoformat()
        resolved, meta_secrets, summary, derived_plaintexts = _process_batch(
            secrets_list,
            existing_values={},
            existing_meta={},
            now=now,
        )

        data: dict[str, Any] = {k: v for k, v in resolved.items()}
        data["_meta_unencrypted"] = {"version": 1, "secrets": meta_secrets}

        encrypted_yaml = self.encryptor.encrypt(data)

        summary_lines = ["Created secrets:"] + summary
        responses = [
            TextContent(type="text", text=encrypted_yaml),
            TextContent(type="text", text="\n".join(summary_lines)),
        ]
        if derived_plaintexts:
            responses.append(
                TextContent(
                    type="text",
                    text=(
                        "Derived plaintexts (copy these into your "
                        "application config if needed):\n"
                        + "\n".join(derived_plaintexts)
                    ),
                )
            )
        return responses

    async def _list_secrets(
        self, arguments: dict[str, Any]
    ) -> Sequence[TextContent]:
        content = arguments.get("encrypted_content", "")
        if not content:
            raise ValueError("No encrypted content provided")

        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Content is not valid YAML")

        meta = parsed.get("_meta_unencrypted", {})
        meta_secrets = meta.get("secrets", {}) if isinstance(meta, dict) else {}

        secret_keys = [
            k for k in parsed
            if k != "sops" and not k.startswith("_")
        ]

        lines = ["Secrets in file:"]
        lines.append(f"{'Key':<30} {'Source':<12} {'Description'}")
        lines.append("-" * 70)

        for key in secret_keys:
            info = meta_secrets.get(key, {})
            source = info.get("source", "unknown")
            desc = info.get("description", "")
            lines.append(f"{key:<30} {source:<12} {desc}")

        if not secret_keys:
            lines.append("  (no secret keys found)")

        return [TextContent(type="text", text="\n".join(lines))]

    async def _rotate_generated(
        self, arguments: dict[str, Any]
    ) -> Sequence[TextContent]:
        content = arguments.get("encrypted_content", "")
        if not content:
            raise ValueError("No encrypted content provided")

        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Content is not valid YAML")

        meta = parsed.get("_meta_unencrypted", {})
        meta_secrets = meta.get("secrets", {}) if isinstance(meta, dict) else {}

        if not meta_secrets:
            raise ValueError(
                "No _meta_unencrypted block found. "
                "Cannot determine which secrets to rotate."
            )

        decrypted = self.encryptor.decrypt(content)

        now = datetime.now(timezone.utc).isoformat()
        new_data: dict[str, Any] = {}
        rotated: list[str] = []
        recomputed: list[str] = []
        preserved: list[str] = []
        derived_plaintexts: list[str] = []

        order = topological_order(meta_secrets)
        changed: set[str] = set()

        for key in order:
            info = meta_secrets.get(key, {})
            source = info.get("source")
            if source == "generated":
                gen = info.get("generation", {})
                length = gen.get("length", 32)
                charset = gen.get("charset", "alphanumeric")
                exclude_chars = gen.get("exclude_chars", "")
                new_data[key] = generate_secret(length, charset, exclude_chars)
                info["last_rotated"] = now
                rotated.append(key)
                changed.add(key)
            elif source == "derived":
                derivation = info.get("derivation", {})
                transform = derivation.get("transform")
                source_key = derivation.get("from")
                if not transform or not source_key:
                    raise ValueError(
                        f"Derived secret {key!r} has incomplete derivation "
                        "metadata"
                    )
                if source_key in changed:
                    if source_key not in new_data:
                        raise ValueError(
                            f"Derived secret {key!r} references missing "
                            f"source {source_key!r}"
                        )
                    new_data[key] = derive_secret(
                        new_data[source_key], transform
                    )
                    info["last_rotated"] = now
                    recomputed.append(key)
                    changed.add(key)
                    derived_plaintexts.append(f"{key} = {new_data[key]}")
                else:
                    if key not in decrypted:
                        raise ValueError(
                            f"Derived secret {key!r} is in metadata but "
                            "missing from encrypted file"
                        )
                    new_data[key] = decrypted[key]
                    preserved.append(key)
            else:
                if key not in decrypted:
                    raise ValueError(
                        f"External secret {key!r} is in metadata but "
                        "missing from encrypted file"
                    )
                new_data[key] = decrypted[key]
                preserved.append(key)

        new_data["_meta_unencrypted"] = {
            "version": meta.get("version", 1),
            "secrets": meta_secrets,
        }

        encrypted_yaml = self.encryptor.encrypt(new_data)

        summary_lines = ["Rotation complete:"]
        if rotated:
            summary_lines.append(f"  Rotated: {', '.join(rotated)}")
        if recomputed:
            summary_lines.append(f"  Recomputed (derived): {', '.join(recomputed)}")
        if preserved:
            summary_lines.append(f"  Preserved: {', '.join(preserved)}")

        responses = [
            TextContent(type="text", text=encrypted_yaml),
            TextContent(type="text", text="\n".join(summary_lines)),
        ]
        if derived_plaintexts:
            responses.append(
                TextContent(
                    type="text",
                    text=(
                        "Derived plaintexts (update any config files "
                        "that reference these):\n"
                        + "\n".join(derived_plaintexts)
                    ),
                )
            )
        return responses

    async def _add_secrets(
        self, arguments: dict[str, Any]
    ) -> Sequence[TextContent]:
        content = arguments.get("encrypted_content", "")
        if not content:
            raise ValueError("No encrypted content provided")

        secrets_list = arguments.get("secrets", [])
        if not secrets_list:
            raise ValueError("No secrets provided")

        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Content is not valid YAML")

        meta = parsed.get("_meta_unencrypted", {})
        meta_secrets = meta.get("secrets", {}) if isinstance(meta, dict) else {}

        existing_keys = {
            k for k in parsed if k != "sops" and not k.startswith("_")
        }

        new_key_names = [s["key_name"] for s in secrets_list]
        collisions = set(new_key_names) & existing_keys
        if collisions:
            raise ValueError(
                f"Keys already exist in file: {', '.join(sorted(collisions))}. "
                "Use sops_rotate_generated or sops_update_external to change "
                "existing secrets."
            )

        decrypted = self.encryptor.decrypt(content)

        existing_values = {
            k: v for k, v in decrypted.items() if not k.startswith("_")
        }
        preserved = list(existing_values.keys())

        now = datetime.now(timezone.utc).isoformat()
        resolved, merged_meta, summary, derived_plaintexts = _process_batch(
            secrets_list,
            existing_values=existing_values,
            existing_meta=dict(meta_secrets),
            now=now,
        )

        new_data: dict[str, Any] = {k: v for k, v in resolved.items()}
        new_data["_meta_unencrypted"] = {
            "version": meta.get("version", 1) if isinstance(meta, dict) else 1,
            "secrets": merged_meta,
        }

        encrypted_yaml = self.encryptor.encrypt(new_data)

        summary_lines = ["Secrets added:"] + summary
        if preserved:
            summary_lines.append(f"Preserved: {', '.join(preserved)}")

        responses = [
            TextContent(type="text", text=encrypted_yaml),
            TextContent(type="text", text="\n".join(summary_lines)),
        ]
        if derived_plaintexts:
            responses.append(
                TextContent(
                    type="text",
                    text=(
                        "Derived plaintexts (copy these into your "
                        "application config if needed):\n"
                        + "\n".join(derived_plaintexts)
                    ),
                )
            )
        return responses

    async def _add_metadata(
        self, arguments: dict[str, Any]
    ) -> Sequence[TextContent]:
        content = arguments.get("encrypted_content", "")
        if not content:
            raise ValueError("No encrypted content provided")

        secret_metadata = arguments.get("secret_metadata", {})
        if not secret_metadata:
            raise ValueError("No secret_metadata provided")

        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Content is not valid YAML")

        if "_meta_unencrypted" in parsed:
            raise ValueError(
                "File already has _meta_unencrypted block. "
                "Use sops_rotate_generated or sops_create_secrets instead."
            )

        file_keys = sorted(
            k for k in parsed if k != "sops" and not k.startswith("_")
        )
        meta_keys = sorted(secret_metadata.keys())

        if file_keys != meta_keys:
            missing_from_meta = set(file_keys) - set(meta_keys)
            extra_in_meta = set(meta_keys) - set(file_keys)
            parts = []
            if missing_from_meta:
                parts.append(
                    f"Keys in file but not in metadata: "
                    f"{', '.join(sorted(missing_from_meta))}"
                )
            if extra_in_meta:
                parts.append(
                    f"Keys in metadata but not in file: "
                    f"{', '.join(sorted(extra_in_meta))}"
                )
            raise ValueError(
                f"Key mismatch between file and metadata. {'; '.join(parts)}"
            )

        known_keys = set(secret_metadata.keys())
        for key_name, meta in secret_metadata.items():
            _validate_key_name(key_name)
            source = meta.get("source")
            if source not in VALID_SOURCES:
                raise ValueError(
                    f"Invalid source {source!r} for {key_name}. "
                    f"Must be one of: {', '.join(VALID_SOURCES)}"
                )
            if source == "derived":
                transform = meta.get("transform")
                from_key = meta.get("from")
                if not transform:
                    raise ValueError(
                        f"Derived metadata for {key_name} requires 'transform'"
                    )
                if transform not in VALID_TRANSFORMS:
                    raise ValueError(
                        f"Unknown transform {transform!r} for {key_name}"
                    )
                if not from_key:
                    raise ValueError(
                        f"Derived metadata for {key_name} requires 'from'"
                    )
                if from_key == key_name:
                    raise ValueError(
                        f"Derived secret {key_name} cannot reference itself"
                    )
                if from_key not in known_keys:
                    raise ValueError(
                        f"Derived metadata for {key_name}: source "
                        f"{from_key!r} is not in the file"
                    )

        decrypted = self.encryptor.decrypt(content)

        now = datetime.now(timezone.utc).isoformat()
        meta_secrets = {}
        for key_name, meta in secret_metadata.items():
            source = meta["source"]
            entry: dict[str, Any] = {"source": source}
            if meta.get("description"):
                entry["description"] = meta["description"]
            if source == "generated":
                entry["generation"] = {
                    "length": 32,
                    "charset": "alphanumeric",
                }
                entry["last_rotated"] = now
            elif source == "derived":
                entry["derivation"] = {
                    "transform": meta["transform"],
                    "from": meta["from"],
                }
                entry["last_rotated"] = now
            meta_secrets[key_name] = entry

        new_data = {}
        for key in decrypted:
            if key.startswith("_"):
                continue
            new_data[key] = decrypted[key]

        new_data["_meta_unencrypted"] = {
            "version": 1,
            "secrets": meta_secrets,
        }

        encrypted_yaml = self.encryptor.encrypt(new_data)

        summary_lines = ["Added metadata:"]
        for key_name, entry in meta_secrets.items():
            source = entry["source"]
            desc = entry.get("description", "")
            desc_str = f" - {desc}" if desc else ""
            summary_lines.append(f"  {key_name}: {source}{desc_str}")

        return [
            TextContent(type="text", text=encrypted_yaml),
            TextContent(type="text", text="\n".join(summary_lines)),
        ]

    async def _create_oidc_secret(
        self, arguments: dict[str, Any]
    ) -> Sequence[TextContent]:
        key_name = arguments.get("key_name", "")
        if not key_name:
            raise ValueError("key_name is required")
        _validate_key_name(key_name)

        description = arguments.get("description", "")
        hash_key = f"{key_name}_HASH"

        base_spec: dict[str, Any] = {
            "key_name": key_name,
            "source": "generated",
            "length": 64,
            "charset": "alphanumeric",
        }
        hash_spec: dict[str, Any] = {
            "key_name": hash_key,
            "source": "derived",
            "transform": "pbkdf2_sha512_authelia",
            "from": key_name,
        }
        if description:
            base_spec["description"] = description
            hash_spec["description"] = f"{description} (Authelia hash)"

        return await self._create_secrets({"secrets": [base_spec, hash_spec]})

    async def _delete_secrets(
        self, arguments: dict[str, Any]
    ) -> Sequence[TextContent]:
        content = arguments.get("encrypted_content", "")
        if not content:
            raise ValueError("No encrypted content provided")

        key_names = arguments.get("key_names") or []
        if not key_names:
            raise ValueError("No key_names provided")

        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Content is not valid YAML")

        existing_keys = {
            k for k in parsed if k != "sops" and not k.startswith("_")
        }
        missing = [k for k in key_names if k not in existing_keys]
        if missing:
            raise ValueError(
                f"Keys not found in file: {', '.join(sorted(missing))}"
            )

        meta = parsed.get("_meta_unencrypted", {})
        meta_secrets = meta.get("secrets", {}) if isinstance(meta, dict) else {}

        to_delete = set(key_names)
        for key in key_names:
            dependents = dependents_of(meta_secrets, key)
            unresolved = [d for d in dependents if d not in to_delete]
            if unresolved:
                raise ValueError(
                    f"Cannot delete {key!r}: derived secret(s) "
                    f"{', '.join(sorted(unresolved))} depend on it. "
                    "Delete them in the same call or drop the derivation "
                    "first."
                )

        decrypted = self.encryptor.decrypt(content)

        new_data: dict[str, Any] = {}
        for key, value in decrypted.items():
            if key.startswith("_"):
                continue
            if key in to_delete:
                continue
            new_data[key] = value

        new_meta = {
            k: v for k, v in meta_secrets.items() if k not in to_delete
        }
        new_data["_meta_unencrypted"] = {
            "version": meta.get("version", 1) if isinstance(meta, dict) else 1,
            "secrets": new_meta,
        }

        encrypted_yaml = self.encryptor.encrypt(new_data)

        summary = f"Deleted: {', '.join(sorted(to_delete))}"
        return [
            TextContent(type="text", text=encrypted_yaml),
            TextContent(type="text", text=summary),
        ]

    async def _rename_secret(
        self, arguments: dict[str, Any]
    ) -> Sequence[TextContent]:
        content = arguments.get("encrypted_content", "")
        if not content:
            raise ValueError("No encrypted content provided")

        old_name = arguments.get("old_name", "")
        new_name = arguments.get("new_name", "")
        if not old_name or not new_name:
            raise ValueError("old_name and new_name are required")
        _validate_key_name(new_name)
        if old_name == new_name:
            raise ValueError("old_name and new_name are identical")

        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Content is not valid YAML")

        existing_keys = {
            k for k in parsed if k != "sops" and not k.startswith("_")
        }
        if old_name not in existing_keys:
            raise ValueError(f"Key {old_name!r} not found in file")
        if new_name in existing_keys:
            raise ValueError(
                f"Key {new_name!r} already exists in file"
            )

        meta = parsed.get("_meta_unencrypted", {})
        meta_secrets = meta.get("secrets", {}) if isinstance(meta, dict) else {}

        decrypted = self.encryptor.decrypt(content)

        new_data: dict[str, Any] = {}
        for key, value in decrypted.items():
            if key.startswith("_"):
                continue
            target_key = new_name if key == old_name else key
            new_data[target_key] = value

        new_meta: dict[str, Any] = {}
        dependents_updated: list[str] = []
        for key, entry in meta_secrets.items():
            target_key = new_name if key == old_name else key
            if (
                isinstance(entry, dict)
                and entry.get("source") == "derived"
                and (entry.get("derivation") or {}).get("from") == old_name
            ):
                updated = dict(entry)
                updated["derivation"] = dict(entry["derivation"])
                updated["derivation"]["from"] = new_name
                new_meta[target_key] = updated
                if target_key != old_name:
                    dependents_updated.append(target_key)
            else:
                new_meta[target_key] = entry

        new_data["_meta_unencrypted"] = {
            "version": meta.get("version", 1) if isinstance(meta, dict) else 1,
            "secrets": new_meta,
        }

        encrypted_yaml = self.encryptor.encrypt(new_data)

        summary_lines = [f"Renamed {old_name} -> {new_name}"]
        if dependents_updated:
            summary_lines.append(
                "Updated derivation references in: "
                + ", ".join(sorted(dependents_updated))
            )

        return [
            TextContent(type="text", text=encrypted_yaml),
            TextContent(type="text", text="\n".join(summary_lines)),
        ]

    async def _update_external(
        self, arguments: dict[str, Any]
    ) -> Sequence[TextContent]:
        content = arguments.get("encrypted_content", "")
        if not content:
            raise ValueError("No encrypted content provided")

        key_name = arguments.get("key_name", "")
        if not key_name:
            raise ValueError("key_name is required")
        new_value = arguments.get("value")
        if new_value is None or new_value == "":
            raise ValueError("value is required")

        parsed = yaml.safe_load(content)
        if not isinstance(parsed, dict):
            raise ValueError("Content is not valid YAML")

        existing_keys = {
            k for k in parsed if k != "sops" and not k.startswith("_")
        }
        if key_name not in existing_keys:
            raise ValueError(f"Key {key_name!r} not found in file")

        meta = parsed.get("_meta_unencrypted", {})
        meta_secrets = meta.get("secrets", {}) if isinstance(meta, dict) else {}
        info = meta_secrets.get(key_name, {})
        source = info.get("source") if isinstance(info, dict) else None

        if source != "external":
            raise ValueError(
                f"Cannot update {key_name!r}: source is {source!r}, "
                "not 'external'. Use sops_rotate_generated for generated "
                "or derived secrets."
            )

        decrypted = self.encryptor.decrypt(content)

        now = datetime.now(timezone.utc).isoformat()
        new_data: dict[str, Any] = {}
        for key, value in decrypted.items():
            if key.startswith("_"):
                continue
            new_data[key] = new_value if key == key_name else value

        info = dict(info)
        info["last_rotated"] = now
        meta_secrets = dict(meta_secrets)
        meta_secrets[key_name] = info

        recomputed: list[str] = []
        derived_plaintexts: list[str] = []
        order = topological_order(meta_secrets)
        changed = {key_name}
        for k in order:
            entry = meta_secrets.get(k, {})
            if not isinstance(entry, dict) or entry.get("source") != "derived":
                continue
            derivation = entry.get("derivation") or {}
            src = derivation.get("from")
            if src in changed:
                transform = derivation.get("transform")
                if not transform:
                    raise ValueError(
                        f"Derived secret {k!r} missing transform"
                    )
                new_data[k] = derive_secret(new_data[src], transform)
                entry = dict(entry)
                entry["last_rotated"] = now
                meta_secrets[k] = entry
                changed.add(k)
                recomputed.append(k)
                derived_plaintexts.append(f"{k} = {new_data[k]}")

        new_data["_meta_unencrypted"] = {
            "version": meta.get("version", 1) if isinstance(meta, dict) else 1,
            "secrets": meta_secrets,
        }

        encrypted_yaml = self.encryptor.encrypt(new_data)

        summary_lines = [f"Updated external secret: {key_name}"]
        if recomputed:
            summary_lines.append(
                "Recomputed (derived): " + ", ".join(recomputed)
            )

        responses = [
            TextContent(type="text", text=encrypted_yaml),
            TextContent(type="text", text="\n".join(summary_lines)),
        ]
        if derived_plaintexts:
            responses.append(
                TextContent(
                    type="text",
                    text=(
                        "Derived plaintexts (update any config files "
                        "that reference these):\n"
                        + "\n".join(derived_plaintexts)
                    ),
                )
            )
        return responses

    async def run(self) -> None:
        """Run the server with stdio transport."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )

    async def run_sse(
        self,
        host: str = "127.0.0.1",
        port: int = 55090,
        allowed_hosts: list[str] | None = None,
    ) -> None:
        """Run the server with SSE transport over HTTP.

        DNS rebinding protection is always enabled: the SseServerTransport is
        constructed with TransportSecuritySettings that validate the Host
        header against `allowed_hosts`. When `allowed_hosts` is None, the
        default is loopback only.
        """
        import uvicorn
        from mcp.server.sse import SseServerTransport
        from mcp.server.transport_security import TransportSecuritySettings

        if allowed_hosts is None:
            allowed_hosts = [
                "127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*",
            ]
        security_settings = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[],
        )
        sse = SseServerTransport(
            "/messages/", security_settings=security_settings,
        )
        api_token = os.environ.get("SOPS_MCP_API_TOKEN")

        async def handle_sse(request: Request) -> Response:
            if api_token and request.headers.get(
                "authorization"
            ) != f"Bearer {api_token}":
                return PlainTextResponse("Unauthorized", status_code=401)
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options(),
                    stateless=True,
                )
            return Response()

        async def handle_messages(
            scope: Any, receive: Any, send: Any
        ) -> None:
            if api_token:
                from starlette.datastructures import Headers

                headers = Headers(scope=scope)
                if headers.get("authorization") != f"Bearer {api_token}":
                    response = PlainTextResponse(
                        "Unauthorized", status_code=401
                    )
                    await response(scope, receive, send)
                    return
            await sse.handle_post_message(scope, receive, send)

        async def health(request: Request) -> PlainTextResponse:
            return PlainTextResponse("ok")

        app = Starlette(
            routes=[
                Route("/health", health, methods=["GET"]),
                Route("/sse", handle_sse, methods=["GET"]),
                Mount("/messages/", app=handle_messages),
            ],
        )

        config = uvicorn.Config(app, host=host, port=port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()


def create_server() -> SopsMcpServer:
    """Create a server from environment variables."""
    age_public_key = (
        os.environ.get("SOPS_MCP_AGE_PUBLIC_KEY")
        or os.environ.get("SOPS_AGE_RECIPIENTS")
    )
    if not age_public_key:
        raise RuntimeError(
            "Age public key required. "
            "Set SOPS_MCP_AGE_PUBLIC_KEY or SOPS_AGE_RECIPIENTS."
        )

    sops_binary = os.environ.get("SOPS_MCP_SOPS_BINARY", "sops")
    encryptor = SopsEncryptor(age_public_key, sops_binary)

    return SopsMcpServer(encryptor)


def main() -> None:
    """Entry point."""
    transport = os.environ.get("SOPS_MCP_TRANSPORT", "stdio")
    log_level = os.environ.get("SOPS_MCP_LOG_LEVEL", "WARNING")
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.WARNING),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    server = create_server()

    if transport == "sse":
        host = os.environ.get("SOPS_MCP_HOST", "127.0.0.1")
        port = int(os.environ.get("SOPS_MCP_PORT", "55090"))
        api_token = os.environ.get("SOPS_MCP_API_TOKEN")
        if host == "0.0.0.0" and not api_token:
            raise RuntimeError(
                "Refusing to bind the SSE transport to 0.0.0.0 without "
                "SOPS_MCP_API_TOKEN. Either set the token, bind to "
                "127.0.0.1, or place the server behind an authenticating "
                "reverse proxy."
            )
        allowed_hosts_env = os.environ.get("SOPS_MCP_ALLOWED_HOSTS", "").strip()
        allowed_hosts: list[str] | None = None
        if allowed_hosts_env:
            allowed_hosts = [
                h.strip() for h in allowed_hosts_env.split(",") if h.strip()
            ]
        elif host != "127.0.0.1":
            logger.warning(
                "SOPS_MCP_HOST=%s but SOPS_MCP_ALLOWED_HOSTS is unset; "
                "falling back to loopback-only allowed_hosts. Clients whose "
                "Host header is not 127.0.0.1/localhost will be rejected. "
                "Set SOPS_MCP_ALLOWED_HOSTS (comma-separated) to match your "
                "deployment's expected Host header(s).",
                host,
            )
        asyncio.run(
            server.run_sse(host=host, port=port, allowed_hosts=allowed_hosts)
        )
    else:
        asyncio.run(server.run())
