# syntax=docker/dockerfile:1.7

# ---- build stage ----
# Wolfi-based image with apk + shell + build toolchain. Used to install
# Python deps into a venv and to source the sops + age binaries.
FROM cgr.dev/chainguard/python:latest-dev@sha256:2c0fbbac86b72ebb4bfee15b64d8cd5fd6b49dfe7bb279b5c9f193198a84c1c9 AS build

USER root

# sops and age come from Wolfi's apk repo, signed by Chainguard. Pinned
# transitively by the digest of the build base image.
RUN apk add --no-cache sops age

# Upgrade the CA bundle past the pinned base's. The runtime stage copies it,
# since that stage has no apk. 20260413-r0 in the pinned bases still trusts
# emSign ECC Root CA - G3 (GHSA-6q48-6c7w-9gw2); 20260909-r3 and later don't.
# The upstream rebuilds that dropped it moved to Python 3.15, so the digests
# stay put and the bundle is upgraded here instead.
RUN apk add --no-cache -u ca-certificates-bundle

WORKDIR /app

# Build a self-contained venv at /opt/venv. Copying the venv (instead of
# pip-installing again in the runtime stage) keeps the runtime distroless.
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY requirements.lock.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock.txt

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir --no-deps .

# pip is not needed at runtime, and it vendors its own certifi bundle
# (pip/_vendor/certifi/cacert.pem), which would ship in /opt/venv with
# whatever roots that pip release trusted.
RUN python -m pip uninstall --yes pip

# ---- runtime stage ----
# Distroless Wolfi Python. No shell, no apk, no package manager. Runs as
# the built-in `nonroot` user (uid 65532) by default.
FROM cgr.dev/chainguard/python:latest@sha256:18a4fbda8c280978b6aa5329f7acd4dbb106876e76fdc87913855ebf4876f2ff

# Anti-squatting annotation required by registry.modelcontextprotocol.io
# when an OCI image is referenced by a server.json submission. The label
# binds the published image to a registry namespace this repo owns.
LABEL io.modelcontextprotocol.server.name="io.github.privacyplaybook/sops-mcp"

COPY --from=build /usr/bin/sops /usr/bin/sops
COPY --from=build /usr/bin/age /usr/bin/age
COPY --from=build /usr/bin/age-keygen /usr/bin/age-keygen
COPY --from=build /opt/venv /opt/venv
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Fail the build if any trust store in this image (the OS bundle, its
# /etc/ssl symlinks, certifi in the venv, or any other bundle under the
# Python trees) still holds a distrusted root. The script is bind-mounted,
# so it doesn't ship in the image. Exec form: this stage has no shell.
RUN --mount=type=bind,source=lib/check_trust_store.py,target=/tmp/check_trust_store.py \
    ["/usr/bin/python3", "-I", "/tmp/check_trust_store.py", "/etc/ssl", "/opt/venv", "/usr/lib"]

ENV PATH=/opt/venv/bin:$PATH
ENV SOPS_MCP_TRANSPORT=sse
ENV SOPS_MCP_HOST=0.0.0.0
ENV SOPS_MCP_PORT=55090
ENV SOPS_MCP_ALLOWED_HOSTS=localhost,localhost:*,127.0.0.1,127.0.0.1:*
EXPOSE 55090

# Container binds 0.0.0.0 by default, which means SOPS_MCP_API_TOKEN must be
# set at runtime — the server refuses to start otherwise. See README.
ENTRYPOINT ["/opt/venv/bin/sops-mcp"]
