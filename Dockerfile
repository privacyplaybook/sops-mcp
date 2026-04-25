# syntax=docker/dockerfile:1.7

# ---- build stage ----
# Wolfi-based image with apk + shell + build toolchain. Used to install
# Python deps into a venv and to source the sops + age binaries.
FROM cgr.dev/chainguard/python:latest-dev@sha256:2c0fbbac86b72ebb4bfee15b64d8cd5fd6b49dfe7bb279b5c9f193198a84c1c9 AS build

USER root

# sops and age come from Wolfi's apk repo, signed by Chainguard. Pinned
# transitively by the digest of the build base image.
RUN apk add --no-cache sops age

WORKDIR /app

# Build a self-contained venv at /opt/venv. Copying the venv (instead of
# pip-installing again in the runtime stage) keeps the runtime distroless.
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY requirements.lock.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock.txt

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir --no-deps .

# ---- runtime stage ----
# Distroless Wolfi Python. No shell, no apk, no package manager. Runs as
# the built-in `nonroot` user (uid 65532) by default.
FROM cgr.dev/chainguard/python:latest@sha256:18a4fbda8c280978b6aa5329f7acd4dbb106876e76fdc87913855ebf4876f2ff

COPY --from=build /usr/bin/sops /usr/bin/sops
COPY --from=build /usr/bin/age /usr/bin/age
COPY --from=build /usr/bin/age-keygen /usr/bin/age-keygen
COPY --from=build /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH
ENV SOPS_MCP_TRANSPORT=sse
ENV SOPS_MCP_HOST=0.0.0.0
ENV SOPS_MCP_PORT=55090
ENV SOPS_MCP_ALLOWED_HOSTS=localhost,localhost:*,127.0.0.1,127.0.0.1:*
EXPOSE 55090

# Container binds 0.0.0.0 by default, which means SOPS_MCP_API_TOKEN must be
# set at runtime — the server refuses to start otherwise. See README.
ENTRYPOINT ["/opt/venv/bin/sops-mcp"]
