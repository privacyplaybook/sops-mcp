# syntax=docker/dockerfile:1.7

# ---- build stage ----
# Wolfi-based image with apk + shell + build toolchain. Used to install
# Python deps into a venv and to source the sops + age binaries.
FROM cgr.dev/chainguard/python:latest-dev@sha256:64f414bffa25ca9ff518f35975ad153a921b2e4850c4a84c31a96885fdb86a02 AS build

USER root

# sops and age come from Wolfi's apk repo, signed by Chainguard. They are
# NOT pinned by the base digest: apk fetches the newest in the live repo at
# build time, so they move with every rebuild.
RUN apk add --no-cache sops age

# Upgrade the CA bundle to the newest in the live Wolfi repo, with a floor.
# The runtime stage copies this stage's bundle, since that stage has no apk.
# Like sops and age above, the result follows the build date, not the base
# digest. 20260909-r3 is the first bundle that no longer trusts emSign ECC
# Root CA - G3 (GHSA-6q48-6c7w-9gw2). The pinned bases (Python 3.15) already
# ship a later one; the floor stays so a future digest change can't bring the
# distrusted root back. lib/check_trust_store.py in the runtime stage is the
# gate either way.
RUN apk add --no-cache -u 'ca-certificates-bundle>=20260909-r3'

WORKDIR /app

# Build a self-contained venv at /opt/venv. Copying the venv (instead of
# pip-installing again in the runtime stage) keeps the runtime distroless.
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# Build tools first, hash-checked (requirements-build.lock.txt), so every
# sdist below builds with --no-build-isolation against them. Isolation would
# fetch the newest setuptools/Cython/hatchling from PyPI unpinned and
# unhashed. --only-binary :all: makes any other locked package that loses
# its wheel fail the build instead of silently compiling.
#
# pyyaml is the one sdist: 6.0.3 has no cp315 wheel. It builds without
# libyaml (this stage has no libyaml-dev), i.e. the pure-Python loader;
# sops-mcp only calls safe_load and dump. If a later base ships libyaml-dev,
# pyyaml builds its C extension instead, which is equally fine.
COPY requirements.lock.txt requirements-build.lock.txt ./
RUN pip install --no-cache-dir --require-hashes --only-binary :all: \
        -r requirements-build.lock.txt \
 && pip install --no-cache-dir --require-hashes --no-build-isolation \
        --only-binary :all: --no-binary pyyaml -r requirements.lock.txt

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir --no-deps --no-build-isolation . \
 && pip uninstall --yes -r requirements-build.lock.txt

# pip is not needed at runtime, and it vendors its own certifi bundle
# (pip/_vendor/certifi/cacert.pem), which would ship in /opt/venv with
# whatever roots that pip release trusted.
RUN python -m pip uninstall --yes pip

# ---- runtime stage ----
# Distroless Wolfi Python. No shell, no apk, no package manager. Runs as
# the built-in `nonroot` user (uid 65532) by default.
FROM cgr.dev/chainguard/python:latest@sha256:f3e5face39b0acd813fae456df27b33bf6a6bffba5d201d15f6498138cb8fd96

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
# /etc/ssl symlinks, certifi in the venv, or any other bundle or CApath
# entry under /usr/lib and /usr/share) still holds a distrusted root, or
# can't be read. The script is bind-mounted, so it doesn't ship in the
# image. Exec form: this stage has no shell.
RUN --mount=type=bind,source=lib/check_trust_store.py,target=/tmp/check_trust_store.py \
    ["/usr/bin/python3", "-I", "/tmp/check_trust_store.py", "/etc/ssl", "/opt/venv", "/usr/lib", "/usr/share"]

ENV PATH=/opt/venv/bin:$PATH
ENV SOPS_MCP_TRANSPORT=sse
ENV SOPS_MCP_HOST=0.0.0.0
ENV SOPS_MCP_PORT=55090
ENV SOPS_MCP_ALLOWED_HOSTS=localhost,localhost:*,127.0.0.1,127.0.0.1:*
EXPOSE 55090

# Container binds 0.0.0.0 by default, which means SOPS_MCP_API_TOKEN must be
# set at runtime — the server refuses to start otherwise. See README.
ENTRYPOINT ["/opt/venv/bin/sops-mcp"]
