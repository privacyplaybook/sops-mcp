FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4

# Install sops and age binaries with checksum verification
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    curl -fsSL -o /usr/local/bin/sops \
      https://github.com/getsops/sops/releases/download/v3.9.4/sops-v3.9.4.linux.amd64 && \
    echo "5488e32bc471de7982ad895dd054bbab3ab91c417a118426134551e9626e4e85  /usr/local/bin/sops" | sha256sum -c && \
    chmod +x /usr/local/bin/sops && \
    curl -fsSL -o /tmp/age.tar.gz \
      https://github.com/FiloSottile/age/releases/download/v1.2.0/age-v1.2.0-linux-amd64.tar.gz && \
    echo "2ae71cb3ea761118937a944083f057cfd42f0ef11d197ce72fc2b8780d50c4ef  /tmp/age.tar.gz" | sha256sum -c && \
    tar -xzf /tmp/age.tar.gz -C /tmp && \
    mv /tmp/age/age /usr/local/bin/age && \
    mv /tmp/age/age-keygen /usr/local/bin/age-keygen && \
    chmod +x /usr/local/bin/age /usr/local/bin/age-keygen && \
    rm -rf /tmp/age /tmp/age.tar.gz && \
    apt-get purge -y curl && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.lock.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock.txt

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir --no-deps .

ENV SOPS_MCP_TRANSPORT=sse
ENV SOPS_MCP_PORT=55090
EXPOSE 55090

CMD ["sops-mcp"]
