FROM python:3.12-slim AS builder

WORKDIR /app

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# ── production image ─────────────────────────────────────────────────────────
FROM python:3.12-slim

RUN groupadd -r mcp && useradd -r -g mcp -d /app mcp

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/wazuh-mcp /usr/local/bin/wazuh-mcp

RUN mkdir -p /var/log/wazuh-mcp && chown mcp:mcp /var/log/wazuh-mcp

USER mcp

ENTRYPOINT ["wazuh-mcp"]
