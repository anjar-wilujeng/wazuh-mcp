#!/usr/bin/env bash
# Wrapper: jalankan wazuh-mcp sebagai daemon HTTP persisten (load .env).
# Klien (claude -p) connect via --mcp-config ke http://127.0.0.1:8765/mcp,
# sehingga MCP TIDAK di-spawn ulang (cold-start) tiap pesan.
set -a
source /home/claude-runner/wazuh-mcp/.env
set +a
export WAZUH_MCP_HTTP_HOST="${WAZUH_MCP_HTTP_HOST:-127.0.0.1}"
export WAZUH_MCP_HTTP_PORT="${WAZUH_MCP_HTTP_PORT:-8765}"
exec /home/claude-runner/wazuh-mcp/.venv/bin/wazuh-mcp-http
