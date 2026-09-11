#!/usr/bin/env bash
# Wrapper: jalankan wazuh-mcp sebagai daemon HTTP persisten (load .env).
# Klien (claude -p) connect via --mcp-config ke http://127.0.0.1:8765/mcp,
# sehingga MCP TIDAK di-spawn ulang (cold-start) tiap pesan.
#
# Path dihitung relatif ke lokasi script ini, supaya portable lintas host/user
# (jangan hardcode /home/<user>/wazuh-mcp — itu bikin gagal senyap kalau di-clone
# ke path/host lain, mis. saat pindah ke EC2 baru).
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -a
source "$DIR/.env"
set +a
export WAZUH_MCP_HTTP_HOST="${WAZUH_MCP_HTTP_HOST:-127.0.0.1}"
export WAZUH_MCP_HTTP_PORT="${WAZUH_MCP_HTTP_PORT:-8765}"
exec "$DIR/.venv/bin/wazuh-mcp-http"
