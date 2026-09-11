#!/usr/bin/env bash
# Wrapper agar Claude Code bisa launch wazuh-mcp dengan .env di-load.
# Path dihitung relatif ke lokasi script ini, supaya portable lintas host/user
# (jangan hardcode /home/<user>/wazuh-mcp — itu bikin gagal senyap kalau di-clone
# ke path/host lain).
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -a
source "$DIR/.env"
set +a
exec "$DIR/.venv/bin/wazuh-mcp"
