#!/usr/bin/env bash
# Wrapper agar Claude Code bisa launch wazuh-mcp dengan .env di-load.
set -a
source /home/claude-runner/wazuh-mcp/.env
set +a
exec /home/claude-runner/wazuh-mcp/.venv/bin/wazuh-mcp
