"""
Wazuh MCP Server — entry point.

Setup:
- Single cluster: master + worker node
- Auth: basic auth
"""
from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
from pathlib import Path
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from .config import settings
from .indexer_client import WazuhIndexerClient
from .manager_client import WazuhManagerClient

logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── audit logger (persisten ke file) ─────────────────────────────────────────
audit_logger = logging.getLogger("wazuh_mcp.audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False

_audit_dir = Path(settings.audit_log_path).parent
_audit_dir.mkdir(parents=True, exist_ok=True)

_audit_handler = logging.handlers.RotatingFileHandler(
    settings.audit_log_path,
    maxBytes=50 * 1024 * 1024,  # 50 MB
    backupCount=10,
)
_audit_handler.setFormatter(
    logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z")
)
audit_logger.addHandler(_audit_handler)

app = Server("wazuh-mcp")

# ── helpers ──────────────────────────────────────────────────────────────────

def _fmt(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


# ── tool definitions ──────────────────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    cluster_info = (
        f"Cluster: {settings.cluster_name} "
        f"(master: {settings.master_node_name}, worker: {settings.worker_node_name})"
    )
    return [
        types.Tool(
            name="query_alerts",
            description=(
                f"Query security alerts dari Wazuh Indexer. {cluster_info}. "
                "Filter: severity, agent, source IP, rule ID, rentang waktu. "
                "Gunakan untuk investigasi insiden, threat hunting, atau daily review."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["low","medium","high","critical"]},
                        "description": "Filter severity. Contoh: ['high','critical']",
                    },
                    "agent_name": {
                        "type": "string",
                        "description": "Nama agent/host, e.g. 'web-server-01'.",
                    },
                    "rule_id": {
                        "type": "string",
                        "description": "Wazuh rule ID, e.g. '5710'.",
                    },
                    "src_ip": {
                        "type": "string",
                        "description": "Source IP address untuk difilter.",
                    },
                    "time_from": {
                        "type": "string",
                        "description": "Waktu mulai (Elasticsearch date math). Default: 'now-24h'.",
                        "default": "now-24h",
                    },
                    "time_to": {
                        "type": "string",
                        "description": "Waktu akhir. Default: 'now'.",
                        "default": "now",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max hasil. Default: 50, max: 100.",
                        "default": 50,
                        "maximum": 100,
                    },
                },
                "required": [],
            },
        ),

        types.Tool(
            name="query_vulnerabilities",
            description=(
                f"Query vulnerability data dari Wazuh Indexer. {cluster_info}. "
                "Menampilkan CVE, severity, package name, dan fix version. "
                "Berguna untuk vulnerability assessment dan patch prioritization."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_name": {
                        "type": "string",
                        "description": "Filter berdasarkan nama agent/host.",
                    },
                    "cve_id": {
                        "type": "string",
                        "description": "CVE ID, e.g. 'CVE-2024-1234'.",
                    },
                    "severity": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["critical","high","medium","low"]},
                        "description": "Filter severity vulnerability.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max hasil. Default: 50.",
                        "default": 50,
                    },
                },
                "required": [],
            },
        ),

        types.Tool(
            name="get_alert_summary",
            description=(
                f"Ringkasan statistik alerts: total per severity, top rules, top agents. "
                f"{cluster_info}. Juga menampilkan breakdown per node (master vs worker). "
                "Cocok untuk daily SOC briefing."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "time_from": {
                        "type": "string",
                        "description": "Waktu mulai. Default: 'now-24h'.",
                        "default": "now-24h",
                    },
                    "time_to": {
                        "type": "string",
                        "description": "Waktu akhir. Default: 'now'.",
                        "default": "now",
                    },
                },
                "required": [],
            },
        ),

        types.Tool(
            name="list_agents",
            description=(
                "Tampilkan semua agents aktif (dari master dan worker node). "
                "Berguna untuk verifikasi sebelum eksekusi active response."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),

        types.Tool(
            name="get_cluster_status",
            description=(
                "Tampilkan status node cluster Wazuh: master dan worker. "
                "Berguna untuk memastikan cluster sehat sebelum operasi."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
    ]


# ── tool handlers ─────────────────────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    logger.info("Tool: %s | args: %s", name, arguments)
    try:
        result = await _dispatch(name, arguments)
        return [types.TextContent(type="text", text=_fmt(result))]
    except ValueError as e:
        return [types.TextContent(type="text", text=f"Konfigurasi error: {e}")]
    except Exception as e:
        logger.exception("Tool %s failed", name)
        return [types.TextContent(type="text", text=f"Error ({type(e).__name__}): {e}")]


async def _dispatch(name: str, args: dict[str, Any]) -> Any:
    match name:
        case "query_alerts":
            async with WazuhIndexerClient() as c:
                alerts = await c.query_alerts(
                    severity=args.get("severity"),
                    agent_name=args.get("agent_name"),
                    rule_id=args.get("rule_id"),
                    src_ip=args.get("src_ip"),
                    time_from=args.get("time_from", "now-24h"),
                    time_to=args.get("time_to", "now"),
                    size=min(args.get("limit", 50), settings.max_alerts_per_query),
                )
            return {
                "cluster": settings.cluster_name,
                "total_returned": len(alerts),
                "alerts": alerts,
            }

        case "query_vulnerabilities":
            async with WazuhIndexerClient() as c:
                vulns = await c.query_vulnerabilities(
                    agent_name=args.get("agent_name"),
                    cve_id=args.get("cve_id"),
                    severity=args.get("severity"),
                    size=args.get("limit", 50),
                )
            return {
                "cluster": settings.cluster_name,
                "total_returned": len(vulns),
                "vulnerabilities": vulns,
            }

        case "get_alert_summary":
            async with WazuhIndexerClient() as c:
                summary = await c.get_alert_summary(
                    time_from=args.get("time_from", "now-24h"),
                    time_to=args.get("time_to", "now"),
                )
            return {"cluster": settings.cluster_name, **summary}

        case "list_agents":
            async with WazuhManagerClient() as m:
                agents = await m.get_agents()
            return {
                "cluster": settings.cluster_name,
                "total": len(agents),
                "agents": agents,
            }

        case "get_cluster_status":
            async with WazuhManagerClient() as m:
                nodes = await m.get_cluster_nodes()
            return {
                "cluster": settings.cluster_name,
                "master_node": settings.master_node_name,
                "worker_node": settings.worker_node_name,
                "nodes": nodes,
            }

        case _:
            raise ValueError(f"Tool tidak dikenal: {name}")


# ── entry point ───────────────────────────────────────────────────────────────

async def _run() -> None:
    logger.info("Wazuh MCP Server starting")
    logger.info("Cluster: %s | Indexer: %s | Manager: %s",
                settings.cluster_name,
                settings.wazuh_indexer_url,
                settings.wazuh_manager_url)
    logger.info("Audit log: %s", settings.audit_log_path)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main() -> None:
    asyncio.run(_run())


# ── HTTP daemon (persisten — hindari cold-start MCP per panggilan claude -p) ────

def main_http() -> None:
    """Jalankan MCP server sebagai daemon HTTP (transport: streamable-http).

    Tujuan: proses tetap hidup antar panggilan `claude -p`, sehingga interpreter
    Python + koneksi Wazuh tidak di-spawn ulang tiap pesan. Klien (claude)
    connect via --mcp-config ke http://HOST:PORT/mcp.

    Env override: WAZUH_MCP_HTTP_HOST (default 127.0.0.1), WAZUH_MCP_HTTP_PORT (8765).
    """
    import contextlib

    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Mount
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    host = os.environ.get("WAZUH_MCP_HTTP_HOST", "127.0.0.1")
    port = int(os.environ.get("WAZUH_MCP_HTTP_PORT", "8765"))

    # stateless: tiap invocation claude -p adalah sesi MCP independen (request/response
    # tool call), jadi tak perlu tracking session-id lintas koneksi HTTP.
    session_manager = StreamableHTTPSessionManager(app=app, stateless=True)

    async def handle_mcp(scope, receive, send):
        await session_manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with session_manager.run():
            logger.info("Wazuh MCP HTTP daemon ready on http://%s:%d/mcp", host, port)
            logger.info("Cluster: %s | Indexer: %s | Manager: %s",
                        settings.cluster_name,
                        settings.wazuh_indexer_url,
                        settings.wazuh_manager_url)
            logger.info("Audit log: %s", settings.audit_log_path)
            yield

    http_app = Starlette(routes=[Mount("/mcp", app=handle_mcp)], lifespan=lifespan)
    uvicorn.run(http_app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
