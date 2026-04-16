"""
Wazuh MCP Server — entry point.

Setup:
- Single cluster: master + worker node
- Auth: basic auth
- block_ip: manual confirm di Claude Desktop (human-in-the-loop)
- Slack: opsional, hanya untuk notifikasi pasca eksekusi
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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

# ── slack client (reuse across calls) ────────────────────────────────────────
_slack_client = None


def _get_slack_client():
    global _slack_client
    if _slack_client is None:
        from slack_sdk.web.async_client import AsyncWebClient
        _slack_client = AsyncWebClient(token=settings.slack_bot_token)
    return _slack_client


# ── helpers ──────────────────────────────────────────────────────────────────

def _fmt(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


async def _slack_notify(action: str, details: dict[str, Any], success: bool) -> None:
    """Kirim notifikasi Slack setelah eksekusi (opsional)."""
    if not settings.slack_enabled:
        return
    try:
        client = _get_slack_client()
        emoji = "✅" if success else "❌"
        status = "BERHASIL" if success else "GAGAL"
        detail_text = "\n".join(f"• *{k}:* `{v}`" for k, v in details.items())
        await client.chat_postMessage(
            channel=settings.slack_notify_channel,
            text=f"{emoji} [{status}] {action}",
            blocks=[{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *Active Response {status}*\n*Aksi:* {action}\n{detail_text}",
                },
            }],
        )
    except Exception as e:
        logger.warning("Gagal kirim Slack notifikasi: %s", e)


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
            name="compliance_report",
            description=(
                "Generate compliance report: PCI DSS, HIPAA, GDPR, NIST 800-53, atau TSC. "
                "Menampilkan events per requirement dan agent yang terdampak."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["pci_dss","hipaa","gdpr","nist","tsc"],
                        "description": "Framework compliance.",
                        "default": "pci_dss",
                    },
                    "time_from": {
                        "type": "string",
                        "description": "Waktu mulai. Default: 'now-7d'.",
                        "default": "now-7d",
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
            name="block_ip",
            description=(
                "AKSI DESTRUKTIF — Memerlukan konfirmasi eksplisit dari Anda. "
                "Block IP address di Wazuh agents menggunakan active response 'firewall-drop'. "
                "Master node akan forward perintah ke worker secara otomatis. "
                "PENTING: Sebelum memanggil tool ini, Claude HARUS menampilkan detail lengkap "
                "dan meminta konfirmasi eksplisit user ('ya' / 'setuju' / 'lanjutkan'). "
                "Jangan eksekusi jika user belum menyatakan persetujuan."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address yang akan di-block (IPv4 atau IPv6).",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Alasan pemblokiran (wajib, untuk audit trail).",
                    },
                    "agents": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Agent IDs spesifik. WAJIB diisi — "
                            "gunakan list_agents untuk mendapatkan ID."
                        ),
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": (
                            f"Durasi block (detik). Default: {settings.block_ip_default_timeout}s "
                            f"({settings.block_ip_default_timeout // 3600} jam). "
                            "Set 0 untuk permanen (hati-hati)."
                        ),
                        "default": settings.block_ip_default_timeout,
                    },
                    "confirmed": {
                        "type": "boolean",
                        "description": (
                            "HARUS true. Claude meng-set ini setelah user "
                            "menyatakan konfirmasi eksplisit di chat."
                        ),
                    },
                },
                "required": ["ip", "reason", "agents", "confirmed"],
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

        case "compliance_report":
            async with WazuhIndexerClient() as c:
                report = await c.compliance_report(
                    framework=args.get("framework", "pci_dss"),
                    time_from=args.get("time_from", "now-7d"),
                    time_to=args.get("time_to", "now"),
                )
            return {"cluster": settings.cluster_name, **report}

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

        case "block_ip":
            return await _handle_block_ip(args)

        case _:
            raise ValueError(f"Tool tidak dikenal: {name}")


async def _handle_block_ip(args: dict[str, Any]) -> dict[str, Any]:
    """
    Eksekusi block_ip dengan safety checks.

    Approval model: Claude Desktop (manual confirm).
    Claude HARUS meminta konfirmasi user sebelum memanggil tool ini.
    Field 'confirmed' harus True — ini yang membuktikan user sudah setuju.
    """
    # 1. Konfirmasi wajib
    confirmed = args.get("confirmed", False)
    if not confirmed:
        return {
            "status": "aborted",
            "reason": (
                "block_ip memerlukan konfirmasi eksplisit. "
                "Tampilkan detail ke user dan minta persetujuan terlebih dahulu."
            ),
        }

    ip = args["ip"]
    reason = args["reason"]
    agents = args.get("agents")
    timeout_seconds = args.get("timeout_seconds", settings.block_ip_default_timeout)

    # 2. Validasi IP (stdlib — IPv4 dan IPv6)
    if not _validate_ip(ip):
        return {"status": "rejected", "reason": f"IP tidak valid: '{ip}'"}

    # 3. Agent wajib spesifik — tidak boleh kosong (mencegah blast radius)
    if not agents or len(agents) == 0:
        return {
            "status": "rejected",
            "reason": (
                "agents wajib diisi dengan agent ID spesifik. "
                "Gunakan tool list_agents untuk mendapatkan daftar agent ID."
            ),
        }

    # 4. Audit log (persisten ke file)
    audit_logger.info(
        "ACTION=block_ip IP=%s AGENTS=%s TIMEOUT=%s REASON=%s",
        ip, ",".join(agents), timeout_seconds, reason,
    )

    logger.warning(
        "BLOCK IP: ip=%s reason=%s agents=%s timeout=%s",
        ip, reason, agents, timeout_seconds,
    )

    # 5. Eksekusi
    success = False
    try:
        async with WazuhManagerClient() as mgr:
            result = await mgr.block_ip(ip=ip, agents=agents, timeout=timeout_seconds)
        success = result.get("status") == "executed"
    except Exception as e:
        audit_logger.info(
            "ACTION=block_ip STATUS=failed IP=%s ERROR=%s", ip, e,
        )
        raise

    # 6. Audit result
    audit_logger.info(
        "ACTION=block_ip STATUS=%s IP=%s AGENTS=%s",
        "success" if success else "failed", ip, ",".join(agents),
    )

    # 7. Slack notifikasi (cek result sebelum kirim)
    timeout_display = f"{timeout_seconds}s" if timeout_seconds > 0 else "permanen"
    await _slack_notify(
        action=f"Block IP {ip}",
        details={
            "IP": ip,
            "Cluster": settings.cluster_name,
            "Agents": ", ".join(agents),
            "Durasi": timeout_display,
            "Alasan": reason,
        },
        success=success,
    )

    return {**result, "reason": reason}


# ── entry point ───────────────────────────────────────────────────────────────

async def _run() -> None:
    logger.info("Wazuh MCP Server starting")
    logger.info("Cluster: %s | Indexer: %s | Manager: %s",
                settings.cluster_name,
                settings.wazuh_indexer_url,
                settings.wazuh_manager_url)
    logger.info("Slack notify: %s", "enabled" if settings.slack_enabled else "disabled")
    logger.info("Audit log: %s", settings.audit_log_path)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
