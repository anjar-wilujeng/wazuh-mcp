"""
Wazuh Manager API client (port 55000).
Auth: basic auth → JWT token. Active response dikirim ke master,
master node forward ke worker secara otomatis via Wazuh cluster protocol.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from .config import settings

logger = logging.getLogger(__name__)


class WazuhManagerClient:
    def __init__(self) -> None:
        self._token: str | None = None
        self._client = httpx.AsyncClient(
            base_url=settings.wazuh_manager_url,
            verify=settings.wazuh_ca_cert_path or settings.wazuh_verify_ssl,
            timeout=30.0,
        )

    async def __aenter__(self) -> "WazuhManagerClient":
        await self._authenticate()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.aclose()

    async def _authenticate(self) -> None:
        """Exchange basic auth → JWT token."""
        resp = await self._client.get(
            "/security/user/authenticate",
            auth=(settings.manager_username, settings.manager_password),
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        self._client.headers["Authorization"] = f"Bearer {self._token}"
        logger.info("Authenticated to Wazuh Manager: %s", settings.wazuh_manager_url)

    async def block_ip(
        self,
        ip: str,
        agents: list[str],
        timeout: int = 0,
    ) -> dict[str, Any]:
        """
        Block IP via active response 'firewall-drop'.
        Master node memforward ke worker secara otomatis.

        Args:
            ip: IP yang di-block
            agents: Agent IDs spesifik (wajib)
            timeout: Detik (0 = permanen)
        """
        payload: dict[str, Any] = {
            "command": "firewall-drop",
            "alert": {"data": {"srcip": ip}},
            "agents_list": agents,
        }
        if timeout > 0:
            payload["parameters"] = {"extra_args": [f"-t {timeout}"]}

        resp = await self._client.put("/active-response", json=payload)
        resp.raise_for_status()

        logger.warning("BLOCK IP executed: ip=%s agents=%s timeout=%s", ip, agents, timeout)
        return {
            "status": "executed",
            "ip": ip,
            "agents": agents,
            "timeout_seconds": timeout,
            "manager": settings.wazuh_manager_url,
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10), reraise=True)
    async def get_agents(self) -> list[dict[str, Any]]:
        """List semua agents aktif (dari master + worker).

        Pakai `select` agar payload dipangkas di sisi Wazuh (sebelum sampai ke
        model): hanya field yang relevan untuk triase. Field operasional/redundan
        (group_config_status, status_code, dateAdd, registerIP, manager, os.uname,
        os.arch, dll) sengaja tidak diambil — memangkas ~65% ukuran respons.
        """
        resp = await self._client.get(
            "/agents",
            params={
                "status": "active",
                "limit": 500,
                "select": "id,name,ip,status,version,lastKeepAlive,node_name,os.name,os.version",
            },
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("affected_items", [])

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10), reraise=True)
    async def get_cluster_nodes(self) -> list[dict[str, Any]]:
        """Ambil info node cluster (master + worker)."""
        resp = await self._client.get("/cluster/nodes")
        resp.raise_for_status()
        return resp.json().get("data", {}).get("affected_items", [])
