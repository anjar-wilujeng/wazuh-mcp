"""
Wazuh Indexer client.
OpenSearch-compatible REST API, port 9200.
Auth: basic auth. Topology: single cluster (master + worker).
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from .config import settings

logger = logging.getLogger(__name__)

ALERTS_INDEX = "wazuh-alerts-4.x-*"
VULNERABILITIES_INDEX = "wazuh-states-vulnerabilities-*"


class WazuhIndexerClient:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.wazuh_indexer_url,
            auth=(settings.wazuh_username, settings.wazuh_password),
            verify=settings.wazuh_ca_cert_path or settings.wazuh_verify_ssl,
            timeout=30.0,
        )

    async def __aenter__(self) -> "WazuhIndexerClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.aclose()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10), reraise=True)
    async def _search(self, index: str, query: dict[str, Any]) -> dict[str, Any]:
        resp = await self._client.post(f"/{index}/_search", json=query)
        resp.raise_for_status()
        return resp.json()

    async def query_alerts(
        self,
        *,
        severity: list[str] | None = None,
        agent_name: str | None = None,
        rule_id: str | None = None,
        src_ip: str | None = None,
        time_from: str = "now-24h",
        time_to: str = "now",
        size: int = 50,
    ) -> list[dict[str, Any]]:
        severity_level_map = {
            "low":      {"gte": 1,  "lte": 6},
            "medium":   {"gte": 7,  "lte": 11},
            "high":     {"gte": 12, "lte": 14},
            "critical": {"gte": 15, "lte": 15},
        }
        must: list[dict] = [
            {"range": {"timestamp": {"gte": time_from, "lte": time_to}}}
        ]
        if severity:
            ranges = [{"range": {"rule.level": severity_level_map[s]}}
                      for s in severity if s in severity_level_map]
            if ranges:
                must.append({"bool": {"should": ranges, "minimum_should_match": 1}})
        if agent_name:
            must.append({"match": {"agent.name": agent_name}})
        if rule_id:
            must.append({"term": {"rule.id": rule_id}})
        if src_ip:
            must.append({"bool": {
                "should": [{"term": {"data.srcip": src_ip}},
                           {"term": {"data.src_ip": src_ip}}],
                "minimum_should_match": 1,
            }})

        result = await self._search(ALERTS_INDEX, {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must}},
            "_source": [
                "timestamp", "agent.name", "agent.ip", "manager.name",
                "rule.id", "rule.level", "rule.description", "rule.groups",
                "data.srcip", "data.dstip", "full_log",
            ],
        })
        return [h["_source"] for h in result.get("hits", {}).get("hits", [])]

    async def query_vulnerabilities(
        self,
        *,
        agent_name: str | None = None,
        cve_id: str | None = None,
        severity: list[str] | None = None,
        size: int = 50,
    ) -> list[dict[str, Any]]:
        must: list[dict] = []
        if agent_name:
            must.append({"match": {"agent.name": agent_name}})
        if cve_id:
            must.append({"term": {"vulnerability.id": cve_id.upper()}})
        if severity:
            must.append({"terms": {"vulnerability.severity": [s.capitalize() for s in severity]}})

        result = await self._search(VULNERABILITIES_INDEX, {
            "size": size,
            "sort": [{"vulnerability.severity": {"order": "desc"}}],
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "_source": [
                "agent.name", "agent.ip",
                "vulnerability.id", "vulnerability.severity", "vulnerability.title",
                "vulnerability.package.name", "vulnerability.package.version",
                "vulnerability.package.fix", "vulnerability.cvss.cvss3.base_score",
                "vulnerability.published",
            ],
        })
        return [h["_source"] for h in result.get("hits", {}).get("hits", [])]

    async def get_alert_summary(
        self,
        time_from: str = "now-24h",
        time_to: str = "now",
    ) -> dict[str, Any]:
        result = await self._search(ALERTS_INDEX, {
            "size": 0,
            "query": {"range": {"timestamp": {"gte": time_from, "lte": time_to}}},
            "aggs": {
                "by_severity": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low",      "from": 1,  "to": 7},
                            {"key": "medium",   "from": 7,  "to": 12},
                            {"key": "high",     "from": 12, "to": 15},
                            {"key": "critical", "from": 15, "to": 16},
                        ],
                    }
                },
                "top_rules":  {"terms": {"field": "rule.id",      "size": 10}},
                "top_agents": {"terms": {"field": "agent.name",   "size": 10}},
                "by_node":    {"terms": {"field": "manager.name", "size": 5}},
            },
        })
        aggs = result.get("aggregations", {})
        total = result.get("hits", {}).get("total", {}).get("value", 0)
        return {
            "total": total,
            "time_range": {"from": time_from, "to": time_to},
            "severity_breakdown": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_severity", {}).get("buckets", [])
            },
            "top_rules":  [{"rule_id": b["key"], "count": b["doc_count"]}
                           for b in aggs.get("top_rules",  {}).get("buckets", [])],
            "top_agents": [{"agent":   b["key"], "count": b["doc_count"]}
                           for b in aggs.get("top_agents", {}).get("buckets", [])],
            "by_node":    [{"node":    b["key"], "count": b["doc_count"]}
                           for b in aggs.get("by_node",    {}).get("buckets", [])],
        }

