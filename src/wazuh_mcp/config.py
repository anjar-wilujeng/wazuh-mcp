"""
Configuration untuk Wazuh MCP Server.

Topology: satu Wazuh cluster dengan satu master node dan satu worker node.
- Indexer queries → ke Wazuh Indexer (biasanya di master node)
- Active response  → ke Wazuh Manager master (yang akan forward ke worker)
- Auth             → basic auth (username + password)
"""
from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Wazuh Indexer (OpenSearch, port 9200) ─────────────────────
    wazuh_indexer_url: str = Field(
        default="https://wazuh-indexer:9200",
        alias="WAZUH_INDEXER_URL",
    )

    # ── Wazuh Manager (REST API, port 55000) ──────────────────────
    wazuh_manager_url: str = Field(
        default="https://wazuh-manager:55000",
        alias="WAZUH_MANAGER_URL",
    )

    # ── Auth (wajib — tidak ada default) ──────────────────────────
    wazuh_username: str = Field(alias="WAZUH_USERNAME")
    wazuh_password: str = Field(alias="WAZUH_PASSWORD")

    # ── SSL ───────────────────────────────────────────────────────
    wazuh_verify_ssl: bool = Field(default=True, alias="WAZUH_VERIFY_SSL")
    wazuh_ca_cert_path: str | None = Field(default=None, alias="WAZUH_CA_CERT_PATH")

    # ── Cluster info (informational) ──────────────────────────────
    cluster_name: str = Field(default="wazuh-cluster", alias="WAZUH_CLUSTER_NAME")
    master_node_name: str = Field(default="wazuh-master", alias="WAZUH_MASTER_NODE")
    worker_node_name: str = Field(default="wazuh-worker", alias="WAZUH_WORKER_NODE")

    # ── Active response safety ────────────────────────────────────
    block_ip_default_timeout: int = Field(
        default=3600,
        alias="BLOCK_IP_DEFAULT_TIMEOUT",
    )

    # ── Slack (opsional — hanya untuk notifikasi, BUKAN approval) ─
    slack_bot_token: str = Field(default="", alias="SLACK_BOT_TOKEN")
    slack_notify_channel: str = Field(
        default="#soc-notifications",
        alias="SLACK_NOTIFY_CHANNEL",
    )

    # ── Audit log ─────────────────────────────────────────────────
    audit_log_path: str = Field(
        default="/var/log/wazuh-mcp/audit.log",
        alias="AUDIT_LOG_PATH",
    )

    # ── Server ────────────────────────────────────────────────────
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    max_alerts_per_query: int = Field(default=100, alias="MAX_ALERTS_PER_QUERY")

    @field_validator("wazuh_ca_cert_path")
    @classmethod
    def validate_ca_cert(cls, v: str | None) -> str | None:
        if v and not Path(v).exists():
            raise ValueError(f"CA cert file not found: {v}")
        return v

    @property
    def slack_enabled(self) -> bool:
        return bool(self.slack_bot_token)


settings = Settings()
