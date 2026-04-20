# Wazuh MCP Server untuk Tim SOC

MCP (Model Context Protocol) server yang menghubungkan **Claude Desktop** dengan **Wazuh SIEM**.

**Topology:** Single cluster, satu master node + satu worker node.  
**Auth:** Basic auth (username + password).  
**Approval flow:** Konfirmasi manual di Claude Desktop — tidak perlu tool eksternal.

---

## Tools yang Tersedia

| Tool | Deskripsi | Approval? |
|------|-----------|-----------|
| `query_alerts` | Query alerts dengan filter severity, agent, IP, waktu | Tidak |
| `query_vulnerabilities` | Query CVE dan vuln data | Tidak |
| `get_alert_summary` | Statistik harian + breakdown per node | Tidak |
| `compliance_report` | Report PCI DSS / HIPAA / GDPR / NIST / TSC | Tidak |
| `block_ip` | Block IP via active response (firewall-drop) | **Ya — confirm di Claude Desktop** |
| `list_agents` | Daftar agents aktif dari master + worker | Tidak |
| `get_cluster_status` | Status node master dan worker | Tidak |

---

## Arsitektur

```
Claude Desktop (SOC Analyst)
    │
    │  stdio (MCP protocol)
    ▼
Wazuh MCP Server (Python)
    │
    ├── query_* ─────────────────────────► Wazuh Indexer :9200 (master)
    │                                       └─ shard otomatis ke worker
    │
    ├── list_agents / cluster_status ────► Wazuh Manager :55000 (master)
    │
    └── block_ip
          │
          ├─ 1. Claude tampilkan detail & minta konfirmasi
          ├─ 2. SOC analyst ketik "ya" / "lanjutkan"
          ├─ 3. Eksekusi → Wazuh Manager :55000 (master)
          │              └─ master forward ke worker otomatis
          ├─ 4. Audit log ke file (persisten)
          └─ 5. Notifikasi Slack (opsional)
```

---

## Project Structure

```
wazuh-mcp/
├── src/
│   └── wazuh_mcp/
│       ├── __init__.py
│       ├── server.py           # MCP server entry point
│       ├── config.py           # Pydantic settings
│       ├── manager_client.py   # Wazuh Manager API client
│       └── indexer_client.py   # Wazuh Indexer client
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── .env.example
├── claude_desktop_config.example.json
└── README.md
```

---

## Setup

### 1. Install

```bash
git clone <repo>
cd wazuh-mcp
pip install -e .
```

### 2. Konfigurasi

```bash
cp .env.example .env
nano .env   # Sesuaikan URL, username, password
```

**Konfigurasi minimum:**

```env
WAZUH_INDEXER_URL=https://wazuh-master:9200
WAZUH_MANAGER_URL=https://wazuh-master:55000
WAZUH_USERNAME=admin
WAZUH_PASSWORD=PASSWORD_ANDA
WAZUH_VERIFY_SSL=true
```

### 3. Claude Desktop

Edit config Claude Desktop:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wazuh-soc": {
      "command": "wazuh-mcp",
      "env": {
        "WAZUH_INDEXER_URL": "https://wazuh-master:9200",
        "WAZUH_MANAGER_URL": "https://wazuh-master:55000",
        "WAZUH_USERNAME": "admin",
        "WAZUH_PASSWORD": "PASSWORD_ANDA",
        "WAZUH_VERIFY_SSL": "true"
      }
    }
  }
}
```

Restart Claude Desktop setelah edit.

### 4. Docker (production)

```bash
# Cek nama network Docker Wazuh yang sudah ada
docker network ls | grep wazuh

# Konfigurasi
cp .env.example .env
nano .env

# Build & run sebagai sidecar
docker compose up -d
```

---

## Safety: block_ip

`block_ip` memiliki beberapa lapisan keamanan:

1. **Human-in-the-loop** — Claude wajib menampilkan detail dan meminta konfirmasi eksplisit sebelum eksekusi
2. **Agent wajib spesifik** — tidak ada default "semua agents", harus menyebutkan agent ID
3. **Default timeout 1 jam** — block otomatis expire, bukan permanen
4. **IP validation** — menggunakan Python `ipaddress` stdlib (mendukung IPv4 & IPv6)
5. **Audit log persisten** — setiap eksekusi dicatat ke file (rotasi 50MB x 10 file)
6. **Slack notifikasi** — opsional, melaporkan status berhasil/gagal

---

## Cara Pakai di Claude Desktop

### Query alerts

```
Tampilkan alert severity high dan critical dari 24 jam terakhir
```

```
Ada alert apa saja untuk IP 10.0.0.5 dalam 7 hari terakhir?
```

### Vulnerability check

```
Tampilkan semua CVE critical di agent web-prod-01
```

### Daily briefing

```
Buatkan summary alert hari ini, breakdown per node cluster
```

### Compliance

```
Generate compliance report PCI DSS untuk 7 hari terakhir
```

### Block IP — flow konfirmasi

```
SOC: Block IP 185.220.101.5 — brute force SSH ke 3 server sejak 2 jam lalu

Claude: Saya akan melakukan block IP dengan detail berikut:
        ┌─────────────────────────────────────────┐
        │ KONFIRMASI REQUIRED                      │
        │ IP Target : 185.220.101.5               │
        │ Aksi      : firewall-drop               │
        │ Agents    : 001, 003, 007               │
        │ Durasi    : 3600s (1 jam)               │
        │ Alasan    : Brute force SSH             │
        │ Node      : master → worker (otomatis)  │
        └─────────────────────────────────────────┘
        Ketik "ya" untuk melanjutkan atau "batal" untuk membatalkan.

SOC: ya

Claude: [eksekusi block_ip] IP 185.220.101.5 berhasil di-block di agents 001, 003, 007.
        Block akan expire dalam 1 jam.
```

---

## Slack Notifikasi (Opsional)

Slack hanya digunakan untuk **notifikasi pasca-eksekusi**, bukan untuk approval.
Approval tetap dilakukan manual di Claude Desktop.

Dua cara konfigurasi — pilih salah satu:

```env
# Opsi A (direkomendasikan): Incoming Webhook — channel fixed, simpel & aman
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ

# Opsi B: Bot token — bot harus di-invite ke channel
SLACK_BOT_TOKEN=xoxb-xxx
SLACK_NOTIFY_CHANNEL=#soc-notifications
```

Scopes yang diperlukan untuk Opsi B: `chat:write`. Jika keduanya di-set, webhook diprioritaskan.

Tool `send_alerts_to_slack` mengirim ringkasan alert (summary + top-N list) ke channel — pesan posting sebagai **bot/app**, bukan akun user, sehingga aman dari perspektif privasi.

---

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| Tools tidak muncul di Claude Desktop | Cek JSON syntax `claude_desktop_config.json`, restart Claude |
| Connection refused ke Indexer/Manager | Pastikan container MCP di network Docker yang sama dengan Wazuh |
| SSL error | Set `WAZUH_VERIFY_SSL=false` untuk self-signed cert (dev only) |
| `Authentication failed` | Cek username/password di `.env` |
| `block_ip` tidak jalan | Pastikan Wazuh Manager API aktif dan agents punya active response module |
| `agents wajib diisi` | Jalankan `list_agents` dulu untuk mendapatkan agent ID |

---

## Roadmap

### MVP (sekarang)
- Query alerts, vulnerabilities, summary, compliance
- block_ip dengan manual confirm + audit log
- Single cluster master + worker
- Slack notifikasi opsional
- Container hardening (non-root, cap_drop, read-only fs)

### v2
- `unblock_ip` — undo active response
- `get_agent_detail` — detail satu agent spesifik
- Rate limiting per tool
- SIEM forwarding untuk audit log

### v3
- Integrasi TheHive / JIRA untuk case management
- IP enrichment via VirusTotal / AbuseIPDB
- Scheduled Slack reports
