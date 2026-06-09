# Wazuh MCP Server untuk Tim SOC

MCP (Model Context Protocol) server **read-only** yang menghubungkan **Claude**
(Claude Code / Claude Desktop) dengan **Wazuh SIEM** untuk triase & analisis alert.

**Topology:** Single cluster, satu master node + satu worker node.
**Auth:** Basic auth (Indexer) + token auth (Manager API).
**Sifat:** Murni read-only & analitik — tidak ada tool yang mengubah state.

> Posting hasil ke Slack ditangani oleh bot eksternal (`blue-agent`), **bukan** oleh
> MCP ini. MCP hanya menyediakan data Wazuh.

---

## Tools yang Tersedia

Semua read-only — tidak ada konfirmasi/approval karena tidak ada aksi destruktif.

| Tool | Deskripsi |
|------|-----------|
| `query_alerts` | Query alerts dengan filter severity, agent, rule id, IP, rentang waktu |
| `query_vulnerabilities` | Query CVE / vulnerability data per agent |
| `get_alert_summary` | Statistik ringkas: per severity, top rules, top agents, per node |
| `list_agents` | Daftar agents aktif (field di-trim untuk efisiensi — lihat catatan) |
| `get_cluster_status` | Status node master & worker |

> **Catatan efisiensi `list_agents`:** payload dipangkas di sisi Wazuh via parameter
> `select` (hanya `id,name,ip,status,version,lastKeepAlive,node_name,os.name,os.version`),
> memangkas respons ~65% agar model membaca lebih sedikit & lebih cepat.

---

## Arsitektur

Dua transport tersedia. Untuk pemakaian terus-menerus (mis. bot SOC), gunakan
**daemon HTTP persisten** agar MCP tidak cold-start (spawn ulang Python) tiap panggilan.

```
Claude Code (claude -p) / Claude Desktop / blue-agent bot
    │
    ├─ stdio  (per-panggilan, via run-mcp.sh) ───────┐
    │                                                 │
    └─ HTTP   (daemon persisten, :8765, via          │
              run-mcp-http.sh + manage-http.sh) ──────┤
                                                      ▼
                                          Wazuh MCP Server (Python)
                                                      │
       query_alerts / vulnerabilities / summary ─────► Wazuh Indexer :9200
                                                      │
       list_agents / cluster_status ─────────────────► Wazuh Manager :55000
                                                      │
                                          Audit log persisten (file, rotasi 50MB×10)
```

- **stdio** — Claude men-spawn proses MCP baru tiap sesi (sederhana, tapi ada
  cold-start ~1–3 dtk per panggilan).
- **HTTP daemon** — proses MCP tetap hidup; klien connect via `--mcp-config`.
  Tidak ada spawn ulang Python per panggilan.

---

## Project Structure

```
wazuh-mcp/
├── src/
│   └── wazuh_mcp/
│       ├── __init__.py
│       ├── server.py           # MCP server: tools + entry point stdio (main) & HTTP (main_http)
│       ├── config.py           # Pydantic settings (.env)
│       ├── manager_client.py   # Wazuh Manager API client (token auth)
│       └── indexer_client.py   # Wazuh Indexer client (basic auth)
├── run-mcp.sh                  # Wrapper stdio (load .env → wazuh-mcp)
├── run-mcp-http.sh             # Wrapper daemon HTTP (load .env → wazuh-mcp-http)
├── manage-http.sh              # Kelola daemon HTTP: start/stop/restart/status/ensure
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── .env.example
└── README.md
```

---

## Setup

### 1. Install

Project ini memakai virtualenv (dibuat dengan `uv`):

```bash
git clone https://github.com/anjar-wilujeng/wazuh-mcp.git
cd wazuh-mcp
uv venv .venv
uv pip install -e . --python .venv/bin/python
```

Console script yang terdaftar: `wazuh-mcp` (stdio) dan `wazuh-mcp-http` (daemon HTTP).

### 2. Konfigurasi

```bash
cp .env.example .env
nano .env
```

**Konfigurasi minimum:**

```env
WAZUH_INDEXER_URL=https://wazuh-master:9200
WAZUH_MANAGER_URL=https://wazuh-master:55000
WAZUH_USERNAME=admin            # auth Indexer (wajib)
WAZUH_PASSWORD=PASSWORD_ANDA
WAZUH_VERIFY_SSL=true
```

**Opsional:**

```env
# Kredensial Manager terpisah (jika beda dgn Indexer; default fallback ke WAZUH_USERNAME/PASSWORD)
WAZUH_MANAGER_USERNAME=
WAZUH_MANAGER_PASSWORD=

WAZUH_CA_CERT_PATH=             # path CA cert; kalau di-set, dipakai untuk verifikasi TLS
WAZUH_CLUSTER_NAME=wazuh-cluster
WAZUH_MASTER_NODE=wazuh-master
WAZUH_WORKER_NODE=wazuh-worker
AUDIT_LOG_PATH=/var/log/wazuh-mcp/audit.log
LOG_LEVEL=INFO
MAX_ALERTS_PER_QUERY=100

# Daemon HTTP (default 127.0.0.1:8765)
WAZUH_MCP_HTTP_HOST=127.0.0.1
WAZUH_MCP_HTTP_PORT=8765
```

### 3a. Pakai via stdio (Claude Desktop / Claude Code)

Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`
di macOS, `%APPDATA%\Claude\claude_desktop_config.json` di Windows):

```json
{
  "mcpServers": {
    "wazuh-soc": {
      "command": "/path/ke/wazuh-mcp/run-mcp.sh"
    }
  }
}
```

`run-mcp.sh` me-load `.env` lalu menjalankan `wazuh-mcp`. Restart Claude setelah edit.

### 3b. Pakai via daemon HTTP (disarankan untuk bot / pemakaian terus-menerus)

```bash
# Nyalakan daemon (load .env, listen 127.0.0.1:8765)
./manage-http.sh start
./manage-http.sh status        # cek RUNNING
```

Lalu arahkan Claude ke daemon (mis. dari `claude -p`):

```bash
claude -p "..." \
  --mcp-config '{"mcpServers":{"wazuh-soc":{"type":"http","url":"http://127.0.0.1:8765/mcp"}}}' \
  --strict-mcp-config
```

Perintah `manage-http.sh`: `start | stop | restart | status | ensure | log`
(`ensure` = start hanya jika belum jalan; cocok dipanggil dari skrip lain saat boot).

### 4. Docker

```bash
docker network ls | grep wazuh   # cek network Wazuh yang ada
cp .env.example .env && nano .env
docker compose up -d
```

---

## Cara Pakai (contoh prompt)

### Query alerts
```
Tampilkan alert severity high dan critical dari 24 jam terakhir
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

### Agents & cluster
```
Daftar agent yang aktif sekarang
Status cluster Wazuh sehat?
```

---

## Audit Log

Setiap panggilan tool dicatat ke file audit (`AUDIT_LOG_PATH`, rotasi 50MB × 10 file).
Berguna untuk jejak siapa menanyakan apa, kapan.

---

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| Tools tidak muncul | Cek path `run-mcp.sh` di config, pastikan executable; restart klien |
| `AttributeError ... settings.X` saat start | `.env`/kode tidak konsisten — cek `config.py` vs referensi di `server.py` |
| Daemon HTTP tak bisa connect | `./manage-http.sh status`; cek `mcp-http.log`; pastikan port 8765 listen |
| Connection refused ke Indexer/Manager | Pastikan URL benar & MCP di network yang sama dengan Wazuh |
| SSL error | Set `WAZUH_VERIFY_SSL=false` untuk self-signed (dev only) atau set `WAZUH_CA_CERT_PATH` |
| `Authentication failed` | Cek `WAZUH_USERNAME/PASSWORD` (dan `WAZUH_MANAGER_*` bila terpisah) |

---

## Roadmap

### Sekarang
- 5 tool read-only: query alerts / vulnerabilities / summary / list agents / cluster status
- Dua transport: stdio (per-panggilan) & HTTP daemon (persisten)
- Payload `list_agents` di-trim via `select` (efisiensi token & latensi)
- Audit log persisten
- Single cluster master + worker

### Berikutnya (ide)
- `get_agent_detail` — detail satu agent spesifik
- IP enrichment (VirusTotal / AbuseIPDB) untuk konteks triase
- Rate limiting per tool
- SIEM forwarding untuk audit log

> **Catatan historis:** versi awal sempat punya `block_ip` (active response),
> `compliance_report`, dan `send_alerts_to_slack`. Semua dibuang demi menjaga MCP
> tetap read-only/analitik; posting Slack kini ditangani bot eksternal (`blue-agent`).
