#!/usr/bin/env bash
# Kelola daemon MCP HTTP persisten (wazuh-soc).
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDFILE="$DIR/mcp-http.pid"
LOGFILE="$DIR/mcp-http.log"
HOST="${WAZUH_MCP_HTTP_HOST:-127.0.0.1}"
PORT="${WAZUH_MCP_HTTP_PORT:-8765}"

is_up() { [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

start() {
    if is_up; then echo "mcp-http sudah jalan (PID $(cat "$PIDFILE"))."; return 0; fi
    cd "$DIR"
    PYTHONUNBUFFERED=1 nohup ./run-mcp-http.sh >> "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    # tunggu port listen (maks ~10 dtk)
    for _ in $(seq 1 20); do
        if (exec 3<>"/dev/tcp/$HOST/$PORT") 2>/dev/null; then exec 3>&- 3<&-; echo "mcp-http started (PID $(cat "$PIDFILE")) on $HOST:$PORT."; return 0; fi
        sleep 0.5
    done
    echo "mcp-http start TIMEOUT — cek $LOGFILE"; return 1
}

stop() {
    if [[ ! -f "$PIDFILE" ]]; then echo "PID file tidak ada."; return 0; fi
    local pid; pid=$(cat "$PIDFILE")
    if kill -0 "$pid" 2>/dev/null; then kill "$pid"; echo "mcp-http stopped (PID $pid)."; fi
    rm -f "$PIDFILE"
}

status() { if is_up; then echo "mcp-http RUNNING (PID $(cat "$PIDFILE")) on $HOST:$PORT."; else echo "mcp-http STOPPED."; fi; }

case "${1:-}" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    status)  status ;;
    ensure)  is_up || start ;;
    log)     tail -f "$LOGFILE" ;;
    *) echo "Usage: $0 {start|stop|restart|status|ensure|log}"; exit 1 ;;
esac
