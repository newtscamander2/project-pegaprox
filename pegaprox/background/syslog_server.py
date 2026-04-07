"""
PegaProx Syslog Server — receives syslog messages via UDP/TCP
Stores events in SQLite for the integrated log viewer.

NS: Apr 2026 — rewritten for gevent compatibility (no asyncio, no multiprocessing)
Original PR by gyptazy, adapted to fit PegaProx architecture.
"""
import os
import time
import logging
import sqlite3
import threading
from datetime import datetime

from pegaprox.constants import CONFIG_DIR

# DB in config dir, not CWD
DB_FILE = os.path.join(CONFIG_DIR, 'syslog.db')

SEVERITY_MAP = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug"
}

_syslog_thread = None


def _init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            hostname TEXT,
            facility INTEGER,
            severity INTEGER,
            severity_text TEXT,
            message TEXT,
            protocol TEXT
        )
    """)
    conn.commit()
    conn.close()
    logging.info(f"[Syslog] Database initialized: {DB_FILE}")


def _insert_log(entry):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO logs (timestamp, source_ip, hostname, facility, severity, severity_text, message, protocol)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, entry)
        conn.commit()
        conn.close()
    except Exception as e:
        logging.debug(f"[Syslog] Insert failed: {e}")


def parse_syslog(message):
    hostname = "unknown"
    facility = None
    severity = None
    severity_text = "unknown"
    msg = message

    try:
        if message.startswith("<"):
            pri_end = message.find(">")
            pri = int(message[1:pri_end])
            facility = pri // 8
            severity = pri % 8
            severity_text = SEVERITY_MAP.get(severity, "unknown")
            rest = message[pri_end + 1:].strip()
            parts = rest.split()
            if len(parts) >= 4:
                hostname = parts[3]
                msg = " ".join(parts[4:])
            else:
                msg = rest
    except Exception:
        pass

    return hostname, facility, severity, severity_text, msg


def _udp_listener(host, port):
    """UDP syslog listener using plain sockets (gevent-compatible)"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        logging.info(f"[Syslog] UDP listening on {host}:{port}")
    except OSError as e:
        logging.warning(f"[Syslog] UDP bind failed on {host}:{port}: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(8192)
            message = data.decode(errors="ignore").strip()
            if not message:
                continue
            hostname, facility, severity, severity_text, msg = parse_syslog(message)
            entry = (
                datetime.now().isoformat(),
                addr[0], hostname, facility, severity, severity_text, msg, "UDP"
            )
            _insert_log(entry)
        except Exception as e:
            logging.debug(f"[Syslog] UDP error: {e}")
            time.sleep(0.1)


def _tcp_listener(host, port):
    """TCP syslog listener using plain sockets (gevent-compatible)"""
    import socket
    import gevent
    from gevent import socket as gsocket

    srv = gsocket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
        srv.listen(32)
        logging.info(f"[Syslog] TCP listening on {host}:{port}")
    except OSError as e:
        logging.warning(f"[Syslog] TCP bind failed on {host}:{port}: {e}")
        return

    def handle_client(client_sock, addr):
        try:
            buf = b""
            while True:
                data = client_sock.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    message = line.decode(errors="ignore").strip()
                    if message:
                        hostname, facility, severity, severity_text, msg = parse_syslog(message)
                        entry = (
                            datetime.now().isoformat(),
                            addr[0], hostname, facility, severity, severity_text, msg, "TCP"
                        )
                        _insert_log(entry)
        except Exception:
            pass
        finally:
            client_sock.close()

    while True:
        try:
            client, addr = srv.accept()
            gevent.spawn(handle_client, client, addr)
        except Exception as e:
            logging.debug(f"[Syslog] TCP accept error: {e}")
            time.sleep(0.1)


def _syslog_loop():
    """Main syslog server loop — runs UDP + TCP in gevent greenlets"""
    import gevent

    _init_db()

    port = 1514
    host = "0.0.0.0"

    udp = gevent.spawn(_udp_listener, host, port)
    tcp = gevent.spawn(_tcp_listener, host, port)

    logging.info(f"[Syslog] Server started on port {port} (UDP+TCP)")
    gevent.joinall([udp, tcp])


def start_syslog_server():
    """Start syslog server in a background thread"""
    global _syslog_thread
    if _syslog_thread is not None:
        return

    _syslog_thread = threading.Thread(target=_syslog_loop, daemon=True, name='syslog-server')
    _syslog_thread.start()
    logging.info("[Syslog] Background thread started")
