"""
PegaProx Async Syslog Server
Receives syslog messages from remote systems and writes events into local sqllite db
"""

import asyncio
import sqlite3
import ssl
import os
from datetime import datetime


DB_FILE = "syslog.db"
SEVERITY_MAP = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug"
}


def init_db():
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


def _insert_log_sync(entry):
    conn = sqlite3.connect(DB_FILE, timeout=5)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO logs (
            timestamp, source_ip, hostname,
            facility, severity, severity_text,
            message, protocol
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, entry)

    conn.commit()
    conn.close()


def parse_syslog(message: str):
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


class LogWriter:
    def __init__(self):
        self.queue = asyncio.Queue()

    async def start(self):
        loop = asyncio.get_running_loop()
        while True:
            entry = await self.queue.get()
            await loop.run_in_executor(None, _insert_log_sync, entry)

    async def log(self, source_ip, protocol, message):
        hostname, facility, severity, severity_text, msg = parse_syslog(message)

        entry = (
            datetime.utcnow().isoformat(),
            source_ip,
            hostname,
            facility,
            severity,
            severity_text,
            msg,
            protocol
        )

        await self.queue.put(entry)


writer = LogWriter()


class SyslogUDP(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        message = data.decode(errors="ignore").strip()
        asyncio.create_task(writer.log(addr[0], "UDP", message))


async def handle_tcp(reader, writer_stream):
    addr = writer_stream.get_extra_info("peername")[0]

    while True:
        data = await reader.readline()
        if not data:
            break

        message = data.decode(errors="ignore").strip()
        await writer.log(addr, "TCP", message)


def create_ssl_context():
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("[TLS] Disabled (no cert.pem/key.pem)")
        return None

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain("cert.pem", "key.pem")
    return ctx


async def main_async():
    init_db()

    loop = asyncio.get_running_loop()
    asyncio.create_task(writer.start())

    await loop.create_datagram_endpoint(lambda: SyslogUDP(), local_addr=("::", 1514))
    print("[UDP] Listening on [::]:1514")

    tcp_server = await asyncio.start_server(handle_tcp, host="::", port=1514)
    print("[TCP] Listening on [::]:1514")

    ssl_ctx = create_ssl_context()
    if ssl_ctx:
        tls_server = await asyncio.start_server(handle_tcp, host="::", port=6514, ssl=ssl_ctx)
        print("[TLS] Listening on [::]:6514")

    await asyncio.Event().wait()


def main():
    try:
        import uvloop
        uvloop.install()
        print("[Syslog] Using uvloop")
    except ImportError:
        print("[Syslog] uvloop not installed (pip install uvloop)")

    asyncio.run(main_async())


_PROCESS = None


def start_syslog_server():
    global _PROCESS

    import multiprocessing

    if _PROCESS is not None:
        return

    ctx = multiprocessing.get_context("spawn")

    _PROCESS = ctx.Process(
        target=main,
        name="pegaprox-syslog",
        daemon=True
    )

    _PROCESS.start()
    print(f"[Syslog] Started (PID: {_PROCESS.pid})")