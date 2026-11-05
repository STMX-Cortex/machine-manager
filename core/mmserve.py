# SPDX-License-Identifier: Apache-2.0
"""Foreground, loopback-only hosting of cached monitoring data. No collection or control endpoints."""
import http.server
import json
import re
import signal
import socket
import socketserver
import threading
import time

import mmcore
import mmfleet
import mmprometheus
import mmstorage_fleet

PORT = 9877
CONNECTIONS = 4
TIMEOUT_S = 3
CONNECTION_WALL_S = 10
RESPONSE_BYTES = 16 << 20
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
READINGS = ("free_pct", "swap_used_mb", "swap_total_mb", "comp_mb", "pressure", "seg_pct", "load1", "load5",
            "sys_pct", "cpu_pct", "psi_some_pct", "psi_full_pct")


def settings():
    # Like `mm metrics`: never save settings or change their last-good file on a read.
    return mmcore.Settings().peek() or mmcore.resolve(mmcore.defaults())


def public_status(profile, s, now):
    """A small field allowlist; never publish reason text, heartbeat notes, arbitrary keys or raw files."""
    doc = mmprometheus.read_snapshot(mmcore.path("status.json"), mmprometheus.STATUS_BYTES)
    ident = mmcore.machine_id(profile)
    if not mmprometheus.valid_status(doc, ident):
        return None
    out = {k: doc[k] for k in ("kind", "schema_version", "machine_id", "time", "state", "mode", "slots",
                              "slots_would", "busy", "waiting", "calls", "disk_gb", "idle_minutes") if k in doc}
    out["readings"] = {k: v for k, v in mmprometheus.mapping(doc.get("readings")).items() if k in READINGS}
    out["facts"] = {k: v for k, v in mmprometheus.mapping(doc.get("facts")).items()
                    if k in ("cores", "p_cores", "e_cores", "ram_mb", "disk_gb_total")}
    out["alerts"] = {k: v for k, v in mmprometheus.mapping(doc.get("alerts")).items()
                     if k in ("ACTION", "ATTENTION", "INFO")}
    try:
        return mmfleet.validate_status(out, {"id": ident, "status_url": "http://localhost/status.json",
                                            "stale_after_s": s["other.status_fresh_s"]}, now)
    except (ValueError, RecursionError):
        return None


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """At most four connections; finite reads/writes, no directory serving, access logs or keep-alive."""
    daemon_threads = False
    block_on_close = True
    request_queue_size = CONNECTIONS
    allow_reuse_address = True

    def __init__(self, profile, bind="127.0.0.1", port=PORT):
        if bind not in ("127.0.0.1", "::1") or type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid loopback address or port")
        self.profile = profile
        self.workers = threading.BoundedSemaphore(CONNECTIONS)
        self.address_family = socket.AF_INET6 if bind == "::1" else socket.AF_INET
        super().__init__((bind, port), Handler)

    def server_bind(self):
        # HTTPServer.server_bind calls getfqdn(), which may block on reverse DNS even for loopback on macOS.
        # No DNS or external name is needed: this listener accepts numeric loopback addresses only.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(TIMEOUT_S)
        return request, address

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        # Socket timeouts alone reset on each byte; a wall deadline also stops slow/dripping clients.
        deadline = threading.Timer(CONNECTION_WALL_S, self.expire_connection, args=(request,))
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            deadline.join()
            self.workers.release()

    def expire_connection(self, request):
        # TCPServer.shutdown_request shuts down only writes. Both halves must stop: makefile() retains the
        # descriptor, so close() alone can leave a handler reading a client that keeps dripping bytes.
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.close_request(request)

    def handle_error(self, request, client_address):
        pass  # outside requests and local paths never become log messages


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "machine-manager"
    sys_version = ""

    def log_message(self, *args):
        pass

    def reply(self, code, body, content_type="text/plain; charset=utf-8"):
        self.close_connection = True
        if len(body) > RESPONSE_BYTES:
            code, body, content_type = 503, b"monitoring data unavailable\n", "text/plain; charset=utf-8"
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        if code == 405:
            self.send_header("Allow", "GET, HEAD")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        self.reply(code, b"request rejected\n")

    def do_GET(self):
        hosts = self.headers.get_all("Host", [])
        # Reject browser DNS rebinding; tunnels and reverse proxies must retain/set a loopback Host.
        if len(hosts) != 1 or not re.fullmatch(r"(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?", hosts[0], re.I):
            self.reply(403, b"loopback Host required\n")
            return
        # BaseHTTPRequestHandler normalizes leading //; require the original request target too.
        if self.path not in ("/metrics", "/status.json", "/storage.json", "/-/healthy") \
                or self.requestline.split()[1] != self.path:
            self.reply(404, b"not found\n")
            return
        if self.path == "/-/healthy":
            self.reply(200, b"ok\n")  # process health, independent of supervisor freshness
            return
        try:
            s, now = settings(), time.time()
            if self.path == "/metrics":
                text, _ = mmprometheus.export(self.server.profile, s, now)
                self.reply(200, text.encode("utf-8"), CONTENT_TYPE)
            elif self.path == "/storage.json":
                # The local snapshot only (valid, this machine, fresh), re-serialized; never peer caches or raw files.
                doc = mmstorage_fleet.local(self.server.profile, now)
                body = mmstorage_fleet.dumps(doc).encode("ascii") if doc is not None else b""
                if doc is None or len(body) > mmstorage_fleet.SNAPSHOT_BYTES:
                    self.reply(503, b"storage snapshot unavailable\n")
                else:
                    self.reply(200, body, "application/json")
            else:
                status = public_status(self.server.profile, s, now)
                if status is None:
                    self.reply(503, b"machine status unavailable\n")
                else:
                    self.reply(200, (json.dumps(status, allow_nan=False, ensure_ascii=True) + "\n").encode(),
                               "application/json")
        except (OSError, ValueError, TypeError, KeyError, RecursionError, mmcore.MMError):
            self.reply(503, b"monitoring data unavailable\n")

    do_HEAD = do_GET

    def do_POST(self):
        self.reply(405, b"method not allowed\n")

    do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_POST


def run(profile, bind, port):
    """Run until Ctrl-C/SIGTERM. No installs, daemonization, writes, subprocesses or outbound requests."""
    def stop(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, stop)
    try:
        with Server(profile, bind, port) as server:
            print("serve=ready bind=%s port=%d" % (bind, server.server_port), flush=True)
            try:
                server.serve_forever(poll_interval=0.2)
            except KeyboardInterrupt:
                pass
    finally:
        signal.signal(signal.SIGTERM, previous)
    return 0
