#!/usr/bin/env python3
import atexit
import concurrent.futures
import http.client
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATED_CONF = REPO_ROOT / "deploy/nginx/generated/oxidity.io.conf"
NGINX_BIN = shutil.which("nginx") or "/usr/sbin/nginx"


class JsonHandler(BaseHTTPRequestHandler):
    server_version = "OxidityTest"
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        return


class MetricsHandler(JsonHandler):
    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/public/summary":
            self._json(
                200,
                {
                    "source": "strategy-metrics-public",
                    "activity": [],
                    "transactions": [],
                    "services": [],
                },
            )
            return
        if self.path == "/partner/summary":
            self._json(
                200,
                {
                    "source": "strategy-metrics-partner",
                    "authorization": self.headers.get("Authorization"),
                },
            )
            return
        self._json(404, {"error": "not_found", "path": self.path})


class RpcHandler(JsonHandler):
    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True})
            return
        self._json(404, {"error": "not_found", "path": self.path})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        if self.headers.get("Authorization") != "Bearer ingress-test-token":
            self._json(401, {"error": "missing_auth"})
            return
        self._json(200, {"jsonrpc": "2.0", "id": 1, "result": "0x1"})


def pick_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def start_server(handler):
    port = pick_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def request(host, port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    send_headers = {"Host": host}
    if headers:
        send_headers.update(headers)
    conn.request(method, path, body=body, headers=send_headers)
    response = conn.getresponse()
    payload = response.read()
    result = {
        "status": response.status,
        "headers": {k.lower(): v for k, v in response.getheaders()},
        "body": payload,
    }
    conn.close()
    return result


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    if not Path(NGINX_BIN).exists():
        raise SystemExit("nginx is required to run deploy ingress tests")

    metrics_server, metrics_port = start_server(MetricsHandler)
    rpc_server, rpc_port = start_server(RpcHandler)
    nginx_port = pick_port()

    tmp_prefix = tempfile.mkdtemp(prefix="oxidity-nginx-")
    atexit.register(lambda: shutil.rmtree(tmp_prefix, ignore_errors=True))

    render_cmd = [
        str(REPO_ROOT / "deploy/nginx/render.sh"),
        str(GENERATED_CONF),
        str(nginx_port),
        f"127.0.0.1:{metrics_port}",
        f"127.0.0.1:{rpc_port}",
    ]
    subprocess.run(render_cmd, check=True, cwd=REPO_ROOT)

    nginx_cmd = [
        NGINX_BIN,
        "-p",
        f"{REPO_ROOT}/",
        "-c",
        "deploy/nginx/nginx.conf",
        "-g",
        "daemon off;",
    ]
    nginx_proc = subprocess.Popen(
        nginx_cmd,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    def cleanup():
        try:
            metrics_server.shutdown()
            metrics_server.server_close()
        finally:
            rpc_server.shutdown()
            rpc_server.server_close()
        if nginx_proc.poll() is None:
            nginx_proc.terminate()
            try:
                nginx_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                nginx_proc.kill()
        GENERATED_CONF.unlink(missing_ok=True)

    atexit.register(cleanup)

    for _ in range(50):
        if nginx_proc.poll() is not None:
            stderr = nginx_proc.stderr.read() if nginx_proc.stderr else ""
            raise RuntimeError(f"nginx exited early: {stderr}")
        try:
            health = request("rpc.oxidity.io", nginx_port, "GET", "/health")
            if health["status"] == 200:
                break
        except OSError:
            pass
        time.sleep(0.1)
    else:
        raise RuntimeError("nginx did not become ready in time")

    public_summary = request("oxidity.io", nginx_port, "GET", "/api/public/summary")
    assert_true(public_summary["status"] == 200, "public summary should proxy successfully")

    partner_summary = request(
        "oxidity.io",
        nginx_port,
        "GET",
        "/api/partner/summary",
        headers={"Authorization": "Bearer partner-token"},
    )
    partner_payload = json.loads(partner_summary["body"])
    assert_true(partner_summary["status"] == 200, "partner summary should proxy successfully")
    assert_true(
        partner_payload.get("authorization") == "Bearer partner-token",
        "partner summary should forward authorization",
    )

    unauthorized = request(
        "rpc.oxidity.io",
        nginx_port,
        "POST",
        "/",
        body=b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}',
        headers={"Content-Type": "application/json"},
    )
    assert_true(unauthorized["status"] == 401, "rpc ingress should reject missing auth")
    assert_true(
        "access-control-allow-origin" not in unauthorized["headers"],
        "rpc ingress should not emit wildcard CORS headers",
    )

    options = request("rpc.oxidity.io", nginx_port, "OPTIONS", "/")
    assert_true(options["status"] == 403, "rpc ingress should reject OPTIONS preflight")
    assert_true(
        "access-control-allow-origin" not in options["headers"],
        "OPTIONS rejection should not emit CORS headers",
    )

    get_root = request("rpc.oxidity.io", nginx_port, "GET", "/")
    assert_true(get_root["status"] == 403, "rpc ingress should reject non-POST root requests")

    def rpc_post():
        result = request(
            "rpc.oxidity.io",
            nginx_port,
            "POST",
            "/",
            body=b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}',
            headers={
                "Authorization": "Bearer ingress-test-token",
                "Content-Type": "application/json",
            },
        )
        return result["status"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
        statuses = list(executor.map(lambda _idx: rpc_post(), range(40)))
    assert_true(429 in statuses, f"expected nginx rate limit to trigger, saw {statuses}")

    cleanup()


if __name__ == "__main__":
    main()
