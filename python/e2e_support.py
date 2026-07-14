import base64
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlsplit
from urllib.request import parse_http_list, parse_keqv_list

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import httpx


def reserve_loopback_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for_health(endpoint, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Go 服务提前退出，exit code={process.returncode}")
        try:
            if httpx.get(endpoint + "/api/v1/health", timeout=0.2, trust_env=False).status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"Go 服务 health 超时，exit code={process.poll()}")


class HTTPFixture:
    def __init__(self):
        self.calls = []
        self.lock = threading.Lock()
        self.retry_remaining = 1
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _HTTPFixtureHandler)
        self.server.fixture = self
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.endpoint = f"http://{host}:{port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


class _HTTPFixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        try:
            super().handle()
        except ConnectionError:
            pass

    def log_message(self, _format, *_args):
        pass

    def _body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0], 16)
                if not size:
                    self.rfile.readline()
                    return b"".join(chunks)
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def _send(self, status=200, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except ConnectionError:
                pass

    def _json(self, payload, status=200, headers=()):
        self._send(status, json.dumps(payload, separators=(",", ":")).encode(), (("Content-Type", "application/json"), *headers))

    def _handle(self):
        body = self._body()
        parsed = urlsplit(self.path)
        call = {
            "method": self.command,
            "path": parsed.path,
            "query": parse_qs(parsed.query, keep_blank_values=True),
            "query_items": parse_qsl(parsed.query, keep_blank_values=True),
            "headers": list(self.headers.raw_items()),
            "body": body,
        }
        fixture = self.server.fixture
        with fixture.lock:
            fixture.calls.append(call)

        if parsed.path == "/echo/method":
            self._json({"method": self.command})
        elif parsed.path == "/echo/body":
            self._json({"body_base64": base64.b64encode(body).decode()})
        elif parsed.path == "/echo/headers":
            self._json({"query": call["query"], "headers": call["headers"]})
        elif parsed.path == "/redirect/chain":
            self._send(302, headers=(("Location", "/redirect/chain/final"),))
        elif parsed.path == "/redirect/chain/final":
            self._json({"redirected": True})
        elif parsed.path == "/cookies/set":
            self._send(204, headers=(("Set-Cookie", "server=one; Path=/"),))
        elif parsed.path == "/cookies/show":
            self._json({"cookie": self.headers.get("Cookie", "")})
        elif parsed.path == "/auth/basic":
            expected = "Basic " + base64.b64encode(b"user:pass").decode()
            if self.headers.get("Authorization") == expected:
                self._json({"authenticated": True})
            else:
                self._send(401, headers=(("WWW-Authenticate", 'Basic realm="loopback"'),))
        elif parsed.path == "/auth/digest":
            scheme, _, fields = self.headers.get("Authorization", "").partition(" ")
            parsed_fields = parse_keqv_list(parse_http_list(fields)) if fields else {}
            if scheme == "Digest" and {"username", "response", "nonce"}.issubset(parsed_fields):
                self._json({"authenticated": True})
            else:
                self._send(401, headers=(("WWW-Authenticate", 'Digest realm="loopback", nonce="fixed-nonce", algorithm=MD5, qop="auth"'),))
        elif parsed.path.startswith("/status/"):
            self._send(int(parsed.path.rsplit("/", 1)[1]), b"status")
        elif parsed.path == "/slow":
            time.sleep(float(call["query"].get("seconds", ["0.2"])[0]))
            self._send(204)
        elif parsed.path == "/binary":
            self._send(201, b"\x00\xffresponse", (("Content-Type", "application/octet-stream"),))
        elif parsed.path == "/trace-dump":
            self._json({"trace_dump": True})
        elif parsed.path == "/retry":
            with fixture.lock:
                should_fail = fixture.retry_remaining > 0
                fixture.retry_remaining -= 1
            self._send(503 if should_fail else 200, b"retry")
        else:
            self._send(404)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle
    do_PURGE = _handle


class GoHTTPXService:
    def __init__(self, module_dir):
        self.module_dir = Path(module_dir)
        handle, name = tempfile.mkstemp(prefix="gohttpx-test-", suffix=".exe")
        self.exe_path = Path(name).resolve()
        self.endpoint = ""
        self.token = "e2e-fixed-token"
        self.process = None
        os.close(handle)
        self.exe_path.unlink()

    def start(self):
        built = subprocess.run(
            ["go", "build", "-o", str(self.exe_path), "."],
            cwd=self.module_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        if built.returncode:
            self.close()
            raise RuntimeError(f"go build 失败 ({built.returncode}):\n{built.stdout}{built.stderr}")
        port = reserve_loopback_port()
        self.endpoint = f"http://127.0.0.1:{port}"
        try:
            self.process = subprocess.Popen(
                [str(self.exe_path), "--host", "127.0.0.1", "--port", str(port), "--token", self.token],
                cwd=self.module_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_for_health(self.endpoint, self.process)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        if self.exe_path.exists():
            self.exe_path.unlink()
        if self.exe_path.exists():
            raise AssertionError(f"临时 EXE 清理失败: {self.exe_path}")


class TransportTarget:
    def __init__(self, module_dir):
        self.module_dir = Path(module_dir)
        self.target_dir = (self.module_dir / "testdata" / "e2e-target").resolve()
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gohttpx-transport-")
        self.temp_path = Path(self.temp_dir.name).resolve()
        handle, name = tempfile.mkstemp(prefix="gohttpx-target-", suffix=".exe")
        self.exe_path = Path(name).resolve()
        os.close(handle)
        self.exe_path.unlink()
        self.process = None
        self.ca_path = self.temp_path / "ca.pem"
        self.server_cert_path = self.temp_path / "server.pem"
        self.server_key_path = self.temp_path / "server-key.pem"
        self.client_cert_path = self.temp_path / "client.pem"
        self.client_key_path = self.temp_path / "client-key.pem"
        self.log_path = self.temp_path / "target.log"
        self.log_file = None
        self._write_certificates()
        self.http_endpoint = ""
        self.https_endpoint = ""
        self.h2c_endpoint = ""
        self.http3_endpoint = ""
        self.mtls_endpoint = ""

    def _write_certificates(self):
        now = datetime.now(timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GoHTTPX E2E CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(1)
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        self.ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        self._write_leaf(ca_cert, ca_key, self.server_cert_path, self.server_key_path, 2, False)
        self._write_leaf(ca_cert, ca_key, self.client_cert_path, self.client_key_path, 3, True)

    def _write_leaf(self, ca_cert, ca_key, cert_path, key_path, serial, client):
        key = ec.generate_private_key(ec.SECP256R1())
        usage = ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GoHTTPX E2E client" if client else "127.0.0.1")]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        )
        if not client:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        cert_path.write_bytes(builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def start(self):
        built = subprocess.run(
            ["go", "build", "-o", str(self.exe_path), "."],
            cwd=self.target_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        if built.returncode:
            self.close()
            raise RuntimeError(f"测试靶场构建失败 ({built.returncode}):\n{built.stdout}{built.stderr}")
        ports = [reserve_loopback_port() for _ in range(5)]
        self.http_endpoint = f"http://127.0.0.1:{ports[0]}"
        self.https_endpoint = f"https://127.0.0.1:{ports[1]}"
        self.h2c_endpoint = f"http://127.0.0.1:{ports[2]}"
        self.http3_endpoint = f"https://127.0.0.1:{ports[3]}"
        self.mtls_endpoint = f"https://127.0.0.1:{ports[4]}"
        args = [
            str(self.exe_path),
            "--http-port", str(ports[0]),
            "--https-port", str(ports[1]),
            "--h2c-port", str(ports[2]),
            "--http3-port", str(ports[3]),
            "--mtls-port", str(ports[4]),
            "--server-cert", str(self.server_cert_path),
            "--server-key", str(self.server_key_path),
            "--ca-cert", str(self.ca_path),
        ]
        try:
            self.log_file = self.log_path.open("wb")
            self.process = subprocess.Popen(args, cwd=self.target_dir, stdout=subprocess.DEVNULL, stderr=self.log_file)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError(f"测试靶场提前退出，exit code={self.process.returncode}")
                try:
                    with socket.create_connection(("127.0.0.1", ports[1]), timeout=0.2):
                        return
                except OSError:
                    time.sleep(0.05)
            raise RuntimeError(f"测试靶场启动超时，exit code={self.process.poll()}")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        if self.exe_path.exists():
            self.exe_path.unlink()
        if self.log_file is not None:
            self.log_file.close()
            self.log_file = None
        self.temp_dir.cleanup()
