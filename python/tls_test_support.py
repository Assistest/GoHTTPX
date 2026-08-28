import ast
import json
import re
import socketserver
import ssl
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def load_readme_tls_demo():
    text = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    match = re.search(r"<!-- tls-demo:start -->\s*```python\n(.*?)\n```\s*<!-- tls-demo:end -->", text, re.DOTALL)
    if match is None:
        raise ValueError("README 缺少完整可复制的 TLS 示例代码块")
    source = match.group(1)
    assignments = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "TLS_SPEC_JSON" for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError("README 示例必须有且只有一个内联 TLS_SPEC_JSON")
    return source, json.loads(ast.literal_eval(assignments[0].value))


def parse_client_hello(raw):
    """独立解析网络字节，不借用客户端的 uTLS 配置转换逻辑。"""
    if raw[0] != 1 or int.from_bytes(raw[1:4], "big") != len(raw) - 4:
        raise ValueError("invalid ClientHello handshake length")
    offset = 4

    def take(size):
        nonlocal offset
        value = raw[offset:offset + size]
        offset += size
        if len(value) != size:
            raise ValueError("truncated ClientHello")
        return value

    def vector(width):
        return take(int.from_bytes(take(width), "big"))

    version = int.from_bytes(take(2), "big")
    random = take(32).hex()
    session_id = vector(1).hex()
    ciphers = vector(2)
    compression = list(vector(1))
    extensions = vector(2)
    if offset != len(raw):
        raise ValueError("trailing ClientHello bytes")
    result = {"version": version, "random": random, "session_id": session_id,
              "cipher_suites": [int.from_bytes(ciphers[i:i + 2], "big") for i in range(0, len(ciphers), 2)],
              "compression": compression, "extensions": []}
    offset = 0
    while offset < len(extensions):
        kind = int.from_bytes(extensions[offset:offset + 2], "big")
        length = int.from_bytes(extensions[offset + 2:offset + 4], "big")
        data = extensions[offset + 4:offset + 4 + length]
        if len(data) != length or offset + 4 > len(extensions):
            raise ValueError("truncated TLS extension")
        result["extensions"].append({"id": kind, "data": data.hex()})
        offset += 4 + length
    return result


class TLSCaptureTarget:
    def __init__(self, certificates, require_client_cert=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificates.server_cert_path, certificates.server_key_path)
        context.set_alpn_protocols(["http/1.1"])
        if require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(certificates.ca_path)
        self.server = _CaptureServer(("127.0.0.1", 0), _CaptureHandler)
        self.server.context = context
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.endpoint = f"https://localhost:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


class _CaptureServer(socketserver.ThreadingTCPServer):
    request_queue_size = 128
    daemon_threads = True


class _CaptureHandler(socketserver.BaseRequestHandler):
    def read_exact(self, size):
        data = bytearray()
        while len(data) < size:
            chunk = self.request.recv(size - len(data))
            if not chunk:
                raise EOFError("closed TLS socket")
            data.extend(chunk)
        return bytes(data)

    def exchange(self, operation):
        while True:
            need_read = False
            try:
                result = operation()
            except ssl.SSLWantReadError:
                need_read = True
            finally:
                outgoing = self.outgoing.read()
                if outgoing:
                    self.request.sendall(outgoing)
            if not need_read:
                return result
            data = self.request.recv(65536)
            if not data:
                raise EOFError("closed TLS socket")
            self.incoming.write(data)

    def handle(self):
        self.request.settimeout(10)
        try:
            records, hello = bytearray(), bytearray()
            while len(hello) < 4 or len(hello) < 4 + int.from_bytes(hello[1:4], "big"):
                header = self.read_exact(5)
                size = int.from_bytes(header[3:5], "big")
                if header[0] != 22 or size > 18432 or len(records) > 65536:
                    raise ValueError("invalid TLS handshake record")
                body = self.read_exact(size)
                records.extend(header + body)
                hello.extend(body)
            handshake_size = 4 + int.from_bytes(hello[1:4], "big")
            observed = parse_client_hello(bytes(hello[:handshake_size]))
            self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            self.incoming.write(bytes(records))
            connection = self.server.context.wrap_bio(self.incoming, self.outgoing, server_side=True)
            self.exchange(connection.do_handshake)
            request = bytearray()
            while b"\r\n\r\n" not in request:
                request.extend(self.exchange(lambda: connection.read(65536)))
                if len(request) > 65536:
                    raise ValueError("oversized HTTP header")
            lines = bytes(request).split(b"\r\n")
            path = lines[0].split(b" ")[1].decode("ascii")
            headers = {name.lower(): value for name, value in (line.split(b":", 1) for line in lines[1:] if b":" in line)}
            owner = parse_qs(urlsplit(path).query).get("owner", [""])[0]
            payload = json.dumps({"hello": observed, "raw_hello": bytes(hello[:handshake_size]).hex(),
                                  "cookie": headers.get(b"cookie", b"").strip().decode(),
                                  "user_agent": headers.get(b"user-agent", b"").strip().decode(),
                                  "peer_cert_present": bool(connection.getpeercert()),
                                  "tls_version": connection.version(), "alpn": connection.selected_alpn_protocol()}).encode()
            response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
            if owner:
                response += f"Set-Cookie: owner={owner}; Path=/\r\n".encode()
            response += f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload
            self.exchange(lambda: connection.write(response))
        except (OSError, EOFError):
            # 证书拒绝和主动断开是负向用例的正常路径。
            return
