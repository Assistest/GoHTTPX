import base64
import json
import os
import threading
import time
import unittest
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx

from gohttpx import (
    Client,
    ClientOptions,
    GoProtocolError,
    GoServiceUnavailable,
    HTTP2Options,
    HTTP2Setting,
    PriorityFrame,
    PriorityParam,
    RequestOptions,
    RetryOptions,
    TLSFingerprint,
    TransportOptions,
)


FINGERPRINTS = [
    "golang",
    "randomized",
    "randomized_alpn",
    "randomized_no_alpn",
    "android_11_okhttp",
    "chrome_auto",
    "chrome_58",
    "chrome_62",
    "chrome_70",
    "chrome_72",
    "chrome_83",
    "chrome_87",
    "chrome_96",
    "chrome_100",
    "chrome_102",
    "chrome_106_shuffle",
    "chrome_100_psk",
    "chrome_112_psk_shuffle",
    "chrome_114_padding_psk_shuffle",
    "chrome_115_pq",
    "chrome_115_pq_psk",
    "chrome_120",
    "chrome_120_pq",
    "chrome_131",
    "chrome_133",
    "firefox_auto",
    "firefox_55",
    "firefox_56",
    "firefox_63",
    "firefox_65",
    "firefox_99",
    "firefox_102",
    "firefox_105",
    "firefox_120",
    "ios_auto",
    "ios_11_1",
    "ios_12_1",
    "ios_13",
    "ios_14",
    "edge_auto",
    "edge_85",
    "edge_106",
    "safari_auto",
    "safari_16_0",
    "360_auto",
    "360_7_5",
    "360_11_0",
    "qq_auto",
    "qq_11_1",
]


class FakeGo:
    def __init__(self):
        self.calls = []
        self.capabilities_response = None
        self.create_response = None
        self.request_response = None
        self.request_started = threading.Event()
        self.release_request = threading.Event()
        self.block_requests = False


class FakeGoHandler(BaseHTTPRequestHandler):
    server_version = "FakeGo/1"

    @property
    def state(self):
        return self.server.state

    def log_message(self, _format, *_args):
        pass

    def _body(self):
        size = int(self.headers.get("content-length", "0"))
        return self.rfile.read(size)

    def _record(self, payload=None):
        self.state.calls.append(
            {
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("authorization"),
                "payload": payload,
            }
        )

    def _send(self, status, body=b"", content_type="application/json; charset=utf-8"):
        self.send_response(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, payload, content_type="application/json; charset=utf-8"):
        self._send(
            status,
            json.dumps(payload, separators=(",", ":")).encode(),
            content_type,
        )

    def do_GET(self):
        self._record()
        if self.path != "/api/v1/capabilities":
            self._json(404, {"error": {"code": "INVALID_REQUEST", "message": "not found", "retryable": False}})
            return
        if self.state.capabilities_response is not None:
            status, body, content_type = self.state.capabilities_response
            self._send(status, body, content_type)
            return
        self._json(
            200,
            {
                "protocol_version": 1,
                "server_version": "1.0.0",
                "max_body_bytes": 48 << 20,
                "tls_fingerprints": FINGERPRINTS,
            },
        )

    def do_POST(self):
        body = self._body()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        self._record(payload)
        if self.path == "/api/v1/clients":
            if self.state.create_response is not None:
                status, raw, content_type = self.state.create_response
                self._send(status, raw, content_type)
                return
            self._json(
                201,
                {
                    "protocol_version": 1,
                    "client_id": "client-1",
                    "expires_at": "2026-07-14T00:00:00Z",
                },
            )
            return
        if self.path != "/api/v1/clients/client-1/requests":
            self._json(404, {"error": {"code": "CLIENT_NOT_FOUND", "message": "missing", "retryable": False, "request_id": "req-error"}})
            return
        self.state.request_started.set()
        if self.state.block_requests:
            self.state.release_request.wait(2)
        if self.state.request_response is not None:
            status, raw, content_type = self.state.request_response
            self._send(status, raw, content_type)
            return

        target_path = urlsplit(payload["url"]).path
        status_code = 200
        reason_phrase = "OK"
        headers = [["Content-Type", "application/json"], ["X-Dupe", "a"], ["X-Dupe", "b"]]
        response_body = b'{"res":"ok"}'
        protocol = "HTTP/2.0"
        trace = None
        dump = None
        if target_path == "/binary":
            status_code = 201
            reason_phrase = "Cr\xe9ated"
            response_body = b"\x00\xffbody"
            protocol = "HTTP/1.0"
            trace = {
                "dns_lookup_ms": 1.0,
                "connect_ms": 2.0,
                "tls_handshake_ms": 3.0,
                "first_byte_ms": 4.0,
                "response_ms": 5.0,
                "total_ms": 15.0,
                "connection_reused": True,
                "remote_address": "127.0.0.1:443",
            }
            dump = "wire dump"
        elif target_path == "/set-cookie":
            headers.append(["Set-Cookie", "session=one; Path=/"])
        elif target_path == "/redirect":
            status_code = 302
            reason_phrase = "Found"
            headers = [["Location", "https://target.test/final"], ["Set-Cookie", "hop=one; Path=/"]]
            response_body = b""
            protocol = "HTTP/1.1"
        elif target_path == "/final":
            protocol = "HTTP/3.0"
        self._json(
            200,
            {
                "protocol_version": 1,
                "request_id": "req-1",
                "status_code": status_code,
                "reason_phrase": reason_phrase,
                "headers": headers,
                "body_base64": base64.b64encode(response_body).decode(),
                "url": payload["url"],
                "http_version": protocol,
                "elapsed_ms": 12.5,
                "trace": trace,
                "dump": dump,
            },
        )

    def do_DELETE(self):
        self._record()
        self._send(204, b"", None)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.state = FakeGo()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGoHandler)
        self.server.state = self.state
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.endpoint = f"http://{host}:{port}"

    def tearDown(self):
        self.state.release_request.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_enum_matches_go_capabilities_and_default_create_contract(self):
        self.assertEqual({item.value for item in TLSFingerprint}, set(FINGERPRINTS))
        self.assertEqual(len(TLSFingerprint), 49)
        client = Client(go_endpoint=self.endpoint, go_token="secret")
        client.close()

        self.assertEqual(
            [(call["method"], call["path"]) for call in self.state.calls],
            [
                ("GET", "/api/v1/capabilities"),
                ("POST", "/api/v1/clients"),
                ("DELETE", "/api/v1/clients/client-1"),
            ],
        )
        self.assertTrue(all(call["authorization"] == "Bearer secret" for call in self.state.calls))
        create = self.state.calls[1]["payload"]
        self.assertEqual(create["protocol_version"], 1)
        self.assertEqual(create["tls_fingerprint"], "android_11_okhttp")
        self.assertEqual(create["impersonate"], "none")
        self.assertEqual(create["http_version"], "auto")
        self.assertTrue(create["verify"])

    def test_explicit_fingerprint_and_all_client_options_are_serialized(self):
        options = ClientOptions(
            tls_fingerprint=TLSFingerprint.CHROME_120,
            proxy_url="http://proxy.test:8080",
            verify=False,
            root_ca_pem="ca",
            client_cert_pem="cert",
            client_key_pem="key",
            http_version="http2",
            keep_alive=False,
            compression=True,
            allow_get_body=False,
            retry=RetryOptions(count=2, mode="fixed", fixed_interval_ms=10, status_codes=(503,)),
            transport=TransportOptions(
                tls_handshake_timeout_ms=11,
                response_header_timeout_ms=12,
                expect_continue_timeout_ms=13,
                idle_conn_timeout_ms=14,
                max_idle_conns=15,
                max_idle_conns_per_host=16,
                max_conns_per_host=17,
                max_response_header_bytes=18,
                read_buffer_size=19,
                write_buffer_size=20,
                proxy_connect_headers={"X-Proxy": ("a", "b")},
            ),
            http2=HTTP2Options(
                settings=(HTTP2Setting(id=1, value=2),),
                connection_flow=3,
                header_priority=PriorityParam(stream_dependency=4, exclusive=True, weight=5),
                priority_frames=(PriorityFrame(stream_id=6, priority=PriorityParam(weight=7)),),
                max_header_list_size=8,
                strict_max_concurrent_streams=True,
                read_idle_timeout_ms=9,
                ping_timeout_ms=10,
                write_byte_timeout_ms=11,
            ),
        )
        with Client(go_endpoint=self.endpoint, client_options=options):
            pass
        create = self.state.calls[1]["payload"]
        self.assertNotIn("protocol_version", asdict(options))
        self.assertEqual(create["tls_fingerprint"], "chrome_120")
        self.assertEqual(create["retry"]["status_codes"], [503])
        self.assertEqual(create["transport"]["proxy_connect_headers"], {"X-Proxy": ["a", "b"]})
        self.assertEqual(create["http2"]["priority_frames"][0]["priority"]["weight"], 7)

    def test_prepared_json_data_files_and_content_are_forwarded_as_bytes(self):
        with Client(go_endpoint=self.endpoint) as client:
            json_response = client.post("https://target.test/json", json={"name": "test"})
            client.put("https://target.test/data", data={"a": "b"})
            client.patch("https://target.test/files", files={"f": ("a.txt", b"file-bytes")})
            client.request("CUSTOM", "https://target.test/raw", content=b"\x00raw")
            client.delete("https://target.test/delete")
            client.head("https://target.test/head")
            client.options("https://target.test/options")

        requests = [call["payload"] for call in self.state.calls if call["path"].endswith("/requests")]
        bodies = [base64.b64decode(item["body_base64"], validate=True) for item in requests]
        self.assertEqual(bodies[0], b'{"name":"test"}')
        self.assertEqual(json_response.json(), {"res": "ok"})
        self.assertEqual(json_response.text, '{"res":"ok"}')
        self.assertEqual(bodies[1], b"a=b")
        self.assertIn(b'filename="a.txt"', bodies[2])
        self.assertIn(b"file-bytes", bodies[2])
        self.assertEqual(bodies[3], b"\x00raw")
        self.assertEqual(
            [item["method"] for item in requests],
            ["POST", "PUT", "PATCH", "CUSTOM", "DELETE", "HEAD", "OPTIONS"],
        )
        self.assertTrue(all(item["timeout_ms"] == 5000 for item in requests))

    def test_headers_cookies_duplicate_order_and_token_isolation(self):
        with Client(
            go_endpoint=self.endpoint,
            go_token="local-secret",
            headers=[("X-Default", "one"), ("X-Dupe", "a"), ("X-Dupe", "b")],
            cookies={"initial": "yes"},
        ) as client:
            client.get("https://target.test/set-cookie")
            client.headers["X-Default"] = "two"
            client.get("https://target.test/next")

        requests = [call["payload"] for call in self.state.calls if call["path"].endswith("/requests")]
        first_headers = requests[0]["headers"]
        second_headers = requests[1]["headers"]
        self.assertEqual([pair[1] for pair in first_headers if pair[0].lower() == "x-dupe"], ["a", "b"])
        self.assertIn("initial=yes", next(pair[1] for pair in first_headers if pair[0].lower() == "cookie"))
        second_cookie = next(pair[1] for pair in second_headers if pair[0].lower() == "cookie")
        self.assertIn("session=one", second_cookie)
        self.assertIn("two", [pair[1] for pair in second_headers if pair[0].lower() == "x-default"])
        self.assertFalse(any(pair[0].lower() == "authorization" and "local-secret" in pair[1] for pair in first_headers + second_headers))

    def test_real_response_preserves_binary_headers_version_reason_request_trace_dump(self):
        with Client(go_endpoint=self.endpoint) as client:
            response = client.get(
                "https://target.test/binary",
                extensions={"go_req": RequestOptions(trace=True, dump=True)},
            )

        self.assertIsInstance(response, httpx.Response)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, b"\x00\xffbody")
        self.assertEqual(response.text, "\x00\ufffdbody")
        self.assertEqual(response.headers.get_list("x-dupe"), ["a", "b"])
        self.assertEqual(
            [pair for pair in response.headers.raw if pair[0].lower() == b"x-dupe"],
            [(b"X-Dupe", b"a"), (b"X-Dupe", b"b")],
        )
        self.assertFalse(any(name.lower() == b"content-length" for name, _ in response.headers.raw))
        self.assertEqual(response.http_version, "HTTP/1.0")
        self.assertEqual(response.reason_phrase, "Crated")
        self.assertEqual(response.extensions["reason_phrase"], b"Cr\xe9ated")
        self.assertEqual(response.request.method, "GET")
        self.assertEqual(response.request.url, httpx.URL("https://target.test/binary"))
        self.assertTrue(response.extensions["go_trace"]["connection_reused"])
        self.assertEqual(response.extensions["go_dump"], "wire dump")

    def test_http_version_mapping_does_not_corrupt_http_1_0_or_http_3(self):
        with Client(go_endpoint=self.endpoint, follow_redirects=True) as client:
            response = client.get("https://target.test/redirect")
        self.assertEqual(response.http_version, "HTTP/3")
        self.assertEqual(response.history[0].http_version, "HTTP/1.1")
        requests = [call["payload"] for call in self.state.calls if call["path"].endswith("/requests")]
        self.assertEqual([item["url"] for item in requests], ["https://target.test/redirect", "https://target.test/final"])
        final_cookie = next(pair[1] for pair in requests[1]["headers"] if pair[0].lower() == "cookie")
        self.assertIn("hop=one", final_cookie)

    def test_request_options_accept_dataclass_or_strict_mapping_without_mutation(self):
        mapping = {
            "header_order": ["x-b", "x-a"],
            "pseudo_header_order": [":method", ":path"],
            "force_chunked": True,
            "close_connection": True,
            "trace": True,
            "dump": True,
            "retry_count": 2,
        }
        expected = json.loads(json.dumps(mapping))
        with Client(go_endpoint=self.endpoint) as client:
            client.post("https://target.test/a", extensions={"go_req": mapping})
        request = next(call["payload"] for call in self.state.calls if call["path"].endswith("/requests"))
        self.assertEqual(request["options"], expected)
        self.assertEqual(mapping, expected)

    def test_invalid_request_options_are_rejected(self):
        invalid = [
            {"unknown": True},
            {"trace": "yes"},
            {"header_order": "x-a"},
            {"retry_count": True},
            object(),
        ]
        with Client(go_endpoint=self.endpoint) as client:
            for value in invalid:
                with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                    client.get("https://target.test/a", extensions={"go_req": value})

    def test_control_errors_and_bad_envelopes_raise_protocol_error_with_request(self):
        cases = [
            (400, {"error": {"code": "INVALID_REQUEST", "message": "bad", "retryable": False, "request_id": "req-e"}}, "application/json"),
            (200, {"protocol_version": 2}, "application/json"),
            (200, {"protocol_version": 1}, "application/json"),
            (200, {"protocol_version": 1, "request_id": "x", "status_code": 200, "reason_phrase": "OK", "headers": [["x", "a", "b"]], "body_base64": "", "url": "https://target.test/a", "http_version": "HTTP/1.1", "elapsed_ms": 1, "trace": None}, "application/json"),
            (200, {"protocol_version": 1, "request_id": "x", "status_code": 200, "reason_phrase": "OK", "headers": [], "body_base64": "***", "url": "https://target.test/a", "http_version": "HTTP/1.1", "elapsed_ms": 1, "trace": None}, "application/json"),
            (200, {"protocol_version": 1, "request_id": "x", "status_code": 200, "reason_phrase": "OK", "headers": [], "body_base64": "", "url": "https://target.test/a", "http_version": [], "elapsed_ms": 1, "trace": None}, "application/json"),
            (200, {"protocol_version": True, "request_id": "x", "status_code": 200, "reason_phrase": "OK", "headers": [], "body_base64": "", "url": "https://target.test/a", "http_version": "HTTP/1.1", "elapsed_ms": 1, "trace": None}, "application/json"),
            (200, {}, "text/plain"),
        ]
        for status, payload, content_type in cases:
            with self.subTest(payload=payload, content_type=content_type):
                self.state.request_response = (
                    status,
                    json.dumps(payload).encode(),
                    content_type,
                )
                with Client(go_endpoint=self.endpoint) as client:
                    with self.assertRaises(GoProtocolError) as caught:
                        client.get("https://target.test/a")
                self.assertIsNotNone(caught.exception.request)
        error = cases[0][1]["error"]
        self.assertEqual(error["code"], "INVALID_REQUEST")

    def test_capability_and_create_failures_are_strict_and_cleanup_control_client(self):
        self.state.capabilities_response = (200, b'{"protocol_version":2}', "application/json")
        with self.assertRaises(GoProtocolError):
            Client(go_endpoint=self.endpoint)
        self.assertEqual(len(self.state.calls), 1)

        self.state.calls.clear()
        self.state.capabilities_response = None
        self.state.create_response = (
            400,
            b'{"error":{"code":"UNAUTHORIZED","message":"no","retryable":false}}',
            "application/json",
        )
        with self.assertRaises(GoProtocolError) as caught:
            Client(go_endpoint=self.endpoint)
        self.assertEqual(caught.exception.code, "UNAUTHORIZED")
        with self.assertRaises(RuntimeError):
            _ = caught.exception.request

    def test_parent_initialization_failure_deletes_created_session(self):
        with self.assertRaises(TypeError):
            Client(go_endpoint=self.endpoint, auth=object())
        self.assertEqual(
            [(call["method"], call["path"]) for call in self.state.calls],
            [
                ("GET", "/api/v1/capabilities"),
                ("POST", "/api/v1/clients"),
                ("DELETE", "/api/v1/clients/client-1"),
            ],
        )

    def test_service_unavailable_and_control_client_ignores_environment_proxy(self):
        probe = ThreadingHTTPServer(("127.0.0.1", 0), FakeGoHandler)
        host, port = probe.server_address
        probe.server_close()
        with self.assertRaises(GoServiceUnavailable):
            Client(go_endpoint=f"http://{host}:{port}")

        old_proxy = os.environ.get("HTTP_PROXY")
        old_no_proxy = os.environ.get("NO_PROXY")
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:1"
        os.environ["NO_PROXY"] = ""
        try:
            with Client(go_endpoint=self.endpoint):
                pass
        finally:
            if old_proxy is None:
                os.environ.pop("HTTP_PROXY", None)
            else:
                os.environ["HTTP_PROXY"] = old_proxy
            if old_no_proxy is None:
                os.environ.pop("NO_PROXY", None)
            else:
                os.environ["NO_PROXY"] = old_no_proxy

    def test_transport_and_mounts_are_rejected(self):
        transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
        with self.assertRaises(TypeError):
            Client(go_endpoint=self.endpoint, transport=transport)
        with self.assertRaises(TypeError):
            Client(go_endpoint=self.endpoint, mounts={})
        self.assertEqual(self.state.calls, [])

    def test_http_version_convenience_matches_httpx_defaults(self):
        with self.assertRaises(ValueError):
            Client(go_endpoint=self.endpoint, http1=False)
        self.assertEqual(self.state.calls, [])

        with Client(go_endpoint=self.endpoint, http1=True, http2=False):
            pass
        self.assertEqual(self.state.calls[1]["payload"]["http_version"], "http1")
        self.state.calls.clear()
        with Client(go_endpoint=self.endpoint, http2=True):
            pass
        self.assertEqual(self.state.calls[1]["payload"]["http_version"], "auto")

    def test_close_is_idempotent_and_waits_for_active_request(self):
        self.state.block_requests = True
        client = Client(go_endpoint=self.endpoint)
        result = []
        request_thread = threading.Thread(
            target=lambda: result.append(client.get("https://target.test/a")),
            daemon=True,
        )
        request_thread.start()
        self.assertTrue(self.state.request_started.wait(1))
        close_thread = threading.Thread(target=client.close, daemon=True)
        close_thread.start()
        time.sleep(0.05)
        self.assertTrue(close_thread.is_alive())
        self.state.release_request.set()
        request_thread.join(1)
        close_thread.join(1)
        client.close()
        self.assertEqual(result[0].status_code, 200)
        paths = [call["path"] for call in self.state.calls]
        self.assertLess(paths.index("/api/v1/clients/client-1/requests"), paths.index("/api/v1/clients/client-1"))
        self.assertEqual(paths.count("/api/v1/clients/client-1"), 1)


if __name__ == "__main__":
    unittest.main()
