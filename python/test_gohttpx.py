import asyncio
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
    AsyncClient,
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
        self.lock = threading.Lock()
        self.create_count = 0
        self.capabilities_response = None
        self.create_response = None
        self.request_response = None
        self.delete_response = None
        self.enforce_http3_create = False
        self.not_found_remaining = 0
        self.stale_client_id = None
        self.stale_expected = 0
        self.stale_seen = 0
        self.stale_ready = threading.Event()
        self.drop_request_connection = False
        self.request_started = threading.Event()
        self.release_request = threading.Event()
        self.create_started = threading.Event()
        self.release_create = threading.Event()
        self.block_requests = False
        self.block_create = False
        self.block_rebuild_create = False
        self.block_delete = False


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
        with self.state.lock:
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
        try:
            self.wfile.write(body)
        except ConnectionError:
            pass

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
            with self.state.lock:
                self.state.create_count += 1
                create_count = self.state.create_count
            if self.state.block_create or (self.state.block_rebuild_create and create_count > 1):
                self.state.create_started.set()
                self.state.release_create.wait(2)
            if self.state.enforce_http3_create and payload.get("http_version") == "http3":
                transport = payload.get("transport", {})
                unsupported = (
                    "response_header_timeout_ms",
                    "expect_continue_timeout_ms",
                    "max_idle_conns",
                    "max_idle_conns_per_host",
                    "max_conns_per_host",
                    "read_buffer_size",
                    "write_buffer_size",
                    "proxy_connect_headers",
                )
                if "tls_fingerprint" in payload or any(transport.get(name) for name in unsupported):
                    self._json(
                        400,
                        {
                            "error": {
                                "code": "INVALID_REQUEST",
                                "message": "invalid HTTP/3 configuration",
                                "retryable": False,
                            }
                        },
                    )
                    return
            if self.state.create_response is not None:
                status, raw, content_type = self.state.create_response
                self._send(status, raw, content_type)
                return
            self._json(
                201,
                {
                    "protocol_version": 1,
                    "client_id": f"client-{create_count}",
                    "expires_at": "2026-07-14T00:00:00Z",
                },
            )
            return
        prefix = "/api/v1/clients/"
        suffix = "/requests"
        if not self.path.startswith(prefix) or not self.path.endswith(suffix):
            self._json(404, {"error": {"code": "CLIENT_NOT_FOUND", "message": "missing", "retryable": False, "request_id": "req-error"}})
            return
        client_id = self.path[len(prefix):-len(suffix)]
        self.state.request_started.set()
        if self.state.block_requests:
            self.state.release_request.wait(2)
        if self.state.drop_request_connection:
            self.close_connection = True
            return
        if client_id == self.state.stale_client_id:
            with self.state.lock:
                self.state.stale_seen += 1
                if self.state.stale_seen >= self.state.stale_expected:
                    self.state.stale_ready.set()
            self.state.stale_ready.wait(2)
            self._json(404, {"error": {"code": "CLIENT_NOT_FOUND", "message": "missing", "retryable": False, "request_id": "req-stale"}})
            return
        with self.state.lock:
            not_found = self.state.not_found_remaining > 0
            if not_found:
                self.state.not_found_remaining -= 1
        if not_found:
            self._json(404, {"error": {"code": "CLIENT_NOT_FOUND", "message": "missing", "retryable": False, "request_id": "req-missing"}})
            return
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
        if self.state.block_delete:
            self.state.release_request.wait(2)
        if self.state.delete_response is not None:
            status, raw, content_type = self.state.delete_response
            self._send(status, raw, content_type)
            return
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
        self.state.release_create.set()
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
        self.assertEqual(
            {
                name: create["transport"][name]
                for name in (
                    "tls_handshake_timeout_ms",
                    "expect_continue_timeout_ms",
                    "idle_conn_timeout_ms",
                    "max_idle_conns",
                )
            },
            {
                "tls_handshake_timeout_ms": 10000,
                "expect_continue_timeout_ms": 1000,
                "idle_conn_timeout_ms": 90000,
                "max_idle_conns": 100,
            },
        )

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

    def test_http3_default_omits_fingerprint_and_unsupported_transport_defaults(self):
        self.state.enforce_http3_create = True
        options = ClientOptions(http_version="http3")
        with Client(
            go_endpoint=self.endpoint,
            client_options=options,
        ):
            pass
        create = self.state.calls[1]["payload"]
        self.assertNotIn("tls_fingerprint", create)
        self.assertFalse(create["transport"]["expect_continue_timeout_ms"])
        self.assertFalse(create["transport"]["max_idle_conns"])
        self.assertEqual(create["transport"]["tls_handshake_timeout_ms"], 10000)
        self.assertEqual(create["transport"]["idle_conn_timeout_ms"], 90000)
        self.assertEqual(options.transport, TransportOptions())

        self.state.calls.clear()
        with self.assertRaises(GoProtocolError) as caught:
            Client(
                go_endpoint=self.endpoint,
                client_options=ClientOptions(
                    http_version="http3",
                    tls_fingerprint=TLSFingerprint.ANDROID_11_OKHTTP,
                ),
            )
        self.assertEqual(caught.exception.code, "INVALID_REQUEST")
        self.assertIn("tls_fingerprint", self.state.calls[1]["payload"])

        for name, value, transport in (
            ("expect_continue_timeout_ms", 2000, TransportOptions(expect_continue_timeout_ms=2000)),
            ("max_idle_conns", 101, TransportOptions(max_idle_conns=101)),
        ):
            with self.subTest(transport=transport):
                self.state.calls.clear()
                with self.assertRaises(GoProtocolError) as caught:
                    Client(
                        go_endpoint=self.endpoint,
                        client_options=ClientOptions(http_version="http3", transport=transport),
                    )
                self.assertEqual(caught.exception.code, "INVALID_REQUEST")
                sent = self.state.calls[1]["payload"]["transport"]
                self.assertEqual(sent[name], value)
                self.assertEqual(sent["tls_handshake_timeout_ms"], 10000)
                self.assertEqual(sent["idle_conn_timeout_ms"], 90000)

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
            (200, {"protocol_version": 1, "request_id": "x", "status_code": 200, "reason_phrase": "OK", "headers": [], "body_base64": "", "url": "https://target.test/a", "http_version": "HTTP/1.1", "elapsed_ms": 1, "trace": None, "extra": True}, "application/json"),
            (200, {}, "text/plain"),
        ]
        service_error = None
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
                if status == 400:
                    service_error = caught.exception
        self.assertEqual(service_error.code, "INVALID_REQUEST")
        self.assertEqual(service_error.request_id, "req-e")
        self.assertEqual(service_error.request.url, httpx.URL("https://target.test/a"))

    def test_response_headers_and_reason_reject_protocol_injection(self):
        envelope = {
            "protocol_version": 1,
            "request_id": "req-injection",
            "status_code": 200,
            "reason_phrase": "OK",
            "headers": [["X-Test", "safe"]],
            "body_base64": "",
            "url": "https://target.test/a",
            "http_version": "HTTP/1.1",
            "elapsed_ms": 1,
            "trace": None,
            "dump": None,
        }
        mutations = [
            ("headers", [["Bad Name", "value"]]),
            ("headers", [["X-Test", "value\r\nInjected: yes"]]),
            ("headers", [["X-Test", "value\x00tail"]]),
            ("headers", [["X-Test", "value\x1ftail"]]),
            ("reason_phrase", "OK\r\nInjected"),
            ("reason_phrase", "OK\x7ftail"),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                invalid = dict(envelope)
                invalid[field] = value
                self.state.request_response = (
                    200,
                    json.dumps(invalid).encode(),
                    "application/json",
                )
                with Client(go_endpoint=self.endpoint) as client:
                    with self.assertRaises(GoProtocolError) as caught:
                        client.get("https://target.test/a")
                self.assertEqual(caught.exception.request.url, httpx.URL("https://target.test/a"))

        valid = dict(envelope)
        valid["headers"] = [["X-Test", "\t\xff"]]
        valid["reason_phrase"] = "\t\xff"
        self.state.request_response = (
            200,
            json.dumps(valid).encode(),
            "application/json",
        )
        with Client(go_endpoint=self.endpoint) as client:
            response = client.get("https://target.test/a")
        self.assertEqual(response.headers.raw[0], (b"X-Test", b"\t\xff"))
        self.assertEqual(response.extensions["reason_phrase"], b"\t\xff")

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

    def test_capabilities_require_exact_valid_compatible_fields(self):
        valid = {
            "protocol_version": 1,
            "server_version": "1.0.0",
            "max_body_bytes": 48 << 20,
            "tls_fingerprints": FINGERPRINTS,
        }
        invalid_capabilities = [
            {**valid, "extra": True},
            {**valid, "server_version": ""},
            {**valid, "server_version": 1},
            {**valid, "max_body_bytes": True},
            {**valid, "max_body_bytes": 0},
            {**valid, "tls_fingerprints": FINGERPRINTS + [FINGERPRINTS[0]]},
            {**valid, "tls_fingerprints": FINGERPRINTS[:-1]},
        ]
        for capabilities in invalid_capabilities:
            with self.subTest(capabilities=capabilities):
                self.state.calls.clear()
                self.state.capabilities_response = (
                    200,
                    json.dumps(capabilities).encode(),
                    "application/json",
                )
                with self.assertRaises(GoProtocolError):
                    Client(go_endpoint=self.endpoint)
                self.assertEqual(
                    [(call["method"], call["path"]) for call in self.state.calls],
                    [("GET", "/api/v1/capabilities")],
                )

    def test_invalid_create_success_with_client_id_is_deleted_without_masking_error(self):
        invalid_envelopes = [
            {
                "protocol_version": 2,
                "client_id": "client-1",
                "expires_at": "2026-07-14T00:00:00Z",
            },
            {
                "protocol_version": 1,
                "client_id": "client-1",
                "expires_at": 123,
            },
            {
                "protocol_version": 1,
                "client_id": "client-1",
                "expires_at": "",
            },
            {
                "protocol_version": 1,
                "client_id": "client-1",
                "expires_at": "not-a-time",
            },
            {
                "protocol_version": 1,
                "client_id": "client-1",
                "expires_at": "2026-07-14 00:00:00+00:00",
            },
            {
                "protocol_version": 1,
                "client_id": "client-1",
                "expires_at": "2026-07-14T00:00:00+0000",
            },
            {
                "protocol_version": 1,
                "client_id": "client-1",
                "expires_at": "2026-07-14T00:00:00.1234567890Z",
            },
            {
                "protocol_version": 1,
                "client_id": "client-1",
                "expires_at": "2026-07-14T00:00:00Z",
                "extra": True,
            },
        ]
        for envelope in invalid_envelopes:
            with self.subTest(envelope=envelope):
                self.state.calls.clear()
                self.state.create_response = (
                    201,
                    json.dumps(envelope).encode(),
                    "application/json",
                )
                self.state.delete_response = (500, b"cleanup failed", "text/plain")
                with self.assertRaises(GoProtocolError) as caught:
                    Client(go_endpoint=self.endpoint)
                self.assertIn("创建会话", str(caught.exception))
                self.assertEqual(
                    [(call["method"], call["path"]) for call in self.state.calls],
                    [
                        ("GET", "/api/v1/capabilities"),
                        ("POST", "/api/v1/clients"),
                        ("DELETE", "/api/v1/clients/client-1"),
                    ],
                )

    def test_create_accepts_rfc3339_nano_and_offset_expires_at(self):
        for expires_at in (
            "2026-07-14T00:00:00.123456789Z",
            "2026-07-14T08:00:00+08:00",
        ):
            with self.subTest(expires_at=expires_at):
                self.state.calls.clear()
                self.state.create_response = (
                    201,
                    json.dumps(
                        {
                            "protocol_version": 1,
                            "client_id": "client-1",
                            "expires_at": expires_at,
                        }
                    ).encode(),
                    "application/json",
                )
                with Client(go_endpoint=self.endpoint):
                    pass

    def test_parent_initialization_failure_deletes_created_session(self):
        self.state.delete_response = (500, b"cleanup failed", "text/plain")
        with self.assertRaises(TypeError) as caught:
            Client(go_endpoint=self.endpoint, auth=object())
        self.assertIn('Invalid "auth" argument', str(caught.exception))
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
        for kwargs in (
            {"transport": transport},
            {"transport": None},
            {"mounts": {}},
            {"mounts": None},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                Client(go_endpoint=self.endpoint, **kwargs)
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

    def test_upstream_error_codes_map_to_httpx_exceptions_with_metadata(self):
        cases = [
            ("UPSTREAM_TIMEOUT", httpx.TimeoutException),
            ("UPSTREAM_DNS_ERROR", httpx.ConnectError),
            ("UPSTREAM_CONNECT_ERROR", httpx.ConnectError),
            ("UPSTREAM_TLS_ERROR", httpx.ConnectError),
            ("UPSTREAM_PROTOCOL_ERROR", httpx.RemoteProtocolError),
            ("INTERNAL_ERROR", GoProtocolError),
            ("UNKNOWN_ERROR", GoProtocolError),
        ]
        for code, exception_type in cases:
            with self.subTest(code=code):
                self.state.request_response = (
                    502,
                    json.dumps(
                        {
                            "error": {
                                "code": code,
                                "message": "upstream failed",
                                "retryable": False,
                                "request_id": "req-upstream",
                            }
                        }
                    ).encode(),
                    "application/json",
                )
                with Client(go_endpoint=self.endpoint) as client:
                    with self.assertRaises(exception_type) as caught:
                        client.get("https://target.test/error")
                self.assertEqual(caught.exception.request.url, httpx.URL("https://target.test/error"))
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.request_id, "req-upstream")
                self.state.calls.clear()

    def test_sync_client_not_found_rebuilds_once_and_reuses_exact_post_envelope(self):
        self.state.not_found_remaining = 1
        with Client(go_endpoint=self.endpoint) as client:
            response = client.post("https://target.test/post", content=b"payload")

        requests = [call for call in self.state.calls if call["path"].endswith("/requests")]
        self.assertEqual(response.status_code, 200)
        self.assertEqual([call["path"] for call in requests], [
            "/api/v1/clients/client-1/requests",
            "/api/v1/clients/client-2/requests",
        ])
        self.assertEqual(requests[0]["payload"], requests[1]["payload"])
        self.assertEqual(sum(call["path"] == "/api/v1/clients" for call in self.state.calls), 2)
        self.assertEqual(sum(call["path"] == "/api/v1/capabilities" for call in self.state.calls), 1)

    def test_sync_concurrent_client_not_found_rebuild_is_single_flight(self):
        client = Client(go_endpoint=self.endpoint)
        self.state.stale_client_id = "client-1"
        self.state.stale_expected = 4
        responses = []
        errors = []

        def send(index):
            try:
                responses.append(client.post(f"https://target.test/{index}", content=str(index).encode()))
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=send, args=(index,), daemon=True) for index in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)
        client.close()

        self.assertEqual(errors, [])
        self.assertEqual(len(responses), 4)
        self.assertEqual(self.state.create_count, 2)
        request_paths = [call["path"] for call in self.state.calls if call["path"].endswith("/requests")]
        self.assertEqual(request_paths.count("/api/v1/clients/client-1/requests"), 4)
        self.assertEqual(request_paths.count("/api/v1/clients/client-2/requests"), 4)

    def test_sync_second_client_not_found_and_rebuild_failure_do_not_loop(self):
        self.state.not_found_remaining = 2
        with Client(go_endpoint=self.endpoint) as client:
            with self.assertRaises(GoProtocolError) as caught:
                client.post("https://target.test/post", content=b"once")
        self.assertEqual(caught.exception.code, "CLIENT_NOT_FOUND")
        self.assertEqual(sum(call["path"].endswith("/requests") for call in self.state.calls), 2)
        self.assertEqual(self.state.create_count, 2)

        self.state = FakeGo()
        self.server.state = self.state
        client = Client(go_endpoint=self.endpoint)
        self.state.not_found_remaining = 1
        self.state.create_response = (
            500,
            b'{"error":{"code":"INTERNAL_ERROR","message":"create failed","retryable":false}}',
            "application/json",
        )
        with self.assertRaises(GoProtocolError) as caught:
            client.get("https://target.test/a")
        client.close()
        self.assertEqual(caught.exception.code, "INTERNAL_ERROR")
        self.assertEqual(caught.exception.request.url, httpx.URL("https://target.test/a"))
        self.assertEqual(sum(call["path"].endswith("/requests") for call in self.state.calls), 1)
        self.assertEqual(self.state.create_count, 2)

    def test_sync_control_disconnect_does_not_retry_post(self):
        client = Client(go_endpoint=self.endpoint)
        self.state.drop_request_connection = True
        with self.assertRaises(GoServiceUnavailable):
            client.post("https://target.test/post", content=b"unsafe")
        self.state.drop_request_connection = False
        client.close()
        self.assertEqual(sum(call["path"].endswith("/requests") for call in self.state.calls), 1)
        self.assertEqual(self.state.create_count, 1)

    def test_sync_concurrent_rebuild_failure_is_single_flight_and_keeps_each_request(self):
        client = Client(go_endpoint=self.endpoint)
        self.state.stale_client_id = "client-1"
        self.state.stale_expected = 2
        self.state.create_response = (
            500,
            b'{"error":{"code":"INTERNAL_ERROR","message":"create failed","retryable":false}}',
            "application/json",
        )
        errors = []

        def send(index):
            try:
                client.get(f"https://target.test/{index}")
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=send, args=(index,), daemon=True) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)
        client.close()

        self.assertEqual(self.state.create_count, 2)
        self.assertEqual(len(errors), 2)
        self.assertEqual({error.request.url for error in errors}, {
            httpx.URL("https://target.test/0"),
            httpx.URL("https://target.test/1"),
        })

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

    def test_concurrent_public_close_calls_both_wait_for_transport_cleanup(self):
        self.state.block_requests = True
        client = Client(go_endpoint=self.endpoint)
        request_thread = threading.Thread(
            target=lambda: client.get("https://target.test/a"),
            daemon=True,
        )
        request_thread.start()
        self.assertTrue(self.state.request_started.wait(1))
        finished = [threading.Event(), threading.Event()]

        def close(index):
            client.close()
            finished[index].set()

        first = threading.Thread(target=close, args=(0,), daemon=True)
        second = threading.Thread(target=close, args=(1,), daemon=True)
        first.start()
        time.sleep(0.05)
        second.start()
        time.sleep(0.05)

        self.assertFalse(finished[0].is_set())
        self.assertFalse(finished[1].is_set())
        self.state.release_request.set()
        request_thread.join(1)
        first.join(1)
        second.join(1)
        self.assertTrue(all(event.is_set() for event in finished))

    def test_request_control_timeout_is_target_timeout_plus_bounded_grace(self):
        self.state.block_requests = True
        client = Client(go_endpoint=self.endpoint)
        started = time.monotonic()
        try:
            with self.assertRaises(GoServiceUnavailable) as caught:
                client.get("https://target.test/slow", timeout=0.01)
            self.assertLess(time.monotonic() - started, 1.8)
            self.assertEqual(caught.exception.request.url, httpx.URL("https://target.test/slow"))
        finally:
            self.state.release_request.set()
            client.close()

    def test_close_delete_timeout_is_bounded(self):
        client = Client(go_endpoint=self.endpoint)
        self.state.block_delete = True
        started = time.monotonic()
        with self.assertRaises(GoServiceUnavailable):
            client.close()
        self.assertLess(time.monotonic() - started, 1.8)


class AsyncClientTests(unittest.IsolatedAsyncioTestCase):
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
        self.state.release_create.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    async def test_lazy_async_post_returns_real_response_and_close_is_idempotent(self):
        client = AsyncClient(go_endpoint=self.endpoint)
        self.assertEqual(self.state.calls, [])

        response = await client.post("https://target.test/json", json={"name": "test"})
        await client.aclose()
        await client.aclose()

        self.assertIsInstance(response, httpx.Response)
        self.assertEqual(response.json(), {"res": "ok"})
        self.assertEqual(response.request.url, httpx.URL("https://target.test/json"))
        self.assertEqual(
            [(call["method"], call["path"]) for call in self.state.calls],
            [
                ("GET", "/api/v1/capabilities"),
                ("POST", "/api/v1/clients"),
                ("POST", "/api/v1/clients/client-1/requests"),
                ("DELETE", "/api/v1/clients/client-1"),
            ],
        )

    async def test_async_context_manager_without_request_creates_no_session(self):
        async with AsyncClient(go_endpoint=self.endpoint):
            self.assertEqual(self.state.calls, [])
        self.assertEqual(self.state.calls, [])

    async def test_async_httpx_body_cookie_header_and_redirect_semantics(self):
        async with AsyncClient(
            go_endpoint=self.endpoint,
            headers={"X-Default": "one"},
            cookies={"initial": "yes"},
            follow_redirects=True,
        ) as client:
            json_response = await client.post("https://target.test/json", json={"a": 1})
            await client.post("https://target.test/data", data={"a": "b"})
            await client.post("https://target.test/raw", content=b"\x00raw")
            await client.get("https://target.test/set-cookie")
            await client.get("https://target.test/next")
            redirected = await client.get("https://target.test/redirect")

        requests = [call["payload"] for call in self.state.calls if call["path"].endswith("/requests")]
        self.assertEqual(json_response.json(), {"res": "ok"})
        self.assertEqual(base64.b64decode(requests[0]["body_base64"]), b'{"a":1}')
        self.assertEqual(base64.b64decode(requests[1]["body_base64"]), b"a=b")
        self.assertEqual(base64.b64decode(requests[2]["body_base64"]), b"\x00raw")
        next_cookie = next(pair[1] for pair in requests[4]["headers"] if pair[0].lower() == "cookie")
        self.assertIn("initial=yes", next_cookie)
        self.assertIn("session=one", next_cookie)
        self.assertIn(["x-default", "one"], [[name.lower(), value] for name, value in requests[0]["headers"]])
        self.assertEqual(redirected.history[0].status_code, 302)
        self.assertEqual(redirected.http_version, "HTTP/3")

    async def test_async_concurrent_first_requests_create_one_session(self):
        client = AsyncClient(go_endpoint=self.endpoint)
        responses = await asyncio.gather(
            *(client.get(f"https://target.test/{index}") for index in range(6))
        )
        await client.aclose()

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertEqual(self.state.create_count, 1)
        self.assertEqual(sum(call["path"] == "/api/v1/capabilities" for call in self.state.calls), 1)

    async def test_async_concurrent_first_failure_shares_attempt_then_later_request_retries(self):
        self.state.block_create = True
        self.state.create_response = (
            500,
            b'{"error":{"code":"INTERNAL_ERROR","message":"create failed","retryable":false}}',
            "application/json",
        )
        client = AsyncClient(go_endpoint=self.endpoint)
        tasks = [
            asyncio.create_task(client.get(f"https://target.test/{index}"))
            for index in range(4)
        ]
        self.assertTrue(await asyncio.to_thread(self.state.create_started.wait, 1))
        await asyncio.sleep(0.05)
        self.state.release_create.set()
        errors = await asyncio.gather(*tasks, return_exceptions=True)

        self.assertTrue(all(isinstance(error, GoProtocolError) for error in errors))
        self.assertEqual(
            {error.request.url for error in errors},
            {httpx.URL(f"https://target.test/{index}") for index in range(4)},
        )
        self.assertEqual(sum(call["path"] == "/api/v1/capabilities" for call in self.state.calls), 1)
        self.assertEqual(sum(call["path"] == "/api/v1/clients" for call in self.state.calls), 1)

        self.state.block_create = False
        self.state.create_response = None
        response = await client.get("https://target.test/retry")
        await client.aclose()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.state.create_count, 2)

    async def test_async_concurrent_client_not_found_rebuild_is_single_flight(self):
        client = AsyncClient(go_endpoint=self.endpoint)
        await client.get("https://target.test/warm")
        self.state.stale_client_id = "client-1"
        self.state.stale_expected = 5

        responses = await asyncio.gather(
            *(client.post(f"https://target.test/{index}", content=str(index).encode()) for index in range(5))
        )
        await client.aclose()

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertEqual(self.state.create_count, 2)
        request_paths = [call["path"] for call in self.state.calls if call["path"].endswith("/requests")]
        self.assertEqual(request_paths.count("/api/v1/clients/client-1/requests"), 6)
        self.assertEqual(request_paths.count("/api/v1/clients/client-2/requests"), 5)
        for index in range(5):
            payloads = [
                call["payload"]
                for call in self.state.calls
                if call["path"].endswith("/requests")
                and call["payload"]["url"] == f"https://target.test/{index}"
            ]
            self.assertEqual(payloads[0], payloads[1])

    async def test_async_close_waits_for_request_and_is_idempotent(self):
        self.state.block_requests = True
        client = AsyncClient(go_endpoint=self.endpoint)
        request_task = asyncio.create_task(client.get("https://target.test/slow"))
        self.assertTrue(await asyncio.to_thread(self.state.request_started.wait, 1))
        close_task = asyncio.create_task(client.aclose())
        await asyncio.sleep(0.05)
        self.assertFalse(close_task.done())

        self.state.release_request.set()
        response = await request_task
        await close_task
        await client.aclose()

        self.assertEqual(response.status_code, 200)
        paths = [call["path"] for call in self.state.calls]
        self.assertLess(paths.index("/api/v1/clients/client-1/requests"), paths.index("/api/v1/clients/client-1"))

    async def test_concurrent_public_aclose_calls_both_wait_for_transport_cleanup(self):
        self.state.block_requests = True
        client = AsyncClient(go_endpoint=self.endpoint)
        request_task = asyncio.create_task(client.get("https://target.test/slow"))
        self.assertTrue(await asyncio.to_thread(self.state.request_started.wait, 1))
        first = asyncio.create_task(client.aclose())
        second = asyncio.create_task(client.aclose())
        await asyncio.sleep(0.05)

        self.assertFalse(first.done())
        self.assertFalse(second.done())
        self.state.release_request.set()
        await request_task
        await asyncio.gather(first, second)
        self.assertEqual([call["path"] for call in self.state.calls].count("/api/v1/clients/client-1"), 1)

    async def test_cancelling_one_aclose_waiter_does_not_cancel_shared_cleanup(self):
        self.state.block_requests = True
        client = AsyncClient(go_endpoint=self.endpoint)
        request_task = asyncio.create_task(client.get("https://target.test/slow"))
        self.assertTrue(await asyncio.to_thread(self.state.request_started.wait, 1))
        cancelled = asyncio.create_task(client.aclose())
        survivor = asyncio.create_task(client.aclose())
        await asyncio.sleep(0.05)
        cancelled.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await cancelled
        self.assertFalse(survivor.done())

        self.state.release_request.set()
        await request_task
        await survivor
        self.assertEqual([call["path"] for call in self.state.calls].count("/api/v1/clients/client-1"), 1)

    async def test_concurrent_aclose_waiters_share_cleanup_error(self):
        client = AsyncClient(go_endpoint=self.endpoint)
        await client.get("https://target.test/warm")
        self.state.delete_response = (
            500,
            b'{"error":{"code":"INTERNAL_ERROR","message":"delete failed","retryable":false}}',
            "application/json",
        )

        errors = await asyncio.gather(client.aclose(), client.aclose(), return_exceptions=True)

        self.assertTrue(all(isinstance(error, GoProtocolError) for error in errors))
        self.assertTrue(all(error.code == "INTERNAL_ERROR" for error in errors))
        with self.assertRaises(GoProtocolError) as repeated:
            await client.aclose()
        self.assertEqual(repeated.exception.code, "INTERNAL_ERROR")
        self.assertEqual([call["path"] for call in self.state.calls].count("/api/v1/clients/client-1"), 1)

    async def test_async_error_mapping_and_strict_bad_envelopes_match_sync(self):
        client = AsyncClient(go_endpoint=self.endpoint)
        self.state.request_response = (
            504,
            b'{"error":{"code":"UPSTREAM_TIMEOUT","message":"late","retryable":true,"request_id":"req-timeout"}}',
            "application/json",
        )
        with self.assertRaises(httpx.TimeoutException) as caught:
            await client.get("https://target.test/timeout")
        self.assertEqual(caught.exception.code, "UPSTREAM_TIMEOUT")
        self.assertEqual(caught.exception.request_id, "req-timeout")
        self.assertEqual(caught.exception.request.url, httpx.URL("https://target.test/timeout"))

        malformed = [
            (200, b"{}", "text/plain"),
            (200, b"{", "application/json"),
            (200, b'{"protocol_version":2}', "application/json"),
            (
                200,
                json.dumps(
                    {
                        "protocol_version": 1,
                        "request_id": "req-bad",
                        "status_code": 200,
                        "reason_phrase": "OK",
                        "headers": [["Bad Name", "value"]],
                        "body_base64": "***",
                        "url": "https://target.test/a",
                        "http_version": "HTTP/1.1",
                        "elapsed_ms": 1,
                        "trace": None,
                    }
                ).encode(),
                "application/json",
            ),
        ]
        for response in malformed:
            with self.subTest(response=response):
                self.state.request_response = response
                with self.assertRaises(GoProtocolError):
                    await client.get("https://target.test/bad")
        await client.aclose()

    async def test_async_second_client_not_found_and_rebuild_failure_do_not_loop(self):
        self.state.not_found_remaining = 2
        async with AsyncClient(go_endpoint=self.endpoint) as client:
            with self.assertRaises(GoProtocolError) as caught:
                await client.post("https://target.test/post", content=b"once")
        self.assertEqual(caught.exception.code, "CLIENT_NOT_FOUND")
        self.assertEqual(self.state.create_count, 2)
        self.assertEqual(sum(call["path"].endswith("/requests") for call in self.state.calls), 2)

        self.state = FakeGo()
        self.server.state = self.state
        client = AsyncClient(go_endpoint=self.endpoint)
        await client.get("https://target.test/warm")
        self.state.not_found_remaining = 1
        self.state.create_response = (
            500,
            b'{"error":{"code":"INTERNAL_ERROR","message":"create failed","retryable":false}}',
            "application/json",
        )
        with self.assertRaises(GoProtocolError) as caught:
            await client.get("https://target.test/a")
        await client.aclose()
        self.assertEqual(caught.exception.code, "INTERNAL_ERROR")
        self.assertEqual(caught.exception.request.url, httpx.URL("https://target.test/a"))
        self.assertEqual(self.state.create_count, 2)
        self.assertEqual(sum(call["path"].endswith("/requests") for call in self.state.calls), 2)

    async def test_async_control_disconnect_does_not_retry_post(self):
        client = AsyncClient(go_endpoint=self.endpoint)
        await client.get("https://target.test/warm")
        self.state.drop_request_connection = True
        with self.assertRaises(GoServiceUnavailable) as caught:
            await client.post("https://target.test/post", content=b"unsafe")
        self.state.drop_request_connection = False
        await client.aclose()

        self.assertEqual(caught.exception.request.url, httpx.URL("https://target.test/post"))
        requests = [call for call in self.state.calls if call["path"].endswith("/requests")]
        self.assertEqual(sum(call["payload"]["url"] == "https://target.test/post" for call in requests), 1)
        self.assertEqual(self.state.create_count, 1)

    async def test_async_close_during_started_rebuild_waits_then_deletes_new_session(self):
        client = AsyncClient(go_endpoint=self.endpoint)
        await client.get("https://target.test/warm")
        self.state.not_found_remaining = 1
        self.state.block_rebuild_create = True
        request_task = asyncio.create_task(client.get("https://target.test/rebuild"))
        self.assertTrue(await asyncio.to_thread(self.state.create_started.wait, 1))
        close_task = asyncio.create_task(client.aclose())
        await asyncio.sleep(0.05)
        self.assertFalse(close_task.done())

        self.state.release_create.set()
        response = await request_task
        await close_task

        self.assertEqual(response.status_code, 200)
        self.assertIn("/api/v1/clients/client-2/requests", [call["path"] for call in self.state.calls])
        self.assertEqual([call["path"] for call in self.state.calls].count("/api/v1/clients/client-2"), 1)


if __name__ == "__main__":
    unittest.main()
