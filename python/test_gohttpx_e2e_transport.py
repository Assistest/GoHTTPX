import asyncio
import copy
import io
import json
import os
import ssl
import socket
import subprocess
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import httpx

from e2e_support import ConnectProxyFixture, GoHTTPXService, Socks5ProxyFixture, TransportTarget
from gohttpx import AsyncClient, Client, ClientOptions, GoProtocolError, Impersonate, TLSFingerprint, TransportOptions, tls_spec_from_client_hello
from tls_test_support import TLSCaptureTarget, load_readme_tls_demo
import gohttpx


class TransportE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = GoHTTPXService(Path(__file__).resolve().parents[1])
        cls.target = TransportTarget(Path(__file__).resolve().parents[1])
        try:
            cls.service.start()
            cls.target.start()
        except BaseException:
            cls.target.close()
            cls.service.close()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            cls.target.close()
        finally:
            cls.service.close()

    def custom_hello(self):
        return json.loads((Path(__file__).resolve().parents[1] / "testdata/tls/custom_tls13.json").read_text(encoding="utf-8"))

    def assert_custom_hello(self, observed, variant=False):
        hello = observed["hello"]
        normalize = lambda value: 0x0A0A if value & 0x0F0F == 0x0A0A and value >> 8 == value & 255 else value
        self.assertEqual(hello["version"], 0x0303)
        self.assertEqual(hello["compression"], [0])
        self.assertEqual([normalize(value) for value in hello["cipher_suites"]],
                         [0x0A0A, 0x1301, 0x1303, 0x1302] if variant else [0x0A0A, 0x1302, 0x1303, 0x1301])
        expected_order = [0x0A0A, 43, 0, 10, 27, 16, 51, 13, 0x0A0A] if variant else [0x0A0A, 0, 13, 43, 10, 51, 16, 27, 0x0A0A]
        self.assertEqual([normalize(ext["id"]) for ext in hello["extensions"]], expected_order)
        extensions = {ext["id"]: bytes.fromhex(ext["data"]) for ext in hello["extensions"]}
        self.assertEqual(extensions[0], b"\x00\x0c\x00\x00\x09localhost")
        self.assertEqual(extensions[13].hex(), "0006080404030805" if variant else "0006080504030804")
        self.assertEqual(extensions[43][0], 4)
        self.assertEqual(normalize(int.from_bytes(extensions[43][1:3], "big")), 0x0A0A)
        self.assertEqual(extensions[43][3:], b"\x03\x04")
        self.assertEqual(extensions[10][:2], b"\x00\x06")
        self.assertEqual(normalize(int.from_bytes(extensions[10][2:4], "big")), 0x0A0A)
        self.assertEqual(extensions[10][4:], b"\x00\x17\x00\x1d")
        self.assertEqual(extensions[16], b"\x00\x09\x08http/1.1")
        self.assertEqual(extensions[27], b"\x02\x00\x02")
        self.assertEqual(extensions[51][:2], b"\x00\x29")
        self.assertEqual(normalize(int.from_bytes(extensions[51][2:4], "big")), 0x0A0A)
        self.assertEqual(extensions[51][4:11], b"\x00\x01\x00\x00\x1d\x00\x20")
        self.assertEqual(len(extensions[51][11:]), 32)
        self.assertEqual(observed["tls_version"], "TLSv1.3")
        self.assertEqual(observed["alpn"], "http/1.1")
        return extensions[51][11:]

    def test_client_hello_hex_round_trip_preserves_declared_fields(self):
        spec = self.custom_hello()
        with TLSCaptureTarget(self.target) as target:
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token,
                        verify=self.target.ca_path, tls_spec=spec) as client:
                first = client.get(target.endpoint).json()
        converted = tls_spec_from_client_hello(bytes.fromhex(first["raw_hello"]))
        with TLSCaptureTarget(self.target) as target:
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token,
                        verify=self.target.ca_path, tls_spec=converted) as client:
                second = client.get(target.endpoint).json()
        normalize = lambda value: 0x0A0A if value & 0x0F0F == 0x0A0A and value >> 8 == value & 255 else value
        self.assertEqual([normalize(item) for item in first["hello"]["cipher_suites"]],
                         [normalize(item) for item in second["hello"]["cipher_suites"]])
        self.assertEqual([normalize(ext["id"]) for ext in first["hello"]["extensions"]],
                         [normalize(ext["id"]) for ext in second["hello"]["extensions"]])
        self.assertNotEqual(first["hello"]["random"], second["hello"]["random"])

    def test_custom_tls_json_is_visible_in_actual_client_hello_and_regenerates_keys(self):
        with TLSCaptureTarget(self.target) as target:
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token,
                        verify=self.target.ca_path, tls_spec=json.dumps(self.custom_hello())) as client:
                observations = [client.get(target.endpoint + "/observe").json() for _ in range(3)]
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token,
                        verify=self.target.ca_path, tls_fingerprint="golang") as client:
                default = client.get(target.endpoint + "/observe").json()
        keys = [self.assert_custom_hello(observed) for observed in observations]
        self.assertEqual(len(set(keys)), 3)
        self.assertEqual(len({observed["hello"]["random"] for observed in observations}), 3)
        self.assertEqual(len({observed["hello"]["session_id"] for observed in observations}), 3)
        self.assertNotEqual(observations[0]["hello"]["cipher_suites"], default["hello"]["cipher_suites"])

    def test_custom_tls_numeric_grease_aliases_produce_the_same_wire_structure(self):
        spec = self.custom_hello()
        spec["cipher_suites"][0] = "0x1a1a"
        spec["extensions"][4]["named_group_list"][0] = "0x2a2a"
        spec["extensions"][5]["client_shares"][0]["group"] = "0xfafa"
        with TLSCaptureTarget(self.target) as target:
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token,
                        verify=self.target.ca_path, tls_spec=spec) as client:
                observed = client.get(target.endpoint + "/observe").json()
        self.assert_custom_hello(observed)

    def test_custom_tls_clients_do_not_share_fingerprints_or_cookies_under_concurrency(self):
        first = self.custom_hello()
        second = copy.deepcopy(first)
        second["cipher_suites"][1:] = reversed(second["cipher_suites"][1:])
        second["extensions"][2]["supported_signature_algorithms"].reverse()
        second["extensions"] = [second["extensions"][i] for i in [0, 3, 1, 4, 7, 6, 5, 2, 8]]
        with TLSCaptureTarget(self.target) as target:
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token, verify=self.target.ca_path, tls_spec=first) as a, \
                 Client(go_endpoint=self.service.endpoint, go_token=self.service.token, verify=self.target.ca_path, tls_spec=second) as b:
                a.get(target.endpoint + "/set?owner=A")
                b.get(target.endpoint + "/set?owner=B")
                with ThreadPoolExecutor(max_workers=6) as executor:
                    observations = list(executor.map(lambda i: (a if i % 2 == 0 else b).get(target.endpoint + "/observe").json(), range(20)))
        keys = []
        for i, observed in enumerate(observations):
            keys.append(self.assert_custom_hello(observed, variant=bool(i % 2)))
            self.assertEqual(observed["cookie"], "owner=B" if i % 2 else "owner=A")
        self.assertEqual(len(set(keys)), 20)

    def test_custom_tls_shuffle_changes_only_the_permitted_extension_order(self):
        spec = self.custom_hello()
        spec["shuffle_extensions"] = True
        with TLSCaptureTarget(self.target) as target:
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token, tls_spec=spec, verify=self.target.ca_path) as client:
                observations = [client.get(target.endpoint + "/observe").json() for _ in range(6)]
        orders = []
        for observed in observations:
            extensions = observed["hello"]["extensions"]
            orders.append(tuple(ext["id"] for ext in extensions[1:-1]))
            self.assertCountEqual(orders[-1], [0, 13, 43, 10, 51, 16, 27])
            self.assertEqual(extensions[0]["id"] & 0x0F0F, 0x0A0A)
            self.assertEqual(extensions[-1]["id"] & 0x0F0F, 0x0A0A)
            self.assertEqual(next(ext["data"] for ext in extensions if ext["id"] == 13), "0006080504030804")
        self.assertGreater(len(set(orders)), 1)

    def test_async_custom_tls_snapshot_survives_session_recreation(self):
        async def exercise(target):
            spec = self.custom_hello()
            async with AsyncClient(go_endpoint=self.service.endpoint, go_token=self.service.token,
                                   verify=self.target.ca_path, tls_spec=spec) as client:
                spec["cipher_suites"].reverse()
                first = (await client.get(target.endpoint + "/set?owner=async")).json()
                transport = client._transport
                async with httpx.AsyncClient(trust_env=False) as control:
                    response = await control.delete(self.service.endpoint + "/api/v1/clients/" + transport._client_id,
                                                    headers={"Authorization": "Bearer " + self.service.token})
                    self.assertEqual(response.status_code, 204)
                second = (await client.get(target.endpoint + "/observe")).json()
                return first, second

        with TLSCaptureTarget(self.target) as target:
            first, second = asyncio.run(exercise(target))
        self.assert_custom_hello(first)
        self.assert_custom_hello(second)
        self.assertEqual(second["cookie"], "owner=async")

    def test_custom_tls_preserves_verification_mtls_and_connect_proxy(self):
        with TLSCaptureTarget(self.target, require_client_cert=True) as target, ConnectProxyFixture("user", "pass") as proxy:
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token, tls_spec=self.custom_hello(),
                        verify=self.target.ca_path, cert=(self.target.client_cert_path, self.target.client_key_path),
                        proxy=f"http://user:pass@{proxy.hostport}") as client:
                observed = client.get(target.endpoint + "/observe").json()
            self.assert_custom_hello(observed)
            self.assertTrue(observed["peer_cert_present"])
            self.assertEqual(len(proxy.calls), 1)
        with TLSCaptureTarget(self.target) as target:
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token, tls_spec=self.custom_hello()) as client:
                with self.assertRaises(httpx.ConnectError) as caught:
                    client.get(target.endpoint + "/observe")
                self.assertEqual(caught.exception.code, "UPSTREAM_TLS_ERROR")

    def test_custom_tls_negotiates_real_http2_without_forced_protocol(self):
        spec = self.custom_hello()
        spec["extensions"][6]["protocol_name_list"] = ["h2", "http/1.1"]
        with Client(go_endpoint=self.service.endpoint, go_token=self.service.token, tls_spec=spec,
                    verify=self.target.ca_path) as client:
            response = client.get(self.target.https_endpoint + "/observe")
        self.assertEqual(response.http_version, "HTTP/2")
        self.assertEqual(response.json()["cipher_suites"][1:], [0x1302, 0x1303, 0x1301])
        self.assertEqual(response.json()["alpn"], ["h2", "http/1.1"])

    def test_edge_json_matches_the_declared_wire_fields_for_tls12_and_tls13(self):
        _, spec = load_readme_tls_demo()
        normalize = lambda value: 0x0A0A if value & 0x0F0F == 0x0A0A and value >> 8 == value & 255 else value
        for maximum, version in ((ssl.TLSVersion.TLSv1_2, "TLSv1.2"), (ssl.TLSVersion.TLSv1_3, "TLSv1.3")):
            with self.subTest(version=version), TLSCaptureTarget(self.target) as target:
                target.server.context.maximum_version = maximum
                with Client(go_endpoint=self.service.endpoint, go_token=self.service.token, verify=self.target.ca_path, tls_spec=spec) as client:
                    observed = client.get(target.endpoint + "/observe").json()
            hello = observed["hello"]
            self.assertEqual(observed["tls_version"], version)
            self.assertEqual([normalize(value) for value in hello["cipher_suites"]],
                             [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035])
            self.assertEqual([normalize(ext["id"]) for ext in hello["extensions"]],
                             [0x0A0A, 16, 51, 35, 10, 5, 23, 65037, 11, 43, 65281, 0, 27, 18, 13, 45, 17613, 0x0A0A])
            extensions = {ext["id"]: bytes.fromhex(ext["data"]) for ext in hello["extensions"]}
            self.assertEqual(extensions[13].hex(), "001609040905090604030804040105030805050108060601")
            self.assertEqual(extensions[16], b"\x00\x0c\x02h2\x08http/1.1")
            self.assertEqual(extensions[17613], b"\x00\x03\x02h2")
            self.assertEqual(extensions[10][4:].hex(), "11ec001d00170018")
            self.assertEqual(extensions[43][3:], b"\x03\x04\x03\x03")
            self.assertEqual(extensions[45], b"\x01\x01")
            self.assertEqual(extensions[27], b"\x02\x00\x02")
            self.assertEqual(extensions[11], b"\x01\x00")
            self.assertEqual(extensions[65281], b"\x00")
            self.assertEqual(extensions[5], b"\x01\x00\x00\x00\x00")
            for empty in (35, 23, 18):
                self.assertEqual(extensions[empty], b"")
            self.assertGreater(len(extensions[65037]), 100)
            self.assertEqual(extensions[51][7:11], b"\x11\xec\x04\xc0")
            self.assertEqual(extensions[51][1227:1231], b"\x00\x1d\x00\x20")
            self.assertEqual(len(extensions[51]), 1263)

    def test_readme_tls_demo_is_complete_and_runs_without_external_json(self):
        source, spec = load_readme_tls_demo()
        self.assertEqual(set(spec), {"cipher_suites", "compression_methods", "extensions", "min_vers", "max_vers", "shuffle_extensions"})
        self.assertEqual((spec["min_vers"], spec["max_vers"], spec["shuffle_extensions"]), (771, 772, False))
        self.assertNotIn("read_text", source)
        self.assertEqual(source.count("https://tls.peet.ws/api/all"), 1)
        output, namespace = io.StringIO(), {}
        with TLSCaptureTarget(self.target) as target:
            with patch("gohttpx.Client", side_effect=lambda **kwargs: Client(
                go_endpoint=self.service.endpoint, go_token=self.service.token, verify=self.target.ca_path, **kwargs
            )), redirect_stdout(output):
                exec(compile(source.replace("https://tls.peet.ws/api/all", target.endpoint), "README.md TLS demo", "exec"), namespace)
        observed = json.loads(output.getvalue())
        self.assertEqual(observed["user_agent"], namespace["HEADERS"]["User-Agent"])
        self.assertIn("Edg/", observed["user_agent"])
        self.assertEqual(observed["tls_version"], "TLSv1.3")
        self.assertEqual(observed["hello"]["cipher_suites"][1:],
                         [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035])
        self.assertEqual([ext["id"] for ext in observed["hello"]["extensions"]][1:-1],
                         [16, 51, 35, 10, 5, 23, 65037, 11, 43, 65281, 0, 27, 18, 13, 45, 17613])
        self.assertEqual(next(ext["data"] for ext in observed["hello"]["extensions"] if ext["id"] == 13),
                         "001609040905090604030804040105030805050108060601")

    def test_readme_legacy_alps_alternative_reaches_the_wire_and_rejects_both_codepoints(self):
        _, spec = load_readme_tls_demo()
        alps = next(ext for ext in spec["extensions"] if ext["name"] == "application_settings_new")
        alps["name"] = "application_settings"
        with TLSCaptureTarget(self.target) as target:
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token,
                        verify=self.target.ca_path, tls_spec=spec) as client:
                observed = client.get(target.endpoint).json()
        extensions = {ext["id"]: ext["data"] for ext in observed["hello"]["extensions"]}
        self.assertEqual(extensions[17513], "0003026832")
        self.assertNotIn(17613, extensions)
        spec["extensions"].append({"name": "application_settings_new", "supported_protocols": ["h2"]})
        with self.assertRaises(GoProtocolError) as caught:
            Client(go_endpoint=self.service.endpoint, go_token=self.service.token, tls_spec=spec)
        self.assertEqual(caught.exception.code, "INVALID_REQUEST")

    @unittest.skipUnless(os.name == "nt", "Windows 托管故障注入")
    def test_managed_go_crash_restores_custom_tls_and_cookies_on_the_wire(self):
        gohttpx.configure_runtime(binary_path=self.service.exe_path)
        try:
            with TLSCaptureTarget(self.target) as target:
                original = self.custom_hello()
                with Client(tls_spec=original, verify=self.target.ca_path) as client:
                    first = client.get(target.endpoint + "/set?owner=managed").json()
                    original["extensions"].reverse()
                    old_pid = gohttpx.runtime_status()["child_pid"]
                    process = gohttpx._runtime._current.process
                    process.kill()
                    process.wait(5)
                    second = client.get(target.endpoint + "/observe").json()
                    self.assertNotEqual(gohttpx.runtime_status()["child_pid"], old_pid)
                    self.assertEqual(gohttpx.runtime_status()["start_count"], 2)
                    self.assertEqual(second["cookie"], "owner=managed")
                    self.assert_custom_hello(first)
                    self.assert_custom_hello(second)
        finally:
            gohttpx.shutdown()

    def test_verify_and_mtls_are_observed_by_the_real_target(self):
        with Client(
            go_endpoint=self.service.endpoint,
            go_token=self.service.token,
            verify=self.target.ca_path,
            cert=(self.target.client_cert_path, self.target.client_key_path),
            client_options=ClientOptions(http_version="http2"),
        ) as client:
            response = client.get(self.target.mtls_endpoint + "/observe")

        observed = response.json()
        self.assertTrue(observed["peer_cert_present"])
        self.assertEqual(observed["protocol"], "HTTP/2.0")

    def test_connect_proxy_forwards_auth_and_explicit_headers(self):
        with ConnectProxyFixture("user", "pass") as proxy:
            with Client(
                go_endpoint=self.service.endpoint,
                go_token=self.service.token,
                verify=self.target.ca_path,
                proxy=f"http://user:pass@{proxy.hostport}",
                client_options=ClientOptions(transport=TransportOptions(proxy_connect_headers={"X-Connect": ["one"]})),
            ) as client:
                response = client.get(self.target.https_endpoint + "/observe")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(proxy.calls), 1)
        self.assertEqual(proxy.calls[0]["headers"]["Proxy-Authorization"], ["Basic dXNlcjpwYXNz"])
        self.assertEqual(proxy.calls[0]["headers"]["X-Connect"], ["one"])

    def test_invalid_connect_proxy_auth_maps_to_connect_error(self):
        with ConnectProxyFixture("user", "pass") as proxy:
            with Client(
                go_endpoint=self.service.endpoint,
                go_token=self.service.token,
                verify=self.target.ca_path,
                proxy=f"http://user:wrong@{proxy.hostport}",
            ) as client:
                with self.assertRaises(httpx.ConnectError) as caught:
                    client.get(self.target.https_endpoint + "/observe")

        self.assertEqual(caught.exception.code, "UPSTREAM_CONNECT_ERROR")
        self.assertEqual(len(proxy.calls), 1)

    def test_socks5_proxy_forwards_concurrent_bounded_large_bodies(self):
        body = b"x" * (1024 * 1024)
        with Socks5ProxyFixture() as proxy:
            clients = [
                Client(
                    go_endpoint=self.service.endpoint,
                    go_token=self.service.token,
                    proxy=f"socks5://{proxy.hostport}",
                )
                for _ in range(4)
            ]
            try:
                with ThreadPoolExecutor(max_workers=len(clients)) as executor:
                    responses = list(executor.map(lambda client: client.post(self.target.http_endpoint + "/observe", content=body), clients))
            finally:
                for client in clients:
                    client.close()

        self.assertEqual([response.status_code for response in responses], [200] * len(clients))
        self.assertEqual([response.json()["body_length"] for response in responses], [len(body)] * len(clients))
        self.assertEqual(len(proxy.calls), len(clients))

    def test_proxy_fixtures_reject_nonloopback_destinations_without_dialing(self):
        with ConnectProxyFixture() as proxy:
            with socket.create_connection(("127.0.0.1", proxy.server.server_address[1]), timeout=1) as connection:
                connection.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                self.assertIn(b" 403 ", connection.recv(1024))
            self.assertEqual(proxy.calls[0]["host"], "example.com")
            self.assertEqual(proxy.dialed_hosts, [])

        with Socks5ProxyFixture() as proxy:
            with socket.create_connection(("127.0.0.1", proxy.server.server_address[1]), timeout=1) as connection:
                connection.sendall(b"\x05\x01\x00")
                self.assertEqual(connection.recv(2), b"\x05\x00")
                connection.sendall(b"\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb")
                self.assertEqual(connection.recv(10)[1], 2)
            self.assertEqual(proxy.calls[0]["host"], "8.8.8.8")
            self.assertEqual(proxy.dialed_hosts, [])

        with ConnectProxyFixture() as proxy:
            with socket.create_connection(("127.0.0.1", proxy.server.server_address[1]), timeout=1) as connection:
                connection.sendall(f"CONNECT localhost:{self.target.http_endpoint.rsplit(':', 1)[1]} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
                self.assertIn(b" 200 ", connection.recv(1024))
            self.assertEqual(proxy.dialed_hosts, ["127.0.0.1"])

    def test_http1_http2_h2c_and_http3_reach_their_real_protocol_targets(self):
        cases = (
            ("http1", self.target.http_endpoint, "HTTP/1.1", "HTTP/1.1"),
            ("http2", self.target.https_endpoint, "HTTP/2", "HTTP/2.0"),
            ("h2c", self.target.h2c_endpoint, "HTTP/2", "HTTP/2.0"),
            ("http3", self.target.http3_endpoint, "HTTP/3", "HTTP/3.0"),
        )
        for version, endpoint, expected_response_protocol, expected_target_protocol in cases:
            with Client(
                go_endpoint=self.service.endpoint,
                go_token=self.service.token,
                verify=self.target.ca_path,
                client_options=ClientOptions(http_version=version),
            ) as client:
                response = client.post(endpoint + "/observe", headers={"X-Transport": version}, content=b"protocol-body")
            observed = response.json()
            self.assertEqual(response.http_version, expected_response_protocol)
            self.assertEqual(observed["protocol"], expected_target_protocol)
            self.assertEqual(observed["method"], "POST")
            self.assertEqual(observed["headers"]["X-Transport"], [version])
            self.assertEqual(observed["body_length"], len(b"protocol-body"))

    def test_default_verification_fails_but_disable_or_ca_verify_reaches_target(self):
        with Client(go_endpoint=self.service.endpoint, go_token=self.service.token) as client:
            with self.assertRaises(httpx.ConnectError) as caught:
                client.get(self.target.https_endpoint + "/observe")
        self.assertEqual(caught.exception.code, "UPSTREAM_TLS_ERROR")
        for verify in (False, self.target.ca_path):
            with Client(go_endpoint=self.service.endpoint, go_token=self.service.token, verify=verify) as client:
                response = client.get(self.target.https_endpoint + "/observe")
            self.assertIn(response.json()["protocol"], ("HTTP/1.1", "HTTP/2.0"))

    def test_http2_rejects_explicit_fingerprints_and_browser_impersonation(self):
        for options in (
            {"tls_fingerprint": TLSFingerprint.ANDROID_11_OKHTTP},
            {"impersonate": Impersonate.CHROME},
        ):
            with self.assertRaises(GoProtocolError) as caught:
                Client(
                    go_endpoint=self.service.endpoint,
                    go_token=self.service.token,
                    client_options=ClientOptions(http_version="http2"),
                    **options,
                )
            self.assertEqual(caught.exception.code, "INVALID_REQUEST")

    def test_chrome_and_android_client_hello_fields_differ_from_default_without_packet_matching(self):
        observations = {}
        for name, fingerprint in (("default", None), ("chrome", TLSFingerprint.CHROME_AUTO), ("android", TLSFingerprint.ANDROID_11_OKHTTP)):
            with Client(
                go_endpoint=self.service.endpoint,
                go_token=self.service.token,
                verify=self.target.ca_path,
                tls_fingerprint=fingerprint,
                client_options=ClientOptions(http_version="auto"),
            ) as client:
                observations[name] = client.get(self.target.https_endpoint + "/observe").json()
        fields = ("cipher_suites", "curves", "alpn", "tls_versions")
        self.assertEqual(
            {field: observations["default"][field] for field in fields},
            {field: observations["android"][field] for field in fields},
        )
        self.assertNotEqual(
            {field: observations["default"][field] for field in fields},
            {field: observations["chrome"][field] for field in fields},
        )

    def test_req_v3_confirms_the_android_http2_alpn_conflict(self):
        environment = os.environ | {
            "GOHTTPX_PROBE_ENDPOINT": self.target.https_endpoint,
            "GOHTTPX_PROBE_CA": str(self.target.ca_path),
        }
        result = subprocess.run(
            ["go", "test", "-run", "TestReqTLSHTTP2Probe", "-v"],
            cwd=self.target.target_dir,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
