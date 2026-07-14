import os
import socket
import subprocess
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from e2e_support import ConnectProxyFixture, GoHTTPXService, Socks5ProxyFixture, TransportTarget
from gohttpx import Client, ClientOptions, GoProtocolError, Impersonate, TLSFingerprint, TransportOptions


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
