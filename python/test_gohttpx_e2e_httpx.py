import asyncio
import base64
import unittest
from pathlib import Path

import httpx

from e2e_support import GoHTTPXService, HTTPFixture
from gohttpx import AsyncClient, Client, ClientOptions, RequestOptions, RetryOptions


class HTTPXSemanticE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = GoHTTPXService(Path(__file__).resolve().parents[1])
        cls.fixture = HTTPFixture()
        try:
            cls.service.start()
        except BaseException:
            cls.fixture.close()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            cls.service.close()
        finally:
            cls.fixture.close()

    def setUp(self):
        with self.fixture.lock:
            self.fixture.calls.clear()
            self.fixture.retry_remaining = 1

    def test_all_methods_and_body_modes_reach_the_real_target(self):
        with Client(go_endpoint=self.service.endpoint, go_token=self.service.token) as client:
            for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "PURGE"):
                response = client.request(method, self.fixture.endpoint + "/echo/method")
                self.assertEqual(response.status_code, 200)
            json_response = client.post(self.fixture.endpoint + "/echo/body", json={"a": 1})
            multipart_response = client.post(
                self.fixture.endpoint + "/echo/body",
                files={"file": ("a.bin", b"file-bytes", "application/octet-stream")},
            )

        self.assertEqual(json_response.status_code, 200)
        self.assertEqual(base64.b64decode(json_response.json()["body_base64"]), b'{"a":1}')
        self.assertEqual(multipart_response.status_code, 200)
        self.assertIn(b"file-bytes", base64.b64decode(multipart_response.json()["body_base64"]))
        with self.fixture.lock:
            calls = list(self.fixture.calls)
        self.assertEqual([call["method"] for call in calls[:8]], ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "PURGE"])
        self.assertEqual(calls[8]["body"], b'{"a":1}')
        self.assertIn(b"file-bytes", calls[9]["body"])

    def test_query_headers_cookies_and_redirect_history_reach_the_target(self):
        with Client(
            go_endpoint=self.service.endpoint,
            go_token=self.service.token,
            follow_redirects=True,
            headers=[("X-Dupe", "one"), ("X-Dupe", "two")],
            cookies={"initial": "yes"},
        ) as client:
            echoed = client.get(self.fixture.endpoint + "/echo/headers", params=[("a", "1"), ("a", "2")])
            self.assertEqual(client.get(self.fixture.endpoint + "/cookies/set").status_code, 204)
            cookies = client.get(self.fixture.endpoint + "/cookies/show")
            redirected = client.get(self.fixture.endpoint + "/redirect/chain")

        self.assertEqual(echoed.status_code, 200)
        self.assertEqual(echoed.json()["query"], {"a": ["1", "2"]})
        self.assertEqual([value for name, value in echoed.json()["headers"] if name.lower() == "x-dupe"], ["one", "two"])
        self.assertIn("initial=yes", cookies.json()["cookie"])
        self.assertIn("server=one", cookies.json()["cookie"])
        self.assertEqual(redirected.json(), {"redirected": True})
        self.assertEqual([response.status_code for response in redirected.history], [302])
        with self.fixture.lock:
            self.assertEqual(self.fixture.calls[-1]["path"], "/redirect/chain/final")

    def test_auth_binary_and_non_success_responses_are_real_httpx_results(self):
        with Client(go_endpoint=self.service.endpoint, go_token=self.service.token, auth=("user", "pass")) as client:
            basic = client.get(self.fixture.endpoint + "/auth/basic")
        with Client(go_endpoint=self.service.endpoint, go_token=self.service.token, auth=httpx.DigestAuth("user", "pass")) as client:
            digest = client.get(self.fixture.endpoint + "/auth/digest")
            binary = client.get(self.fixture.endpoint + "/binary")
            missing = client.get(self.fixture.endpoint + "/status/404")
            failed = client.get(self.fixture.endpoint + "/status/500")

        self.assertTrue(basic.json()["authenticated"])
        self.assertTrue(digest.json()["authenticated"])
        self.assertEqual(binary.content, b"\x00\xffresponse")
        self.assertEqual((missing.status_code, failed.status_code), (404, 500))
        with self.fixture.lock:
            calls = list(self.fixture.calls)
        self.assertEqual(calls[0]["headers"][-1][0].lower(), "authorization")
        self.assertEqual([call["path"] for call in calls].count("/auth/digest"), 2)
        self.assertEqual([call["path"] for call in calls if call["path"] == "/binary"], ["/binary"])
        self.assertEqual([call["body"] for call in calls if call["path"] == "/binary"], [b""])
        self.assertEqual([call["path"] for call in calls if call["path"] == "/status/404"], ["/status/404"])
        self.assertEqual([call["path"] for call in calls if call["path"] == "/status/500"], ["/status/500"])

    def test_request_options_trace_dump_chunked_and_close_reach_target(self):
        options = RequestOptions(force_chunked=True, close_connection=True, trace=True, dump=True)
        with Client(go_endpoint=self.service.endpoint, go_token=self.service.token) as client:
            response = client.post(self.fixture.endpoint + "/trace-dump", content=b"chunked", extensions={"go_req": options})

        self.assertEqual(response.status_code, 200)
        self.assertIn("go_trace", response.extensions)
        self.assertIn("go_dump", response.extensions)
        with self.fixture.lock:
            call = self.fixture.calls[0]
        headers = {name.lower(): value for name, value in call["headers"]}
        self.assertEqual(call["body"], b"chunked")
        self.assertEqual(headers.get("transfer-encoding"), "chunked")
        self.assertEqual(headers.get("connection"), "close")

    def test_timeout_retry_and_post_replay_control(self):
        with Client(go_endpoint=self.service.endpoint, go_token=self.service.token) as client:
            with self.assertRaises(httpx.TimeoutException) as caught:
                client.get(self.fixture.endpoint + "/slow?seconds=0.2", timeout=0.02)
        self.assertEqual(caught.exception.code, "UPSTREAM_TIMEOUT")
        with self.fixture.lock:
            self.assertEqual([call["path"] for call in self.fixture.calls], ["/slow"])
        with Client(
            go_endpoint=self.service.endpoint,
            go_token=self.service.token,
            client_options=ClientOptions(retry=RetryOptions(count=1, mode="fixed", fixed_interval_ms=1, status_codes=(503,))),
        ) as client:
            retried = client.get(self.fixture.endpoint + "/retry")
        self.assertEqual(retried.status_code, 200)
        with self.fixture.lock:
            self.fixture.retry_remaining = 1
        with Client(
            go_endpoint=self.service.endpoint,
            go_token=self.service.token,
            client_options=ClientOptions(retry=RetryOptions(count=1, mode="fixed", fixed_interval_ms=1, status_codes=(503,))),
        ) as client:
            post = client.post(self.fixture.endpoint + "/retry", extensions={"go_req": RequestOptions(retry_count=0)})
        self.assertEqual(post.status_code, 503)
        with self.fixture.lock:
            calls = list(self.fixture.calls)
        self.assertEqual([call["method"] for call in calls if call["path"] == "/retry"], ["GET", "GET", "POST"])

    def test_async_client_uses_the_loopback_fixture(self):
        async def request():
            async with AsyncClient(go_endpoint=self.service.endpoint, go_token=self.service.token) as client:
                return await client.post(self.fixture.endpoint + "/echo/body", json={"async": True})

        response = asyncio.run(request())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(base64.b64decode(response.json()["body_base64"]), b'{"async":true}')
        with self.fixture.lock:
            self.assertEqual(self.fixture.calls[0]["body"], b'{"async":true}')


if __name__ == "__main__":
    unittest.main()
