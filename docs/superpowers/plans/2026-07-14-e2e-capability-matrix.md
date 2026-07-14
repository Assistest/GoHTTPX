# E2E Capability Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic Windows loopback E2E coverage for every Python-facing GoHTTPX capability that can be observed by a local target service.

**Architecture:** Keep the existing Fake control-plane tests intact. Extract common EXE/process/port lifecycle code into test-only Python support, use a Python HTTP target for HTTPX semantics, and use a test-only Go target binary for TLS and protocol observability that Python's standard library cannot provide. Every test calls the real Python SDK and a real GoHTTPX EXE.

**Tech Stack:** Python 3.10 `unittest`/`httpx`, Go 1.25, req/v3, quic-go, Windows loopback sockets.

## Global Constraints

- Do not modify GoHTTPX production endpoints, protocol envelopes, or Python SDK public APIs.
- Preserve the user's uncommitted `api.go` whitespace change.
- All fixtures listen only on loopback, use temporary ports, and never access the public Internet.
- No new production dependencies; test helpers use Python stdlib and existing Go module dependencies.
- Keep Go protocol/race tests and Python Fake control-plane tests; E2E adds a fourth coverage axis.
- Every added fixture has bounded startup, request and teardown behavior.

---

### Task 1: Extract reusable real-service test lifecycle

**Files:**
- Create: `python/e2e_support.py`
- Modify: `python/test_gohttpx.py:1533-1719`
- Test: `python/test_gohttpx.py:1642-1719`

**Interfaces:**
- Produces: `GoHTTPXService`, a test-only context object exposing `endpoint`, `token`, `exe_path`, `start()` and `close()`.
- Produces: `reserve_loopback_port()` and `wait_for_health(endpoint, process)` for every E2E fixture.
- Consumes: the existing Go module root and `go build` command.

- [ ] **Step 1: Add a failing lifecycle test**

```python
def test_real_service_starts_and_removes_its_temp_exe(self):
    service = GoHTTPXService(module_dir=Path(__file__).resolve().parents[1])
    service.start()
    self.assertEqual(httpx.get(service.endpoint + "/api/v1/health", trust_env=False).status_code, 200)
    exe_path = service.exe_path
    service.close()
    self.assertFalse(exe_path.exists())
```

- [ ] **Step 2: Run it to verify RED**

Run: `python -B -m unittest python.test_gohttpx.GoHTTPXE2ETests.test_real_service_starts_and_removes_its_temp_exe -v`

Expected: FAIL because `GoHTTPXService` is not defined.

- [ ] **Step 3: Implement the minimal test-only lifecycle object**

```python
class GoHTTPXService:
    def __init__(self, module_dir: Path, token: str = "e2e-fixed-token") -> None:
        self.module_dir = module_dir
        self.token = token
        self.exe_path = Path(tempfile.gettempdir()) / f"gohttpx-test-{os.getpid()}-{id(self)}.exe"
        self.endpoint = ""
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        """构建 EXE、启动服务并等待 /health。"""

    def close(self) -> None:
        """停止本实例进程并删除本实例临时 EXE。"""
```

`start()` builds one unique EXE, reserves a loopback port, starts the server with a token and waits for health. `close()` terminates only its own process and deletes only its own absolute EXE path.

- [ ] **Step 4: Move the existing `GoHTTPXE2ETests` setup/teardown onto the helper**

Replace duplicated EXE build, health polling and cleanup without changing current E2E assertions.

- [ ] **Step 5: Verify GREEN and existing E2E**

Run: `python -B -m unittest python.test_gohttpx.GoHTTPXE2ETests -v`

Expected: all existing real E2E tests pass.

- [ ] **Step 6: Commit**

```text
git add python/e2e_support.py python/test_gohttpx.py
git commit -m "test: 抽取真服务 E2E 生命周期"
```

### Task 2: Add complete HTTPX semantic E2E matrix

**Files:**
- Create: `python/test_gohttpx_e2e_httpx.py`
- Modify: `python/e2e_support.py`
- Test: `python/test_gohttpx_e2e_httpx.py`

**Interfaces:**
- Consumes: `GoHTTPXService` and a new `HTTPFixture` exposing `endpoint`, recorded calls and `close()`.
- Produces: real sync/async tests for methods, body modes, redirect/auth/cookies, errors, trace/dump, timeout, retry and RequestOptions.

- [ ] **Step 1: Write failing method/body test**

```python
def test_all_methods_and_body_modes_reach_the_real_target(self):
    with self.client() as client:
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "PURGE"):
            self.assertEqual(client.request(method, self.fixture.endpoint + "/echo/method").status_code, 200)
        self.assertEqual(client.post(self.fixture.endpoint + "/echo/body", json={"a": 1}).json()["body"], '{"a":1}')
        self.assertIn("file-bytes", client.post(self.fixture.endpoint + "/echo/body", files={"file": ("a.bin", b"file-bytes")}).text)
```

- [ ] **Step 2: Run it to verify RED**

Run: `python -B -m unittest python.test_gohttpx_e2e_httpx.HTTPXSemanticE2ETests.test_all_methods_and_body_modes_reach_the_real_target -v`

Expected: FAIL because the module and `HTTPFixture` do not exist.

- [ ] **Step 3: Implement the minimal HTTP fixture routes**

Implement only these loopback routes: `/echo/method`, `/echo/body`, `/echo/headers`, `/redirect/chain`, `/cookies/set`, `/cookies/show`, `/auth/basic`, `/auth/digest`, `/status/{code}`, `/slow`, `/binary`, `/trace-dump`, and `/retry`. Each route records method/query/header raw items/body before writing its documented response.

- [ ] **Step 4: Add focused real-client tests**

Add one test per behavior group:

```python
def test_query_headers_cookies_and_redirect_history_are_httpx_semantic(self):
    """断言目标记录与 HTTPX cookie/history 一致。"""

def test_basic_digest_binary_and_target_statuses_are_real_responses(self):
    """断言 challenge、二进制和非 2xx 的真实 Response 语义。"""

def test_request_options_trace_dump_chunked_and_close_are_observable(self):
    """断言 Go 专属 options 留在响应扩展或目标记录中。"""

def test_timeout_retry_and_large_body_boundaries_are_mapped(self):
    """断言 timeout/retry 与有限大小正文的真实行为。"""

async def test_async_client_uses_the_same_httpx_fixture(self):
    """断言 AsyncClient 复用相同真实路径。"""
```

Each test asserts both the fixture record and the returned `httpx.Response`/exception. `retry` uses a GET-only deterministic fail-once route; POST only checks that a control failure is not replayed.

- [ ] **Step 5: Verify GREEN**

Run: `python -B -m unittest python.test_gohttpx_e2e_httpx -v`

Expected: all semantic E2E tests pass with no network access.

- [ ] **Step 6: Commit**

```text
git add python/e2e_support.py python/test_gohttpx_e2e_httpx.py
git commit -m "test: 扩展 HTTPX 真链路能力矩阵"
```

### Task 3: Build a transport-observable Go test target

**Files:**
- Create: `testdata/e2e-target/go.mod`
- Create: `testdata/e2e-target/main.go`
- Modify: `python/e2e_support.py`
- Test: `python/test_gohttpx_e2e_transport.py`

**Interfaces:**
- Produces: a test-only target process with `--http1-port`, `--https-port`, `--h2c-port`, `--h3-port`, `--cert`, `--key`, `--ca` arguments.
- Produces: JSON `/observe` response with `protocol`, `tls_version`, `cipher_suites`, `curves`, `alpn`, `peer_cert_present`, method, headers and body length.
- Consumes: generated test CA/server/client certificates from test support.

- [ ] **Step 1: Write a failing HTTPS verification test**

```python
def test_verify_and_mtls_are_observed_by_the_real_target(self):
    with self.client(verify=self.ca_path, cert=(self.client_cert, self.client_key)) as client:
        observed = client.get(self.target.https_endpoint + "/observe").json()
    self.assertTrue(observed["peer_cert_present"])
    self.assertIn(observed["protocol"], {"HTTP/1.1", "HTTP/2.0"})
```

- [ ] **Step 2: Run it to verify RED**

Run: `python -B -m unittest python.test_gohttpx_e2e_transport.TransportE2ETests.test_verify_and_mtls_are_observed_by_the_real_target -v`

Expected: FAIL because the transport target and test module do not exist.

- [ ] **Step 3: Implement the test-only target and certificate helper**

The Go target starts HTTP/1.1 HTTPS, h2c and HTTP/3 servers from explicit loopback listeners. Its TLS callback records `tls.ClientHelloInfo` properties; HTTPS handler reads the peer certificate. Test support creates a CA, server certificate and client certificate using a temporary Go helper or existing repository certificate fixtures, then deletes only paths it created.

- [ ] **Step 4: Add one real E2E per transport capability**

```python
def test_http1_http2_h2c_and_http3_match_requested_versions(self):
    """断言目标观察到每个请求的实际协议。"""

def test_verify_false_ca_verify_and_mtls_have_distinct_results(self):
    """断言验证策略和客户端证书产生不同可观测结果。"""

def test_chrome_and_android_fingerprints_change_observable_client_hello(self):
    """断言两个指纹与默认 TLS 的稳定握手字段差异。"""
```

The HTTP/3 test asserts protocol negotiation; fingerprint tests compare a stable subset of `ClientHelloInfo` fields against the default client, not raw TLS bytes.

- [ ] **Step 5: Verify GREEN**

Run: `python -B -m unittest python.test_gohttpx_e2e_transport.TransportE2ETests -v`

Expected: all local transport tests pass.

- [ ] **Step 6: Commit**

```text
git add testdata/e2e-target python/e2e_support.py python/test_gohttpx_e2e_transport.py
git commit -m "test: 添加 TLS 与协议真链路靶场"
```

### Task 4: Add local proxy and resource-boundary E2E tests

**Files:**
- Modify: `python/e2e_support.py`
- Modify: `python/test_gohttpx_e2e_transport.py`
- Test: `python/test_gohttpx_e2e_transport.py`

**Interfaces:**
- Produces: `ConnectProxyFixture` and `Socks5ProxyFixture`, each recording auth and forwarded authority.
- Consumes: real `Client(proxy=...)`, `ClientOptions(proxy_connect_headers=...)` and target fixture endpoints.

- [ ] **Step 1: Write failing HTTP CONNECT proxy test**

```python
def test_http_connect_proxy_auth_and_connect_headers_reach_the_proxy(self):
    with self.client(proxy=self.proxy.url, client_options=ClientOptions(proxy_connect_headers={"X-Connect": ["one"]})) as client:
        self.assertEqual(client.get(self.target.https_endpoint + "/observe").status_code, 200)
    self.assertEqual(self.proxy.calls[0]["headers"]["x-connect"], ["one"])
```

- [ ] **Step 2: Run it to verify RED**

Run: `python -B -m unittest python.test_gohttpx_e2e_transport.TransportE2ETests.test_http_connect_proxy_auth_and_connect_headers_reach_the_proxy -v`

Expected: FAIL because `ConnectProxyFixture` is not defined.

- [ ] **Step 3: Implement minimal loopback proxies**

CONNECT proxy accepts one authenticated CONNECT request, records authority/headers, dials only `127.0.0.1` and relays both directions. SOCKS5 supports no-auth and username/password negotiation, records destination, dials only loopback and relays. Any non-loopback authority fails closed.

- [ ] **Step 4: Add proxy and boundary tests**

```python
def test_socks5_proxy_reaches_only_the_loopback_target(self):
    """断言 SOCKS5 代理记录 loopback 目标并成功转发。"""

def test_invalid_proxy_auth_returns_an_httpx_transport_error(self):
    """断言错误代理凭证不会被当作目标响应。"""

def test_concurrent_clients_and_near_limit_body_do_not_cross_state(self):
    """断言并发会话和受限大正文不串状态。"""
```

Use a sub-limit body that keeps CI memory bounded; retain the existing Go oversize validation tests for the exact 48 MiB rejection boundary.

- [ ] **Step 5: Verify GREEN**

Run: `python -B -m unittest python.test_gohttpx_e2e_transport -v`

Expected: all proxy and boundary tests pass without outbound connections.

- [ ] **Step 6: Commit**

```text
git add python/e2e_support.py python/test_gohttpx_e2e_transport.py
git commit -m "test: 覆盖代理与资源边界真链路"
```

### Task 5: Update release contract and run the full gate

**Files:**
- Modify: `README.md:367-379`
- Modify: `PROJECT_CONTEXT.md:370-395`
- Test: repository root

- [ ] **Step 1: Document the four-layer test model**

State that the Python E2E suite starts real GoHTTPX and local targets for HTTPX semantics, TLS/protocols and proxies; state that all fixtures remain loopback-only.

- [ ] **Step 2: Run the complete release gate**

```text
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
python -B -m unittest discover -s python -p "test_*.py" -v
go build -trimpath -ldflags="-s -w" -o gohttpx-server.exe .
go version -m gohttpx-server.exe
gohttpx-server.exe --version
git diff --check
git status --short --branch
```

Expected: all commands exit 0; the EXE and Windows replacement artifact remain ignored; the user-owned `api.go` whitespace change remains untouched.

- [ ] **Step 3: Commit**

```text
git add README.md PROJECT_CONTEXT.md
git commit -m "docs: 说明真链路发布门禁"
```
