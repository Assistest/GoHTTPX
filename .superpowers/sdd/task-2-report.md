# Task 2 报告：HTTPX 真链路语义矩阵

## RED

命令：

```text
python -B -m unittest discover -s python -p "test_gohttpx_e2e_httpx.py" -v
```

结果：失败，`ImportError: cannot import name 'HTTPFixture' from 'e2e_support'`。首个
`HTTPXSemanticE2ETests.test_all_methods_and_body_modes_reach_the_real_target`
因此在缺失的测试夹具处停止，符合预期 RED。

## 实现

- `python/e2e_support.py` 新增仅 stdlib 的 `HTTPFixture`，监听 `127.0.0.1`，记录方法、查询、原始请求头和 body，并提供有界 `close()`。
- 夹具实现所需的 `/echo/*`、重定向、cookie、Basic/Digest、状态码、慢响应、二进制、trace/dump 和 retry 路由。
- `python/test_gohttpx_e2e_httpx.py` 新增六个真实 Go 服务到 loopback target 的同步/异步 E2E 测试，覆盖全部要求的 HTTP 方法、body、响应与异常语义。

未修改 `api.go`、其他 Go 生产代码或 `python/gohttpx.py`。

## GREEN / 验证

命令：

```text
python -B -m unittest discover -s python -p "test_gohttpx_e2e_httpx.py" -v
```

最新结果：6 项运行，5 项通过，1 项失败：

```text
FAIL: test_request_options_trace_dump_chunked_and_close_reach_target
python/test_gohttpx_e2e_httpx.py:108
self.assertEqual(headers.get("transfer-encoding"), "chunked")
AssertionError: None != 'chunked'
```

其余通过：方法/body、query/重复 header/cookie/重定向、认证/二进制/非成功状态、超时/GET retry/POST 禁止重放控制、AsyncClient。

## BLOCKED / 顾虑

测试故意保留失败断言，未调整预期，也未修改生产代码。

`force_chunked` 的只读路径为：Python `RequestOptions(force_chunked=True)` →
`python/gohttpx.py:_request_options`（220 行）→ `_request_payload`（390、514 行；async 为 857 行）→
Go `decodeRequestEnvelope`（`api.go:613`）→ `session.client.R()` / `SetBodyBytes`（645、674-675 行）→
`applyRequestOptions`（678、801-817 行）→ `targetReq.EnableForceChunkedEncoding()`（805-806 行）→ `Send`（681 行）。

故障点不在 envelope 丢失或 Go 映射未调用；实际 HTTP/1.1 loopback target 收到 Content-Length，未收到
`Transfer-Encoding: chunked`。依据当前 `github.com/imroc/req/v3 v3.59.0` 的实际行为，
`EnableForceChunkedEncoding()` 没有令该请求在线路上采用 chunked 编码。需要生产层修复或升级该依赖后，此测试才能转绿。

## 自审

- 所有 target 均为 `127.0.0.1`；未访问公共网络。
- 夹具仅关闭自己创建的 server/thread；服务仍复用既有 `GoHTTPXService`。
- 路由记录发生在响应前，断言同时检查 target 记录与 `httpx.Response`/异常。
- 未复制 Fake control-plane 生命周期测试。
