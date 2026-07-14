# Task 3 传输靶场报告

## RED / GREEN 证据

首次 RED：

```text
python -B -m unittest discover -s python -p "test_gohttpx_e2e_transport.py" -v
ImportError: cannot import name 'TransportTarget' from 'e2e_support'
```

HTTP/2 修复前 RED：同一 CA 与 endpoint 的 req/v3 对照中，默认 TLS 与无指纹强制 HTTP/2 都得到 `HTTP/2.0`，而 Android 指纹加 `EnableForceHTTP2` 的完整错误链为：

```text
Get "https://127.0.0.1:<port>/observe": http2: unexpected ALPN protocol ""; want "h2"
-> http2: unexpected ALPN protocol ""; want "h2"
```

最终 GREEN：

```text
python -B -m unittest discover -s python -p "test_gohttpx_e2e_transport.py" -v
Ran 6 tests in 23.626s
OK

go test .
ok   gohttpx  (cached)
```

## 文件与实现

- `testdata/e2e-target/`：仅测试构建的独立 Go module，全部监听 `127.0.0.1`，提供 HTTP/1、TLS HTTP/2、h2c、HTTP/3、mTLS。`/observe` 返回方法、headers、body 长度、协议、TLS 协商信息、客户端证书状态及由 `GetConfigForClient` 捕获的 ClientHello 字段。
- `python/e2e_support.py`：`TransportTarget` 在自有绝对临时目录生成 CA、服务端与客户端证书，构建/关闭靶场和其可执行文件；启动与关闭分别有 10/5 秒上限。
- `python/test_gohttpx_e2e_transport.py`：真实 GoHTTPX 与靶场的协议、verify、mTLS、指纹和 req/v3 对照测试。
- `python/gohttpx.py`：`http2` 不再隐式序列化 Android TLS 指纹；HTTP/1 保留默认 Android 行为。
- `api.go`：HTTP/2 默认保留 req/v3 TLS，以协商 `h2`；显式 TLS fingerprint（包括 JSON 显式空值）或 browser impersonation 在创建会话时返回 `INVALID_REQUEST`，不静默降级。
- `api_test.go`：覆盖 HTTP/2 的显式不兼容配置拒绝，以及未提供指纹时的解码状态。

## 覆盖与诊断结论

- HTTP/1、TLS HTTP/2、h2c、HTTP/3 均断言 Python `Response` 协议表示及靶场实际协议。
- 默认验证失败断言 SDK 当前合同：`httpx.ConnectError`，code 为 `UPSTREAM_TLS_ERROR`；`verify=False`、自定义 CA 和 mTLS 均到达目标。
- Chrome、Android 与默认指纹比较 cipher suites、curves、ALPN、TLS versions 的 ClientHelloInfo 值，不比较原始报文。默认与 Android 一致，Chrome 不同。
- 额外 req/v3 直接对照在同一靶场、同一 CA 上验证根因：默认 TLS 和无指纹强制 HTTP/2 成功；Android 指纹加强制 HTTP/2 必须报告 ALPN 不匹配。

## 自审

- 未新增生产依赖；测试 module 仅使用根 module 已固定的 req/quic-go/uTLS/x/net 版本。
- 未修改生产 endpoint 或 Python SDK 公共 API；未改用户 `api.go` 无关空白。
- 靶场不依赖公网上的服务；本地协议不可用会使测试失败，不跳过。
- `git diff --check` 无空白错误；Go 与 Python E2E 均已重跑。

## 顾虑

- 证书密钥每次测试临时生成；序列号、主题、用途及 loopback SAN 固定，测试不依赖系统 CA 或 openssl。
