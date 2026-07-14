# GoHTTPX 真链路能力矩阵设计

## 目标

让 Python SDK 对外暴露的、可由本机确定性靶场验证的功能，都至少经过一次真实链路：`Client`/`AsyncClient` → GoHTTPX EXE → 本机目标服务。测试同时断言目标服务实际收到的请求与 Python 获得的 HTTPX `Response` 或异常。

## 非目标

- 不修改 `/api/v1` 协议，不为测试增加生产 endpoint。
- 不用真链路测试替代现有 Go 协议/竞态测试或 Python Fake 控制面测试。
- 不访问公网，不使用 httpbin，不为所有配置做笛卡尔积。
- 不测试 Python API 明确拒绝的 callback、middleware、custom transport、streaming 与自定义 TLS handshake。

## 原则

1. 每个公开配置只有在目标端可观测时才新增 E2E；纯 JSON 严格性继续由 Fake 控制面覆盖。
2. 每个 E2E 同时断言目标端输入和 Python 端输出，避免只证明其中一层。
3. 同一能力只覆盖一个最小代表组合；仅对语义冲突组合增加专门用例。
4. 全部 fixture 在测试内启动和销毁，绑定 loopback 与临时端口，并带固定启动、请求、关闭超时。

## 测试结构

保留 `python/test_gohttpx.py` 的 Fake 控制面、生命周期测试与现有 HTTP/1 真 E2E。新增两个按责任拆分的测试模块：

- `python/test_gohttpx_e2e_httpx.py`：普通 HTTP 靶场与 HTTPX 用户语义。
- `python/test_gohttpx_e2e_transport.py`：HTTPS、mTLS、HTTP/2、H2C、HTTP/3、代理与 TLS 指纹观测。

可复用的启动/清理、临时 EXE、token、端口分配和请求记录放入一个仅测试使用的 `python/e2e_support.py`。它不参与 SDK 导出，也不被生产代码导入。

需要 HTTP/2、H2C、HTTP/3、mTLS 或 ClientHello 可观测能力时，Python 测试构建一个仓库内的 Go 测试靶场；该靶场只在测试时运行，不是 GoHTTPX server 的新命令或 endpoint。普通 HTTP、CONNECT 与 SOCKS5 靶场使用 Python 标准库 socket/http.server，以避免新增依赖。

## 能力矩阵

| 能力 | 真链路断言 | 代表组合 |
|---|---|---|
| 所有 HTTP method | 靶场记录 method 与 body；Python 返回正常 Response | GET、POST、PUT、PATCH、DELETE、HEAD、OPTIONS、PURGE |
| params/headers/cookies | 靶场保留 query 多值和重复 header；Python cookie jar 更新 | 重复 query、重复 header、Set-Cookie |
| json/data/files/content | 靶场回显字节与 Content-Type | JSON、form、multipart 上传、二进制 content |
| redirect/auth | 靶场 challenge/redirect；Python history 与认证结果 | Basic、Digest、302 chain |
| timeout/retry/close | 靶场控制等待/失败次数；Python 映射异常与调用次数 | 超时、GET retry、POST 不因控制断开重试、close connection |
| RequestOptions | 靶场或响应扩展提供可观测结果 | trace、dump、force_chunked、header order、close connection |
| HTTPS verify | 自签 CA 靶场记录成功/失败 | CA 文件、`verify=False`、默认校验失败 |
| mTLS | 靶场要求客户端证书并读取 peer certificate | cert/key 与自签 CA |
| HTTP versions | 靶场记录协商协议 | HTTP/1.1、HTTP/2 TLS、H2C、HTTP/3 |
| TLS fingerprint | 靶场 `ClientHelloInfo` 记录 TLS 版本、cipher suites、curves 与 ALPN；不同 fingerprint 与默认配置存在预期差异 | Chrome/Android 指纹各一条 |
| proxy | 本地代理记录目标连接与认证 | HTTP CONNECT、SOCKS5、代理认证、CONNECT headers |
| resource/concurrency | 靶场记录并发与长度 | 多 Client 并发、接近 body 上限、超过上限错误 |

“参数已序列化”不等同于“参数已生效”。例如 `http_version="http3"` 必须由 HTTP/3 靶场确认，`cert` 必须由 mTLS 靶场确认，代理 headers 必须由代理靶场确认。

## 断言规则

每个用例写明两个断言集合：

- **目标断言**：method、URL/query、原始 body、header 多值、TLS/协议、代理 CONNECT 内容、重试次数或客户端证书。
- **Python 断言**：status、headers、cookies、history、reason phrase、http_version、`go_trace`/`go_dump` extensions，或准确的 HTTPX/GoHTTPX 异常代码。

对于 HTTP/2 和 HTTP/3，不承诺 HTTP/1 的 header casing/order；只断言协议允许保留的值与重复值。TLS 指纹断言的是靶场可观测的握手差异和成功应用，不把第三方库内部字节布局当成不变 API。

## 执行与失败处理

- 每个 E2E 类独立构建临时 EXE，启动失败直接报错；临时文件只删除自身创建的单个绝对路径文件。
- 所有服务只监听 `127.0.0.1`/`::1`；每次测试使用临时端口。
- 所有服务在 `tearDownClass` 关闭；无法停止即失败，不吞异常。
- CI 在 Windows 执行完整 Go、race、vet 与 Python unittest；E2E 不因缺少公网或环境变量跳过。
- 超过 60 秒的控制超时只保留一个发布门禁型用例；常规测试使用毫秒级等待，避免把 CI 变成慢速重复套件。

## 验收标准

1. 每项矩阵能力至少有一条真实 Python→Go EXE→目标靶场用例。
2. 同步与异步至少各覆盖一次完整真链路；异步不重复所有同步矩阵。
3. 所有新增用例可在 Windows、无公网环境完成。
4. `go test ./... -count=1`、`go test -race ./... -count=1`、`go vet ./...` 与 Python unittest 全部通过。
5. README 的公开能力与矩阵没有无测试承诺；无法以本地靶场确定性验证的承诺必须明确说明边界。
