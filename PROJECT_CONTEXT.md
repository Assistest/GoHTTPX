# GoHTTPX 项目上下文与开发规范

> 文档状态：GoHTTPX v1 的项目宪章。后续开发开始前必须先阅读本文。
>
> 适用范围：当前 GoHTTPX 独立仓库根目录。

## 1. 项目定位

GoHTTPX 是一个长期运行在本机 loopback 的 Go HTTP 发包服务，以及一个保持 HTTPX 使用习惯的 Python SDK。

目标是让 Python 继续负责业务请求的组织方式，让 Go/req 负责 Python 无法提供的底层 TLS 指纹、连接池和协议能力。

典型部署只有一个 Python 后端：

- Python 后端内部有站点 A、站点 B 等多个业务模块。
- 只有确实需要特殊 TLS/HTTP 能力的请求才使用 GoHTTPX。
- Go 服务由运维或开发者手动启动并长期运行，Python 不负责启动或停止它。
- 多个 Python `Client`/`AsyncClient` 可以共享同一个 Go 服务进程，但各自拥有独立的 Go session。

## 2. 强制项目边界

GoHTTPX 已提取为独立仓库，源码边界只有当前仓库。

迁移来源仓库中的这些内容属于旧项目，不得重新复制、引用、迁移或顺手重构：

- `handlers/`
- `init/`
- 旧项目根 `main.go`
- 旧项目根 `go.mod`
- 旧项目根 `go.sum`

尤其禁止把旧项目的 `goReq`、Huma handler、日志初始化和业务代理参数结构复制进 GoHTTPX。

当前仓库由原仓库的 `gohttpx/` 子目录通过 Git subtree 历史提取生成，只保留了与 GoHTTPX 直接相关的提交。仓库根目录有独立的 `go.mod`，构建和测试必须从仓库根目录执行。

后续提交 GoHTTPX 时：

1. 默认只修改当前仓库。
2. 不通过相对路径依赖迁移来源仓库或其他本机项目。
3. GitHub 发布只包含当前仓库，不打包迁移来源仓库。

## 3. 核心设计原则

### 3.1 HTTPX 负责高层 HTTP 语义

Python HTTPX 负责：

- `params`
- headers 与 cookies 状态
- Basic/Digest auth
- redirect 与 history
- `json`、`data`、`files`、`content` 编码
- 同步与异步调用接口
- 将结果呈现为真实 `httpx.Response`

Go 不重新解释这些业务对象。Python 必须先生成 prepared request，再把以下最终数据交给 Go：

- method
- 绝对 URL
- 有序、可重复的 header 二元组
- 最终 body bytes
- 单次请求超时
- Go 专属请求选项

### 3.2 Go 负责底层传输能力

Go/req 负责：

- uTLS fingerprint 与 impersonate
- mTLS 客户端证书
- Root CA 与服务端证书验证
- HTTP/1.1、HTTP/2、HTTP/3、H2C
- HTTP/HTTPS/SOCKS proxy
- 连接池和传输超时
- req retry、trace、dump
- 原始正文发送与响应读取

任何参数只能处于以下两种状态之一：

1. 已真实映射并有行为测试。
2. 明确返回 `INVALID_REQUEST`。

禁止接受参数后静默忽略、降级协议或绕过代理。

### 3.3 状态归调用方所有

- 业务 cookies、headers、auth 只保存在 Python HTTPX client 中。
- Go session 不保存业务 cookies 和公共业务 headers。
- Go session 只保存 TLS、代理、HTTP 版本、retry 和连接池等传输配置。
- 控制 API bearer token 永远不能转发到目标网站。

## 4. 进程与 session 模型

- Go 服务是一个手动启动、长期存在的独立进程。
- 同步 `Client` 构造时立即创建 Go session。
- 异步 `AsyncClient` 在第一次请求时懒创建 Go session。
- 每个已创建会话的 Python client 对应一个独立 req client。
- 关闭一个 Python client 只能删除自己的 Go session。
- Go 服务重启或空闲清理造成 session 丢失时，只能在收到完整、严格的 `CLIENT_NOT_FOUND` 后自动重建一次。
- 控制连接断开、超时或响应不完整时，不得自动重发 POST，因为无法确认目标请求是否已经执行。

Python 不为每个站点、每个请求或每个协程启动 Go 子进程。

## 5. v1 控制协议

### 5.1 路由

- `GET /api/v1/health`
- `GET /api/v1/capabilities`
- `POST /api/v1/clients`
- `DELETE /api/v1/clients/{client_id}`
- `POST /api/v1/clients/{client_id}/requests`

除 health 外，正式模式使用 bearer token。只有显式 `--insecure-no-auth` 的本机调试模式免鉴权。

### 5.2 Canonical JSON

v1 采用严格 JSON：

- 任意层级禁止 `null`。
- 未知字段必须拒绝。
- required 字段必须存在且类型精确，`bool` 不能冒充整数。
- 只有协议预先声明的 optional 字段可以省略。
- 禁止尾随第二个 JSON 值。
- 两个 POST 控制接口必须使用 `application/json`，允许合法 charset 参数。

成功请求响应的 required 字段：

- `protocol_version`
- `request_id`
- `status_code`
- `reason_phrase`
- `headers`
- `body_base64`
- `url`
- `http_version`
- `elapsed_ms`

optional 字段只有：

- `trace`：启用 trace 时出现。
- `dump`：启用 dump 时出现。

错误对象 required 字段：

- `code`
- `message`
- `retryable`

`request_id` 只在服务已经成功生成请求 ID 时出现。

### 5.3 兼容规则

v1 exact envelope 不允许单方面增加、删除、改名或改变字段类型。

新增协议能力时只能：

1. 使用新的 protocol version 和 endpoint；或
2. 同时升级 Go 服务、Python SDK、测试和文档后整体发布。

不要以“可选字段”为理由向旧 v1 envelope 随意加字段，旧 SDK 会按设计拒绝未知字段。

## 6. Header 语义

### 6.1 请求 Header

Python prepared headers 是权威输入。

- 调用方没有提供 `User-Agent` 或 `Content-Type` 时，Go 不得自动补充。
- HTTP/1 普通 header 保留首次出现的 casing、名称分组顺序和重复值顺序。
- 默认 header order 来自 prepared header 输入顺序。
- 显式 `RequestOptions.header_order` 非空时优先使用显式顺序。
- Host、User-Agent、Content-Length、Transfer-Encoding 是 Go/req 的协议特殊字段，必须按专门测试维护。
- HTTP/2 和 HTTP/3 的 header 名按协议使用小写，不能承诺保留 HTTP/1 casing。

所有 header 状态必须保存在单次请求 context 中，不能使用 client 级共享可变开关，否则并发请求会串扰。

### 6.2 响应 Header

响应已经通过 Go `net/http.Response.Header`：

- 保留 header 值。
- 保留同名 header 的重复值。
- 不承诺原始 casing。
- 不承诺目标服务器的全局线序。
- v1 envelope 使用稳定的 canonical 名称排序。

除非未来改用原始协议解析，否则不得在文档中承诺响应原始 casing 或 wire order。

## 7. 正文与 HTTP 方法

服务端只有一个通用 request route，不为 GET、POST、PUT 等方法分别创建业务 handler。

Python SDK 必须支持 HTTPX 能准备出的任意 method。发布测试至少覆盖：

- GET
- POST
- PUT
- PATCH
- DELETE
- HEAD
- OPTIONS
- 自定义 method，例如 PURGE

`json`、form `data`、multipart `files` 和原始 `content` 最终都转换为 body bytes，通过同一协议传递。

目标网站返回的 4xx/5xx 是正常 `httpx.Response`，不能转换成 GoHTTPX 控制错误。

## 8. TLS、证书与 HTTP 版本

### 8.1 TLS fingerprint 与 mTLS

TLS fingerprint 和客户端证书是两项独立能力，可以同时使用。

req 原生 fingerprint handshake 不会自动携带客户端证书，因此 GoHTTPX 使用固定内部 TLS handshake：

- 保留所选 ClientHelloID。
- 保留 Root CA、verify、SNI、ALPN。
- 正确选择并发送客户端证书。
- 兼容 HTTP CONNECT proxy。
- 不接受调用方自定义 callback。
- 不允许失败后静默降级为普通 TLS。

### 8.2 HTTP/3 例外

HTTP/3 使用 QUIC 标准 TLS transport：

- 省略 fingerprint 时允许使用 HTTP/3。
- 显式 uTLS fingerprint 或 impersonate 与 HTTP/3 组合必须拒绝。
- HTTP/3 与普通 HTTP proxy 组合必须拒绝，不能绕过代理直连。
- HTTP/3 不支持 TCP 专属的 chunked、connection close 和 header order 选项时必须明确拒绝。
- 能映射到 QUIC 的 handshake timeout、idle timeout、compression 和 response header limit 必须真实生效。

### 8.3 H2/H2C 与代理

强制 HTTP/2、HTTP/3、H2C 如果会绕过 req proxy，组合必须在创建 session 时拒绝。

H2C 必须通过真实 cleartext HTTP/2 服务验证，不能只断言配置标志。

## 9. Python SDK 规范

公开客户端：

- `Client(httpx.Client)`
- `AsyncClient(httpx.AsyncClient)`

公开配置入口：

- session 级：`client_options=ClientOptions(...)`
- request 级：`extensions={"go_req": RequestOptions(...)}`

也允许 request options 使用字段严格匹配的 mapping；未知字段或错误类型必须在 Python 侧拒绝。

不提供 `limits`、目标 `trust_env` 的便利映射：

- HTTPX limits 是全局池语义，Go 配置主要是固定 session/per-host 语义，不能假装完全等价。
- HTTPX `trust_env` 涉及按 scheme 和 `NO_PROXY` 动态选路，Go session 使用固定 proxy，不能无损转换。
- 连接池使用 `ClientOptions.transport` 显式配置。
- 代理使用 `ClientOptions.proxy_url` 显式配置。

内部访问 Go 控制面的 HTTPX client 必须固定 `trust_env=False`，避免本机控制流量进入环境代理。

## 10. 同步、协程与并发

同步和异步 API 必须共享同一套 wire 编解码与错误映射，不能维护两份逐渐漂移的协议实现。

异步实现必须满足：

- 首次并发请求只创建一个 session。
- 同一旧 generation 的 `CLIENT_NOT_FOUND` 只重建一次。
- 每个请求最多重发一次。
- 并发等待者的异常绑定各自原始 request。
- 取消全部 create waiter 后，`aclose()` 仍收割 create task 并删除已创建 session。
- 多个并发 `aclose()` 等待同一个 cleanup task。
- 取消一个 close waiter 不得取消底层 cleanup。

同步 `close()` 同样必须等待在途请求，不得因为 HTTPX 已标记 closed 而让第二个并发 close 提前返回。

所有网络 I/O 必须在生命周期 condition/lock 之外执行，避免死锁。

## 11. 错误与日志

Go 服务不输出启动日志或请求日志。

- 控制 API 错误直接返回 JSON error envelope。
- Python 将上游 timeout 映射为 `httpx.TimeoutException`。
- DNS、connect、TLS 错误映射为 `httpx.ConnectError`。
- 上游协议错误映射为 `httpx.RemoteProtocolError`。
- 其他控制协议错误映射为 `GoProtocolError`。
- 本地 Go 服务不可用映射为 `GoServiceUnavailable`。
- 异常保留原目标 `httpx.Request`、`code` 和可用的 `request_id`。

Python 页面层可以捕获这些异常并决定如何展示。GoHTTPX 不包含前端页面，也不引入业务日志系统。

只有服务无法启动的参数错误可以写入 stderr；不得记录 token、Authorization、Proxy-Authorization、Cookie、headers、query 或 body。

## 12. 安全边界

- 默认只能监听 loopback。
- 非 loopback 必须显式 `--allow-non-loopback`，并由部署方承担网络隔离责任。
- 正式模式必须设置 `GOHTTPX_TOKEN` 或 `--token`。
- `--insecure-no-auth` 只允许本机调试。
- token 只用于控制 API，不能进入目标 headers、trace、dump 或错误消息。
- 请求体、证书 PEM、header 数组和响应正文都有硬限制。
- proxy 与强制协议组合不得绕过代理。
- 无法确认目标是否执行时，不重发非幂等请求。

## 13. 明确限制

v1 当前不支持：

- streaming request/response
- WebSocket
- SSE
- 并行分块下载
- 调用方传入 Go callback
- 动态 proxy callback
- 自定义 dial callback
- 调用方自定义 TLS handshake

请求和响应完整缓冲在内存中。默认目标请求和响应正文上限均为 48 MiB；create client JSON 另有较小硬限制。

这些限制必须显式写入文档，不能提供“看似接受但不生效”的参数。

## 14. 测试体系

### 14.1 Go 测试

Go 使用本机测试服务覆盖：

- HTTP/1 raw TCP header casing/order/duplicates
- HTTP/2
- HTTP/3 QUIC
- H2C
- Root CA 与 verify
- uTLS fingerprint + mTLS
- HTTP/HTTPS CONNECT proxy
- retry、trace、dump
- session delete、idle cleanup、registry shutdown
- body/header/config 限制
- JSON media type 与 canonical schema
- race detector

只检查配置字段不算测试完成，必须尽可能断言目标服务器实际观察到的协议和数据。

### 14.2 Python 测试

Python 测试分两层：

1. Fake control service：精确测试 SDK 编解码、错误、并发、取消和 session 重建。
2. 真实 E2E：构建单个临时 Go EXE，启动本机目标站，再通过公开 `Client`/`AsyncClient` 请求。

真实 E2E 必须覆盖：

- 所有常用 method 与自定义 method
- json/data/files/content
- cookies、headers、query 重复值
- Basic/Digest auth
- redirect/history
- 目标 404/500
- timeout
- 二进制正文
- 两个 client 隔离
- `CLIENT_NOT_FOUND` 单次重建
- token 不泄漏
- async client

测试只访问 loopback，不依赖公网。

## 15. 发布门槛

每次发布前必须 fresh 执行：

```powershell
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
python -B -m unittest discover -s python -p "test_*.py" -v
```

然后执行：

```powershell
go build -trimpath -ldflags="-s -w" -o gohttpx-server.exe .
gohttpx-server.exe --version
```

发布构建必须验证：

- `vcs.revision` 对应已审查的 clean 源码提交。
- `vcs.modified=false`。
- EXE SHA-256 和大小写入发布记录。
- health、capabilities、graceful shutdown 实际运行通过。
- stdout/stderr 没有启动或请求日志。
- 工作树没有未提交源码修改。

公开 GitHub 发布时，发布记录以对应 GitHub Release 为准；其中必须写明版本、clean revision、EXE SHA-256 和字节数。手动部署步骤见 `RUNBOOK.md`，变更摘要见 `CHANGELOG.md`。

## 16. 后续修改规则

### 16.1 新增 ClientOptions 字段

必须同时完成：

1. Go DTO 与严格 JSON 校验。
2. Go req/transport 的真实映射或明确拒绝。
3. Python dataclass 与 wire 序列化。
4. Go 边界测试。
5. Python fake-control 测试。
6. 必要的真实 E2E。
7. README 与本文更新。

### 16.2 新增 RequestOptions 字段

必须验证同步、异步、重建重发和 HTTP/3 组合，不得只测试第一次同步请求。

### 16.3 修改 envelope

禁止直接修改 v1 exact envelope。先设计新的 protocol version/endpoint，再同步更新双方。

### 16.4 升级依赖

升级 req、uTLS、quic-go 或 Go toolchain 时必须重跑：

- 49 fingerprint 一致性
- HTTP/3 Root CA/mTLS
- HTTP/1 raw header
- HTTP2/H2C
- proxy
- full/race/vet/Python E2E
- `--version` 与 build info 防漂移测试

## 17. 禁止事项

- 禁止复制父项目的 `goReq` 或业务 handler。
- 禁止引入 Huma、旧日志初始化或父项目配置对象。
- 禁止在 Go session 保存业务 cookies/headers。
- 禁止参数静默忽略。
- 禁止 TLS、HTTP 版本或 proxy 失败后静默降级。
- 禁止因控制连接不确定而重发 POST。
- 禁止只测试配置标志而不测试真实线上行为。
- 禁止把 token、证书、headers、cookies、query 或 body 写入日志。
- 禁止为了“以后可能需要”预留 callback、interface 或兼容层。
- 禁止修改旧项目来迁就 GoHTTPX；适配应由调用 GoHTTPX 的业务代码完成。

## 18. 当前固定版本

- GoHTTPX server：`1.0.0`
- Python SDK：`1.0.0`
- protocol：`1`
- Python：`>=3.10`
- HTTPX：`>=0.28,<0.29`
- req/v3：`v3.59.0`
- quic-go：`v0.60.0`
- uTLS：`v1.8.2`

依赖版本必须以 `go.mod`、`--version` 和测试为准；升级后同步修改本文。

## 19. 开发前检查清单

开始任何修改前逐项确认：

- [ ] 修改只属于当前独立仓库，没有引入迁移来源项目代码。
- [ ] 调用方与 Go 的职责没有反转。
- [ ] 参数会真实生效或明确拒绝。
- [ ] v1 canonical schema 没有被单方面改变。
- [ ] headers/cookies 仍由 HTTPX 管理。
- [ ] 同步和异步行为一致。
- [ ] 并发、取消、close 和 session 重建已考虑。
- [ ] TLS + mTLS、proxy 和 HTTP 版本组合没有静默降级。
- [ ] 没有新增启动日志、请求日志或敏感数据输出。
- [ ] 已先写能复现问题的测试。
- [ ] full/race/vet/Python E2E 已 fresh 通过。
- [ ] README、本文和发布记录已同步。

如任一项无法明确回答，先停止编码并补充设计或测试。
