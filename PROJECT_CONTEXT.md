# GoHTTPX 项目上下文与开发规范

> 文档状态：GoHTTPX 2.1 项目规范，业务控制协议仍为 v1。后续开发开始前必须先阅读本文。
>
> 适用范围：当前 GoHTTPX 独立仓库根目录。

## 1. 项目定位

GoHTTPX 是一个长期运行在本机 loopback 的 Go HTTP 发包服务，以及一个保持 HTTPX 使用习惯的 Python SDK。

目标是让 Python 继续负责业务请求的组织方式，让 Go/req 负责 Python 无法提供的底层 TLS 指纹、连接池和协议能力。

典型部署只有一个 Python 后端：

- Python 后端内部有站点 A、站点 B 等多个业务模块。
- 只有确实需要特殊 TLS/HTTP 能力的请求才使用 GoHTTPX。
- 默认由所属 Python 自动启动、动态分配端口、自动回收和恢复；显式外部模式保留手动部署。
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

- 默认每个 Python 进程托管一个长期存在的 Go 子进程；Windows 在创建时原子加入专属 Job。
- 同步 `Client` 构造时立即创建 Go session。
- 异步 `AsyncClient` 在第一次请求时懒创建 Go session。
- 每个已创建会话的 Python client 对应一个独立 req client。
- 关闭一个 Python client 只能删除自己的 Go session。
- 托管 Go 重启时，按新实例快照重建各 client session；同一实例内完整 `CLIENT_NOT_FOUND` 也允许一次重建。
- 控制连接断开、超时或响应不完整时，不得自动重发 POST，因为无法确认目标请求是否已经执行。

Python 不为每个站点、每个请求或每个协程启动 Go 子进程。关闭最后一个 client 不结束健康 Go；应用退出或显式 shutdown 才结束运行时。恢复只允许一次额外安全尝试，结果不确定不得重放。

## 5. v1 控制协议

### 5.1 路由

- `GET /api/v1/health`
- `GET /api/v1/capabilities`
- `POST /api/v1/clients`
- `DELETE /api/v1/clients/{client_id}`
- `POST /api/v1/clients/{client_id}/requests`

外部模式除 health 外使用 bearer token；托管模式所有控制路由同时校验自动生成的 token 与实例 ID。业务 v1 JSON 不添加实例字段。

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

### 8.1.1 自定义 TLS JSON

2.1 增加 `tls_spec`（Python JSON 对象或字符串，Go 接收对象），沿用 uTLS JSON 字段，并明确限制扩展支持范围。详情见 `docs/tls-json.md`。

- 配置属于 Client/session，Python 在构造时保存不可变快照，恢复时重发同一配置。
- 原始 JSON 声明可以保存，uTLS 扩展对象和 KeyShare 不得跨连接共享；每次握手重新解析并 `HelloCustom + ApplyPreset`。
- 不把 `SetTLSFingerprintSpec` 的共享 spec 指针直接用于并发连接；固定内部握手同时保留 mTLS、SNI、verify 与代理路径。
- TLS JSON 配置/示例变更必须检查服务端实际收到的 ClientHello（套件、扩展内容和顺序），只检查 DTO、JA3/JA4 或 HTTP 200 不足以验收。
- 公共 TLS 演示内联在 README 的 `tls-demo` 代码块，测试直接解析并执行该代码块；不依赖另行下载的 JSON。最小差异配置作为内部夹具保存在 `testdata/tls/`，本地旧 `examples/tls/*.json` 不提交或打包。新增模板必须补可发现用例并记录协议/动态字段边界。
- 2.1 不开放 PSK/ticket 注入、TLS 1.3 恢复配置、任意原始扩展或回调；未知/忽略字段必须拒绝。

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

Go 不输出业务请求日志；托管 stdout 专供启动协议。Python 的 gohttpx.runtime 命名 logger 可提供不含敏感材料的生命周期事件。

- 控制 API 错误直接返回 JSON error envelope。
- Python 将上游 timeout 映射为 `httpx.TimeoutException`。
- DNS、connect、TLS 错误映射为 `httpx.ConnectError`。
- 上游协议错误映射为 `httpx.RemoteProtocolError`。
- 其他控制协议错误映射为 `GoProtocolError`。
- 托管服务未就绪/明确未发送，以及外部服务不可用映射为 `GoServiceUnavailable`；托管已提交后结果不确定映射为 `GoRequestOutcomeUnknown`，不能继承 ConnectError。
- 异常保留原目标 `httpx.Request`、`code` 和可用的 `request_id`。

Python 页面层可以捕获这些异常并决定如何展示。GoHTTPX 不包含前端页面，也不引入业务日志系统。

只有服务无法启动的参数错误可以写入 stderr；不得记录 token、Authorization、Proxy-Authorization、Cookie、headers、query 或 body。

## 12. 安全边界

- 默认只能监听 loopback。
- 非 loopback 必须显式 `--allow-non-loopback`，并由部署方承担网络隔离责任。
- 外部正式模式设置 `GOHTTPX_TOKEN` 或 `--token`；托管凭证由 SDK 自动生成，不接受外部密钥、不读取该环境变量。
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

Python 测试分四层：

1. Fake control service：精确测试 SDK 编解码、错误、并发、取消和 session 重建。
2. 真实 E2E：构建单个临时 Go EXE，启动本机目标站，再通过公开 `Client`/`AsyncClient` 请求。
3. Windows 托管故障注入：由独立观察进程验证父进程死亡、启动窗口、隔离、崩溃、恢复、取消和资源回收。
4. 安装测试：独立虚拟环境、移除 Go PATH、使用 wheel 内置二进制完成请求及退出回收。

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

网络行为测试只访问 loopback；构建/安装依赖可能访问软件源。

### 14.3 固定位置与测试发现

| 内容 | 固定位置 | 执行方式 |
|---|---|---|
| Go 服务单元与集成测试 | 与被测 Go 包同目录的 `*_test.go`，当前为根目录 `api_test.go`、`main_test.go`、`managed_test.go` | `go test ./... -count=1` |
| Python SDK、真实 E2E、托管生命周期、安装及发布约束测试 | `python/test_*.py` | `python -B -m unittest discover -s python -p "test_*.py" -v` |
| 本机目标服务与辅助进程 | `testdata/`、`python/` 中的测试辅助模块 | 由对应正式用例启动，不单独计为回归用例 |
| 验证报告 | `docs/testing/` | 记录实际执行结果，不替代可运行测试 |
| 临时诊断脚本、日志和构建产物 | `.tmp/`，发布构建产物为 `dist/`、`build/` | 不属于正式回归，用完按文件清理临时脚本 |

Go 测试需要访问包内实现，不为集中目录而移出被测包。Python 沿用现有 `python/` 测试发现入口，不新增默认命令无法发现的散落用例。新增正式用例必须确认已被默认命令收集。

### 14.4 每次修改的回归与预期约束

既有用例的预期代表已接受的行为，默认保持不变：

1. 开始代码修改前确认相关测试基线；修复缺陷先增加可复现的失败用例。
2. 代码修改完成后先跑受影响用例，再 fresh 执行下方完整回归。不得用之前某次通过记录代替本次执行。
3. 新增功能同时补正常、异常、边界用例；并发、Cookie 隔离、重启、退出与请求重放规则有改动时补对应实际行为验证。
4. 测试失败应先定位原因。禁止为了通过而降低断言强度、扩大容差、删除或跳过用例；不能让测试追随错误实现。
5. 只有需求明确改变被测行为，或有证据证明用例、测试数据本身有误，才允许同步调整预期；必须说明旧预期、新预期及依据。单纯重构、修复实现或更换测试数据不自动授权改变行为预期。
6. 报告命令、结果、失败及跳过原因；平台不支持或环境依赖缺失属于验证边界，不能算作通过。

从仓库根目录依次执行，任一步失败先处理，不得把部分通过报告成整体通过：

```powershell
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
python -m build
python -B -m unittest discover -s python -p "test_*.py" -v
```

构建当前源码的 wheel 必须在 Python 安装测试之前，避免 `dist/` 的旧包掩盖源码回归。CI 同样按此顺序执行。测试依赖需要 `httpx`、`cryptography` 和 `build`。

临时排查不能冒充正式回归。例如内存采样记录只反映一次环境下的曲线，不应断言进程必须降回启动时的固定 MB 数；若要将其转为正式用例，必须定义可重复的本机负载、采样口径和有依据的容差，并保存在上述测试位置。

## 15. 发布门槛

每次发布前必须 fresh 执行：

```powershell
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
python -m build
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
- stdout/stderr 没有业务请求日志或敏感材料；托管 stdout 允许私有启动消息。
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

- GoHTTPX server：`2.1.1`
- Python SDK：`2.1.1`
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
- [ ] 没有新增业务请求日志或敏感数据输出；托管机器消息和命名生命周期日志符合设计。
- [ ] 已先写能复现问题的测试。
- [ ] full/race/vet/Python E2E 已 fresh 通过。
- [ ] README、本文和发布记录已同步。

如任一项无法明确回答，先停止编码并补充设计或测试。

自动托管的详细约束见 [设计](docs/design/2026-08-27-managed-runtime.md)，当前测试证据见 [验证记录](docs/testing/2026-08-27-managed-runtime.md)。默认平台仅 Windows amd64；Unix 托管尚未实现，不能以普通子进程替代回收保证。
