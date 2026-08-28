# GoHTTPX 2.0

GoHTTPX 保留 HTTPX 的请求编码、Cookie、认证、重定向和 Response 语义，由本地 Go 执行 TLS 指纹、代理及 HTTP/1/2/3 请求。

**2.0 默认自动托管 Go：每个 Python 进程一份 Go，多个 client 共用进程，但各自拥有独立 session 和 Cookie。** 不需要手动启动服务，不需要配置端口或请求密钥。

当前版本为 `2.0.0`，控制协议仍为 `/api/v1`、`protocol_version=1`。发布产物见 [PyPI](https://pypi.org/project/gohttpx/) 和 [GitHub Releases](https://github.com/Assistest/GoHTTPX/releases)。

## 安装与最小用法

默认托管支持 Windows 10+/Windows Server 2016+，安装包平台为 Windows amd64，Python 3.10+、`httpx>=0.28,<0.29`。其他平台尚未实现同等级进程回收，不能使用默认托管模式。

从 PyPI 安装，Go EXE 随 wheel 一起安装，无需另行下载：

```powershell
python -m pip install --upgrade --only-binary=gohttpx "gohttpx==2.0.0"
```

`--only-binary=gohttpx` 避免在不支持的平台意外回退到源码编译；本版本不提供 Linux/macOS 托管安装包。

开发者也可以在仓库构建并安装本地 wheel（仅构建机器需要 Go 工具链）：

```powershell
python -m pip install build
python -m build
python -m pip install dist\gohttpx-2.0.0-py3-none-win_amd64.whl
```

wheel 内置匹配版本的 Go EXE。部署机器安装 wheel 后不需要 Go 编译器；第一次请求不下载、不编译任何程序。2.0 不再支持只复制一个 `gohttpx.py` 即完成接入。

```python
from gohttpx import Client

with Client(follow_redirects=True) as client:
    response = client.get("https://example.com/")
    print(response.status_code)
```

异步调用：

```python
import asyncio
from gohttpx import AsyncClient

async def main():
    async with AsyncClient() as client:
        response = await client.get("https://example.com/")
        print(response.status_code)

asyncio.run(main())
```

同步 client 构造时启动/连接 Go 并创建 session；异步 client 在首次请求时初始化。`import gohttpx` 不启动 Go。

## 进程、session 与 Cookie

```text
Python 进程 A                         Python 进程 B
  Client A1 → Cookie A1 → session A1    Client B1 → Cookie B1 → session B1
  Client A2 → Cookie A2 → session A2    Client B2 → Cookie B2 → session B2
                  ↓                                  ↓
             Go A / 动态端口 A                  Go B / 动态端口 B
```

- 每次接口请求创建一个 client，只创建/删除轻量 Go session，不反复启动 EXE。
- 关闭最后一个 client 后，健康 Go 仍保留到 Python 退出或显式 `shutdown()`。
- Cookie Jar 由各自的 HTTPX client 保存，按域名、路径、Secure、过期规则处理；Go Cookie Jar 关闭。不要把不同账号放进同一个 client，也不要显式共享一个底层 CookieJar。
- Go 重启不会清空 Python 已接收的 Cookie。尚未收到的 Set-Cookie 无法补回，Python 退出后的内存 Cookie 也不会自动保存。
- 内部 bearer token 和实例 ID 每次启动随机生成，通过私有管道传递；它们不会发给目标网站。用户不用配置密钥，但内部实例鉴权保留，防止 A 的请求被 B 接收。
- Go 直接绑定 `127.0.0.1:0`，保留 listener 后报告实际端口，没有先找端口再释放的竞争窗口。

Go 在创建时原子加入仅由所属 Python 持有的 Windows Job。Python 正常退出、未捕获异常、`os._exit()`、任务管理器强杀后，由系统回收所属 Go；不会按进程名或裸 PID 批量杀进程。Job 无法创建或绑定时明确失败，不回退成普通子进程。

这里保证的是 Python **进程结束后的回收**，不是严格同时退出，也不保证强杀时业务请求完成。Python 卡死但进程还活着，需要宿主自己的 watchdog。

## 自动恢复与请求安全

后台监视器发现 Go 退出后，在有存活 client 时自动重启；并发请求共用同一次恢复。没有 client 时意外退出可暂缓到下次使用；显式 `start()/astart()` 预热后，即使没有 client 也保持恢复。

默认配置：启动等待 10 秒，关闭宽限 5 秒；健康检查间隔 5 秒、单次 1 秒、连续 3 次失败才替换存活但无响应的 Go。失败按指数退避，滚动 60 秒内达到 5 次失败后冷却 30 秒。目标站的 500、代理失败、目标超时不会直接导致 Go 重启。

服务恢复不等于重跑业务：

| 情况 | 处理 |
|---|---|
| 尚未提交目标请求、明确连接失败，未发送，或完整 `CLIENT_NOT_FOUND` | 原调用预算内最多增加一次安全尝试 |
| 已经发送后读写中断、响应丢失或实例/响应校验失败 | 抛出 `GoRequestOutcomeUnknown`，不自动重发 |
| 完整响应已收到且通过校验 | 正常返回 |

`GoRequestOutcomeUnknown` 继承 `httpx.TransportError`，不继承 `ConnectError`；包含原始 request、instance_id、可用时的 request_id、`outcome="unknown"`。遇到下单/支付等结果不确定的操作，应按业务标识查询结果。SDK 不会吞掉异常或重跑整个 Python 函数。

## 可选应用生命周期

```python
import gohttpx

# wheel 部署通常不用配置；开发时可指定匹配版本的 EXE。
# gohttpx.configure_runtime(binary_path=r"C:\services\gohttpx-server.exe")
gohttpx.start()  # 可省略；也可以在异步启动钩子 await gohttpx.astart()
try:
    with gohttpx.Client() as client:
        response = client.get("https://example.com/")
    print(gohttpx.runtime_status())
finally:
    gohttpx.shutdown()  # 异步关闭钩子使用 await gohttpx.ashutdown()
```

不要在每个接口请求结束时调用 `shutdown()`；每个请求仅关闭自己的 client。运行时关闭是应用级操作。

`configure_runtime()` 只能在没有 client、运行时未启动或已关闭时调用，支持 `binary_path`、`startup_timeout`、`shutdown_timeout`、`health_interval`、`health_timeout`、`health_failures`、`restart_limit`、`restart_window`、`cooldown`。时间单位为秒。关闭后的运行时不会被迟到请求复活；若确实需要重新初始化，先关闭旧 client，再显式配置。

`runtime_status()` 返回状态、owner_pid、child_pid、instance_id、endpoint、start_count、restart_count、active_clients、last_exit_code、last_failure、retry_in_seconds，不返回 token。命名 logger `gohttpx.runtime` 可接入应用日志，不调用 basicConfig、不打印业务请求。

## 保留的外部服务模式

显式传 `go_endpoint` 就是外部模式：Python 不启动、不停止、不重启该服务，只管理自己的 session。旧代码如果只传 `go_token`，需要补上原来的 endpoint；不允许猜测连接旧端口还是启动托管实例。

```python
from gohttpx import Client

with Client(go_endpoint="http://127.0.0.1:9876", go_token="your-secret") as client:
    response = client.get("https://example.com/")
```

仅外部模式在 `go_token=None` 时读取 `GOHTTPX_TOKEN`。托管模式忽略此环境变量。外部服务的构建、启动、鉴权和健康检查见 [RUNBOOK](RUNBOOK.md)。

## HTTPX 参数

`json/data/files/content`、params、headers、cookies、Basic/Digest auth、redirect/history 仍由 HTTPX 准备和处理；Go 接收最终 bytes。`client_options=ClientOptions(...)` 设置独立 session 的传输配置，单次选项放在 `extensions={"go_req": RequestOptions(...)}`。

支持 `tls_fingerprint`、`impersonate`、`verify`、`cert`、`proxy`、`http1`、`http2` 等固定会话便利参数。不接受 `transport`、`mounts`，不提供 `limits` 或目标 `trust_env` 的便利映射；固定代理和连接池请用下面的 DTO。控制连接始终 `trust_env=False`。

## TLS、代理、证书和 HTTP 版本

```python
import httpx

from gohttpx import Client, ClientOptions, TLSFingerprint

# TLS 指纹
with Client(tls_fingerprint=TLSFingerprint.CHROME_120) as client:
    response = client.get("https://example.test/")

# 固定代理；Proxy 的 auth 和 headers 子集会被序列化
proxy = httpx.Proxy("http://proxy.example:8080", auth=("user", "pass"), headers={"X-Proxy": "one"})
with Client(proxy=proxy) as client:
    response = client.get("https://example.test/")

# 自定义根 CA 与 mTLS
with Client(
    verify=r"C:\certs\root-ca.pem",
    cert=(r"C:\certs\client.pem", r"C:\certs\client-key.pem"),
) as client:
    response = client.get("https://example.test/")

# HTTP/1.1、HTTP/2、HTTP/3、H2C
http1 = Client(client_options=ClientOptions(http_version="http1"))
http2 = Client(client_options=ClientOptions(http_version="http2"))
http3 = Client(client_options=ClientOptions(http_version="http3", tls_fingerprint=None))
h2c = Client(client_options=ClientOptions(http_version="h2c"))
for client in (http1, http2, http3, h2c):
    client.close()
```

`verify` 只支持 `bool` 或 CA PEM 文件路径，不接受自定义 `ssl.SSLContext`。`cert` 支持一个同时含证书和私钥的 PEM 文件，或 `(证书路径, 私钥路径)`。`httpx.Proxy` 若含自定义 SSLContext 会被拒绝。`proxy_url` 支持 `http`、`https`、`socks5`、`socks5h`。

组合限制：

- `impersonate` 与任何显式 `tls_fingerprint` 互斥；impersonate 可选 `none/chrome/firefox/safari`。
- proxy 不能与强制 `http2`、`http3`、`h2c` 组合；proxy 与 `auto/http1` 可用。
- HTTP/3 不接受显式 TLS fingerprint 或非 `none` impersonate，使用标准 QUIC TLS。
- 强制 HTTPS HTTP/2 不接受显式 TLS fingerprint 或非 `none` impersonate；省略两者时使用 req 的标准 TLS 以协商 `h2`，并支持 mTLS。
- HTTP/3 支持 verify、root CA、client cert/key、compression、GET body、retry、trace、dump、单次 timeout 和 `max_response_header_bytes`。
- HTTP/3 将 `tls_handshake_timeout_ms` 映射为 QUIC `HandshakeIdleTimeout`，将 `idle_conn_timeout_ms` 映射为 QUIC `MaxIdleTimeout`。直接发送 0 时采用 quic-go 的 5 秒/30 秒默认；Python `TransportOptions` 默认会显式发送 10000/90000 ms。
- HTTP/3 的 proxy、HTTP 阶段 timeout、TCP pool/buffer 选项和非默认 HTTP/2 嵌套选项会在创建会话时返回 `INVALID_REQUEST`。空 map/slice 和数值 0 视为默认。
- HTTP/3 请求的非空 `header_order`、`pseudo_header_order`，以及 `force_chunked=true`、`close_connection=true` 会返回 `INVALID_REQUEST`。
- `keep_alive=false` 会在每次 HTTP/3 响应完整读取后关闭空闲 QUIC 连接；`true` 允许复用。

### TLSFingerprint 全部 49 个值

| 家族 | 值 |
|---|---|
| Go/随机 | `golang`, `randomized`, `randomized_alpn`, `randomized_no_alpn` |
| Android | `android_11_okhttp` |
| Chrome | `chrome_auto`, `chrome_58`, `chrome_62`, `chrome_70`, `chrome_72`, `chrome_83`, `chrome_87`, `chrome_96`, `chrome_100`, `chrome_102`, `chrome_106_shuffle`, `chrome_100_psk`, `chrome_112_psk_shuffle`, `chrome_114_padding_psk_shuffle`, `chrome_115_pq`, `chrome_115_pq_psk`, `chrome_120`, `chrome_120_pq`, `chrome_131`, `chrome_133` |
| Firefox | `firefox_auto`, `firefox_55`, `firefox_56`, `firefox_63`, `firefox_65`, `firefox_99`, `firefox_102`, `firefox_105`, `firefox_120` |
| iOS | `ios_auto`, `ios_11_1`, `ios_12_1`, `ios_13`, `ios_14` |
| Edge | `edge_auto`, `edge_85`, `edge_106` |
| Safari | `safari_auto`, `safari_16_0` |
| 360 | `360_auto`, `360_7_5`, `360_11_0` |
| QQ | `qq_auto`, `qq_11_1` |

`ClientOptions.tls_fingerprint` 的 Python 默认是 `None`；当 HTTP 版本为 `auto/http1/h2c` 且 impersonate 为 `none` 时，SDK 的有效默认是 `android_11_okhttp`。强制 HTTPS HTTP/2 与 HTTP/3 使用标准 TLS。

## 完整 DTO 字段矩阵

所有时间字段单位均为毫秒。配置 JSON 总大小上限为 4 MiB。表中的“0=默认”表示不调用对应 req 设置；HTTP/3 的例外单独列出。

### ClientOptions

| 字段 | Python 类型 | 默认 | 含义、边界与 HTTP/3 规则 |
|---|---|---:|---|
| `tls_fingerprint` | `TLSFingerprint | str | None` | `None` | `auto/http1/h2c` 且无 impersonate 时有效默认 `android_11_okhttp`；强制 HTTPS HTTP/2、HTTP/3 必须省略。 |
| `impersonate` | `Impersonate | str` | `none` | `none/chrome/firefox/safari`；非 `none` 与显式 fingerprint 互斥，强制 HTTPS HTTP/2、HTTP/3 拒绝。 |
| `proxy_url` | `str | None` | `None` | 固定 `http/https/socks5/socks5h` URL；不能与强制 HTTP/2、HTTP/3、H2C 组合。 |
| `verify` | `bool` | `True` | 是否校验证书；HTTP/3 生效。 |
| `root_ca_pem` | `str | None` | `None` | 一个或多个纯 `CERTIFICATE` PEM，禁止夹杂其他字节/块；HTTP/3 生效。 |
| `client_cert_pem` | `str | None` | `None` | 客户端证书 PEM；必须和 key 同时提供；HTTP/3 生效。 |
| `client_key_pem` | `str | None` | `None` | 客户端私钥 PEM；必须和 cert 匹配；HTTP/3 生效。 |
| `http_version` | `str` | `auto` | `auto/http1/http2/http3/h2c`。 |
| `keep_alive` | `bool` | `True` | TCP/QUIC 连接复用；HTTP/3 false 时每次完整响应后关闭空闲连接。 |
| `compression` | `bool` | `False` | req/QUIC 原生压缩协商；默认关闭以保持 HTTPX 的 `Accept-Encoding` 与正文一致。 |
| `allow_get_body` | `bool` | `True` | 是否允许 GET 携带 body；HTTP/3 生效。 |
| `retry` | `RetryOptions` | `RetryOptions()` | 会话级重试，见下表；HTTP/3 生效。 |
| `transport` | `TransportOptions` | `TransportOptions()` | 连接与 Transport 配置，见下表。 |
| `http2` | `HTTP2Options` | `HTTP2Options()` | HTTP/2 帧和 timeout 配置；HTTP/3 只接受默认/零值。 |

### RetryOptions

| 字段 | 类型 | 默认 | 边界与规则 |
|---|---|---:|---|
| `count` | `int` | `0` | `0..10`；0 时 mode 必须为 `none`。 |
| `mode` | `str` | `none` | `none/fixed/backoff`；count>0 时必须是 fixed 或 backoff。 |
| `fixed_interval_ms` | `int` | `0` | `0..600000`；fixed 模式必须大于 0，其他模式必须为 0。 |
| `backoff_min_ms` | `int` | `0` | `0..600000`；backoff 模式要求 `0 < min <= max`，其他模式为 0。 |
| `backoff_max_ms` | `int` | `0` | `0..600000`；规则同上。 |
| `status_codes` | `tuple[int, ...]` | `()` | 每项 `100..599` 且不得重复；none 模式必须为空。配置后这些状态码和网络错误触发 req 重试。 |

### TransportOptions

| 字段 | 类型 | 默认 | 单位/边界 | HTTP/3 |
|---|---|---:|---|---|
| `tls_handshake_timeout_ms` | `int` | `10000` | ms，`0..600000` | 映射 QUIC 握手空闲 timeout。 |
| `response_header_timeout_ms` | `int` | `0` | ms，`0..600000` | 非 0 拒绝。 |
| `expect_continue_timeout_ms` | `int` | `1000` | ms，`0..600000` | 仅 0 可用；SDK 在默认 HTTP/3 配置中发送 0。 |
| `idle_conn_timeout_ms` | `int` | `90000` | ms，`0..600000` | 映射 QUIC 最大空闲 timeout。 |
| `max_idle_conns` | `int` | `100` | `0..100000` | 仅 0 可用；SDK 在默认 HTTP/3 配置中发送 0。 |
| `max_idle_conns_per_host` | `int` | `0` | `0..100000` | 非 0 拒绝。 |
| `max_conns_per_host` | `int` | `0` | `0..100000` | 非 0 拒绝。 |
| `max_response_header_bytes` | `int` | `0` | bytes，`0..16777216` | 生效。 |
| `read_buffer_size` | `int` | `0` | bytes，`0..16777216` | 非 0 拒绝。 |
| `write_buffer_size` | `int` | `0` | bytes，`0..16777216` | 非 0 拒绝。 |
| `proxy_connect_headers` | `Mapping[str, Sequence[str]]` | `{}` | CONNECT header 名必须是 HTTP token，值不得含控制字符 | 非空拒绝。 |

### HTTP2Options 与嵌套 DTO

| 字段 | 类型 | 默认 | 边界/含义 | HTTP/3 |
|---|---|---:|---|---|
| `settings` | `tuple[HTTP2Setting, ...]` | `()` | SETTINGS 列表；ID 不得重复 | 非空拒绝。 |
| `connection_flow` | `int | None` | `None` | uint32；0=默认 | 非 0 拒绝。 |
| `header_priority` | `PriorityParam | None` | `None` | HEADERS priority | 任何非 None 值拒绝。 |
| `priority_frames` | `tuple[PriorityFrame, ...]` | `()` | 额外 PRIORITY frames | 非空拒绝。 |
| `max_header_list_size` | `int` | `0` | uint32；0=默认 | 非 0 拒绝。 |
| `strict_max_concurrent_streams` | `bool` | `False` | 严格服从对端并发流限制 | true 拒绝。 |
| `read_idle_timeout_ms` | `int` | `0` | ms，`0..600000` | 非 0 拒绝。 |
| `ping_timeout_ms` | `int` | `0` | ms，`0..600000` | 非 0 拒绝。 |
| `write_byte_timeout_ms` | `int` | `0` | ms，`0..600000` | 非 0 拒绝。 |

| 嵌套 DTO 字段 | 类型 | 默认/边界 |
|---|---|---|
| `HTTP2Setting.id` | `int` | 必填，`1..6`，同一 settings 中唯一。 |
| `HTTP2Setting.value` | `int` | 必填，uint32：`0..4294967295`。 |
| `PriorityParam.stream_dependency` | `int` | `0`，`0..2147483647`。 |
| `PriorityParam.exclusive` | `bool` | `False`。 |
| `PriorityParam.weight` | `int` | `0`，`0..255`。 |
| `PriorityFrame.stream_id` | `int` | 必填，`0..2147483647`。 |
| `PriorityFrame.priority` | `PriorityParam` | 必填。 |

### RequestOptions

单次请求放入 HTTPX `extensions={"go_req": ...}`；值可以是 `RequestOptions` 或字段严格匹配的 mapping。未知字段和错误类型在 Python 侧直接拒绝。

| 字段 | 类型 | 默认 | 边界/含义 | HTTP/3 |
|---|---|---:|---|---|
| `header_order` | `tuple[str, ...]` | `()` | 非空时覆盖 HTTP header 名称分组顺序；为空时按 HTTPX prepared headers 的首次出现顺序自动设置 | 非空拒绝。 |
| `pseudo_header_order` | `tuple[str, ...]` | `()` | HTTP/2 pseudo-header 顺序提示 | 非空拒绝。 |
| `force_chunked` | `bool` | `False` | 强制 chunked encoding | true 拒绝。 |
| `close_connection` | `bool` | `False` | 请求后关闭连接 | true 拒绝。 |
| `trace` | `bool` | `False` | 返回 req/QUIC trace | 生效。 |
| `dump` | `bool` | `False` | 返回内存诊断 dump，不接受路径或 writer | 生效，但格式不保证与 TCP dump 逐字节一致。 |
| `retry_count` | `int | None` | `None` | `0..10`，覆盖本次请求最大重试次数 | 生效。 |

## trace、retry 与 dump

```python
from gohttpx import Client, RequestOptions

with Client() as client:
    response = client.get(
        "https://example.test/",
        extensions={
            "go_req": RequestOptions(
                trace=True,
                dump=True,
                retry_count=2,
            )
        },
    )
    trace = response.extensions.get("go_trace")
    dump = response.extensions.get("go_dump")
```

`go_trace` 在启用时包含且仅包含：`dns_lookup_ms`、`connect_ms`、`tls_handshake_ms`、`first_byte_ms`、`response_ms`、`total_ms`、`connection_reused`、`remote_address`。`go_dump` 只在启用 dump 时存在，可能含目标 headers 和 body，调用方必须按敏感诊断数据保护；Go 服务不记录请求日志。

## 控制协议与 header 契约

两个控制 POST（创建会话、发起请求）必须使用 `application/json`；允许合法的参数（例如 `charset=UTF-8`），media type 大小写不敏感。缺失或错误类型返回 415 `UNSUPPORTED_MEDIA_TYPE`，语法畸形返回 400 `INVALID_REQUEST`，均为 JSON error envelope。无正文的 GET/DELETE 不要求 Content-Type。

v1 JSON 在任何层级都禁止 `null`，每个对象拒绝未知 key。创建请求的必需 key 是 `protocol_version`，其余预定义 `ClientOptions` key 可省略；目标请求的必需 key 是 `protocol_version`、`method`、`url`，预定义的 `headers`、`body_base64`、`timeout_ms`、`options` 可省略并采用空/零值。成功目标响应的必需 key 是 `protocol_version`、`request_id`、`status_code`、`reason_phrase`、`headers`、`body_base64`、`url`、`http_version`、`elapsed_ms`，可选 key 仅为 `trace`、`dump`，未启用时省略。错误对象必需 `code`、`message`、`retryable`，可选 `request_id` 只在已生成请求 ID 时出现；健康、能力和创建响应均使用各自文档列出的 exact keys。

目标请求进入 req 最终 RoundTrip 前会从每请求 context 深拷贝恢复 HTTPX prepared headers，不会在线上补出调用方没有的业务 `User-Agent` 或 `Content-Type`。HTTP/1 对普通 header 保留首次出现的 key casing、同名重复值顺序和名称分组顺序；非空 `go_req.header_order` 覆盖自动顺序。`Host`、`User-Agent`、`Content-Length`、`Transfer-Encoding` 等由 req/Go 按协议特殊处理，不能视为任意原始 TCP 重放；HTTP/2 和 HTTP/3 的字段名按协议转为小写。响应侧 `net/http` 只能可靠保留值与重复值，不承诺原始 casing 或全局线序；当前 response envelope 按 canonical header 名排序。

## 错误映射与会话重建

| 场景/Go code | Python 异常 | retryable 字段 |
|---|---|---|
| 托管服务未就绪或明确未发送；外部模式控制连接不可用 | `GoServiceUnavailable` | 不适用 |
| 托管模式已提交后结果不确定 | `GoRequestOutcomeUnknown` | 不适用 |
| 托管二进制、版本、Job 配置错误 | `RuntimeConfigurationError` | 不适用 |
| `UPSTREAM_TIMEOUT` | `httpx.TimeoutException` | `true` |
| `UPSTREAM_DNS_ERROR` | `httpx.ConnectError` | `true` |
| `UPSTREAM_CONNECT_ERROR` | `httpx.ConnectError` | `true` |
| `UPSTREAM_TLS_ERROR` | `httpx.ConnectError` | `false` |
| `UPSTREAM_PROTOCOL_ERROR` | `httpx.RemoteProtocolError` | `false` |
| `INVALID_REQUEST` | `GoProtocolError` | `false` |
| `UNSUPPORTED_MEDIA_TYPE` | `GoProtocolError` | `false` |
| `UNAUTHORIZED` | `GoProtocolError` | `false` |
| `PROTOCOL_MISMATCH` | `GoProtocolError` | `false` |
| `UNSUPPORTED_FEATURE` | `GoProtocolError` | `false` |
| `CLIENT_NOT_FOUND` 第二次仍失败 | `GoProtocolError` | `false` |
| `INTERNAL_ERROR` 或未知 code | `GoProtocolError` | 由 envelope 提供 |
| 目标站点 HTTP 4xx/5xx | 正常 `httpx.Response` | 不适用 |

异常会保留原目标 `httpx.Request`；服务错误还暴露 `code` 和可用时的 `request_id`。

`CLIENT_NOT_FOUND` 允许一次会话重建。托管模式还允许严格确认尚未发送后的安全尝试，两种情况共享最多一次额外尝试预算。已提交后的控制连接中断、超时或响应不完整不重发。外部模式保留原有错误映射与会话重建行为。

## 限制与安全边界

- 请求和响应均完整缓冲在内存中；默认每方向 48 MiB，可用 `--max-body-mib` 调整。
- v1 不支持 streaming upload/download、WebSocket、SSE 或 parallel download。
- 控制配置 JSON 上限 4 MiB；目标 URL 最长 16384 bytes，method 最长 64 bytes。
- 每个目标请求最多 256 个 headers；单个名字最多 256 bytes，单个值最多 16384 bytes，总计最多 1 MiB。header 使用 Latin-1 无损映射。
- 任意 callback、middleware、hook、response transformer、自定义 dial/TLS handshake/proxy 函数、自定义 marshal、`io.Reader`/`io.Writer`、进度回调都不能跨进程。桥接内部为 uTLS+mTLS 使用的固定 handshake 不对调用方开放。
- Go 不持久化业务 cookies/headers/auth，不跟随 redirect，不使用 CookieJar，不自动字符集转换。
- `Host`、`User-Agent`、`Content-Length`、`Transfer-Encoding`、连接复用和 HTTP/2 帧仍受 req 与 Go Transport 控制；普通请求 header 的契约以上述“控制协议与 header 契约”为准，不扩展为任意原始 TCP 报文重放。
- 鉴权仅面向本机 loopback bearer；控制 token 不进入目标请求。
- Go 不输出请求日志；托管 stdout 仅用于私有启动消息。控制错误返回 JSON envelope；运行时仅向命名 logger 提供无敏感材料的生命周期事件。

## 运维与升级

默认托管模式按前文随所属 Python 自动管理；外部模式由部署方管理。升级时安装匹配版本的完整 wheel，或同时更新 SDK 和外部 EXE。Go session 在 client 关闭时删除；遗留空闲 session 默认 24 小时回收，活动请求不会被空闲清理。

2.0 的生命周期变化没有给业务 v1 JSON 增加字段。后续修改 required/optional key、字段类型或语义，仍须同时修改双方并通过兼容性测试。

## 测试与离线 E2E

每次代码修改完成后，在仓库根目录依次执行：

```powershell
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
python -m build
python -B -m unittest discover -s python -p "test_*.py" -v
```

Go 正式用例保留在被测包的 `*_test.go`；Python 正式用例统一为 `python/test_*.py`。`docs/testing/` 保存验证报告，`.tmp/` 中的临时诊断不属于正式回归。安装测试前重新构建 wheel，避免测到旧包。

既有测试预期默认不变，禁止为消除失败而删除用例、跳过或放宽断言。只有需求明确改变对应行为，或有证据证明用例有误，才调整预期并说明原因；具体规则见 [项目测试约定](PROJECT_CONTEXT.md#14-测试体系)。

Go 测试使用 `testing/httptest`，Python 使用 `unittest`。Python E2E 会在系统临时目录构建单个临时 EXE，启动本机 Go 服务和本机目标 HTTP 服务，覆盖正文编码、cookies、redirect、Basic/Digest auth、重复 query/header、错误状态、timeout、会话隔离与重建；测试不访问公网，结束后删除该临时 EXE。

运行 Python 全套测试还需要 `cryptography` 和 `build`：`python -m pip install "httpx>=0.28,<0.29" "cryptography" "build"`。

托管故障测试在真实 Windows 子进程上执行，覆盖正常/强制退出、启动窗口、崩溃、并发、A/B Cookie、异步取消、退避、旧实例拒绝和资源回收；安装测试在独立虚拟环境运行，并从 PATH 移除 Go。网络行为测试只访问本地目标；构建依赖和 pip 安装可能使用软件源。测试详情见 [验证记录](docs/testing/2026-08-27-managed-runtime.md)。
