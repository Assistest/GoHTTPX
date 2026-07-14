# GoHTTPX Bridge v1

GoHTTPX 在本机常驻一个 Go 发包服务，让 Python 继续使用 HTTPX 0.28 的 `Client`、`AsyncClient`、请求编码、cookies、auth、redirect 和 `Response` 语义，同时把目标请求交给 req/v3、uTLS 或 HTTP/3 Transport 执行。

当前发布版本为 `1.0.0`，控制协议为 `/api/v1`、`protocol_version=1`。依赖固定为 req/v3 `v3.59.0`、quic-go `v0.60.0`、uTLS `v1.8.2`；Python 最低版本为 3.10，要求 `httpx>=0.28,<0.29`。

## 架构与状态边界

一个由运维人员手动启动的 loopback Go 服务，可以由同一 Python 后端中的多个站点模块共享。同步 `Client` 在构造时立即创建 Go `req.Client` 会话；异步 `AsyncClient` 在第一次请求时懒创建。每个已经创建会话的 client 都对应一个独立 Go session，因此 TLS、代理、HTTP 版本、连接池和重试配置互不串用。

HTTPX 负责 params、headers、cookies、Basic/Digest auth、redirect、`json/data/files/content` 编码以及最终 `Response`；Go 会话只保存底层网络配置。业务 cookies、headers 和 auth 不会在 Go 中持久化，控制 API 的 bearer token 也不会转发给目标站点。Python 不会启动或停止 Go 服务。

```text
站点模块 -> httpx.Client / httpx.AsyncClient
         -> GoTransport -> 127.0.0.1 /api/v1
         -> 独立 req.Client 会话 -> 目标站点
```

## Windows 构建与启动

在本目录执行：

```powershell
go build -trimpath -ldflags="-s -w" -o gohttpx-server.exe .
.\gohttpx-server.exe --host 127.0.0.1 --port 9876 --token <secret>
```

也可以把 token 放入当前进程环境。显式 `--token` 的优先级高于 `GOHTTPX_TOKEN`：

```powershell
$env:GOHTTPX_TOKEN = "replace-with-a-long-random-secret"
.\gohttpx-server.exe --host 127.0.0.1 --port 9876
```

正式模式 token 不能为空。只有明确传入 `--insecure-no-auth` 才会关闭鉴权，该模式仅用于本机开发。默认禁止监听非 loopback 地址；`--allow-non-loopback` 是显式危险开关，本机 bearer 设计不应被当作公网认证方案。

常用 CLI：

| 参数 | 默认值 | 含义与边界 |
|---|---:|---|
| `--host` | `127.0.0.1` | 监听地址；非 `localhost`/loopback 必须同时传 `--allow-non-loopback`。 |
| `--port` | `9876` | `1..65535`。 |
| `--token` | `GOHTTPX_TOKEN` | bearer token；显式参数覆盖环境变量。 |
| `--insecure-no-auth` | `false` | 清空 token 并关闭鉴权，仅限开发。 |
| `--allow-non-loopback` | `false` | 允许非 loopback 监听。 |
| `--max-body-mib` | `48` | 单次目标请求正文和响应正文的内存上限，正整数 MiB。 |
| `--idle-ttl` | `24h` | 无活动 Go 会话的回收时间，必须大于 0。 |
| `--version` | `false` | 不需要 token、不会监听端口，打印 server、protocol、req/v3、uTLS 实际构建版本后退出 0。 |

版本、健康和能力检查：

```powershell
.\gohttpx-server.exe --version
Invoke-RestMethod http://127.0.0.1:9876/api/v1/health
Invoke-RestMethod http://127.0.0.1:9876/api/v1/capabilities -Headers @{Authorization="Bearer $env:GOHTTPX_TOKEN"}
```

`health` 无需鉴权，固定返回 `status`、`protocol_version`、`server_version`。正常模式下 `capabilities` 需要 bearer；只有显式使用 `--insecure-no-auth` 的本机调试模式才免鉴权。v1 capabilities 精确返回四个字段：`protocol_version`、`server_version`、`max_body_bytes`、`tls_fingerprints`。

## Python 单文件接入

把 `python/gohttpx.py` 复制到项目的可导入目录；它不是已发布的 pip 包。项目需自行安装兼容的 HTTPX 0.28.x。同步客户端在构造时检查 capabilities 并创建 Go 会话；异步客户端在第一次请求时懒创建会话。

### 同步示例

```python
import httpx

from gohttpx import Client, RequestOptions

with Client(
    go_endpoint="http://127.0.0.1:9876",
    go_token="replace-with-secret",
    headers={"User-Agent": "my-backend/1.0"},
    cookies={"site": "one"},
    follow_redirects=True,
) as client:
    query = client.get("https://example.test/search", params=[("q", "a"), ("q", "b")])
    created = client.post("https://example.test/items", json={"name": "test"})
    form = client.post("https://example.test/form", data={"name": "test"})
    upload = client.post("https://example.test/upload", files={"file": ("a.bin", b"abc")})
    raw = client.post("https://example.test/raw", content=b"\x00\xff")
    traced = client.get(
        "https://example.test/trace",
        extensions={"go_req": RequestOptions(trace=True, dump=True, retry_count=1)},
    )

    created.raise_for_status()
    print(query.url, form.status_code, upload.headers, raw.content)
    print(traced.extensions.get("go_trace"))
    print(traced.extensions.get("go_dump"))
```

`json`、`data`、`files`、`content` 都是 HTTPX 原生参数；HTTPX 先编码最终 bytes，Go 原样发送。默认 headers、cookies、重复 query、redirect history 也由 HTTPX 处理。

Basic 与 Digest auth 使用 HTTPX 的真实 auth 对象：

```python
import httpx

from gohttpx import Client

with Client(go_token="secret", auth=("user", "pass")) as client:
    basic = client.get("https://example.test/basic")

with Client(go_token="secret", auth=httpx.DigestAuth("user", "pass")) as client:
    digest = client.get("https://example.test/digest")
```

### 异步示例

```python
import asyncio

from gohttpx import AsyncClient


async def main() -> None:
    async with AsyncClient(
        go_endpoint="http://127.0.0.1:9876",
        go_token="replace-with-secret",
        headers={"X-Site": "demo"},
        cookies={"session": "one"},
        follow_redirects=True,
    ) as client:
        response = await client.post(
            "https://example.test/items",
            params=[("source", "a"), ("source", "b")],
            json={"name": "async"},
        )
        response.raise_for_status()
        print(response.json(), response.history)


asyncio.run(main())
```

`Client` 和 `AsyncClient` 的会话配置入口是 `client_options=ClientOptions(...)`；`tls_fingerprint`、`impersonate`、`verify`、`cert`、`proxy`、`http1`、`http2` 是当前签名支持的固定会话便利参数。单次 `RequestOptions` 不属于构造参数，只能放在 `extensions={"go_req": ...}`。公开签名还接受 HTTPX 的 `auth`、`params`、`headers`、`cookies`、`timeout`、`follow_redirects`、`max_redirects`、`event_hooks`、`base_url`、`default_encoding`；`transport` 与 `mounts` 明确禁止，避免绕过 Go Transport。

当前签名正式不提供 `limits` 或 `trust_env` 便利参数。HTTPX 的全局/按 URL 环境代理规则无法无损映射到一个配置固定的 Go session，控制连接也固定不读取代理环境变量；连接池和固定代理分别使用 `ClientOptions.transport` 与 `ClientOptions.proxy_url` 显式配置。`proxy=` 便利参数同样只生成一个固定会话代理，不表示支持环境代理或 per-URL mounts。

`go_token=None` 时读取 `GOHTTPX_TOKEN`；显式字符串（包括空字符串）不再读取环境变量。

## TLS、代理、证书和 HTTP 版本

```python
import httpx

from gohttpx import Client, ClientOptions, TLSFingerprint

# TLS 指纹
with Client(go_token="secret", tls_fingerprint=TLSFingerprint.CHROME_120) as client:
    response = client.get("https://example.test/")

# 固定代理；Proxy 的 auth 和 headers 子集会被序列化
proxy = httpx.Proxy("http://proxy.example:8080", auth=("user", "pass"), headers={"X-Proxy": "one"})
with Client(go_token="secret", proxy=proxy) as client:
    response = client.get("https://example.test/")

# 自定义根 CA 与 mTLS
with Client(
    go_token="secret",
    verify=r"C:\certs\root-ca.pem",
    cert=(r"C:\certs\client.pem", r"C:\certs\client-key.pem"),
) as client:
    response = client.get("https://example.test/")

# HTTP/1.1、HTTP/2、HTTP/3、H2C
http1 = Client(go_token="secret", client_options=ClientOptions(http_version="http1"))
http2 = Client(go_token="secret", client_options=ClientOptions(http_version="http2"))
http3 = Client(go_token="secret", client_options=ClientOptions(http_version="http3", tls_fingerprint=None))
h2c = Client(go_token="secret", client_options=ClientOptions(http_version="h2c"))
for client in (http1, http2, http3, h2c):
    client.close()
```

`verify` 只支持 `bool` 或 CA PEM 文件路径，不接受自定义 `ssl.SSLContext`。`cert` 支持一个同时含证书和私钥的 PEM 文件，或 `(证书路径, 私钥路径)`。`httpx.Proxy` 若含自定义 SSLContext 会被拒绝。`proxy_url` 支持 `http`、`https`、`socks5`、`socks5h`。

组合限制：

- `impersonate` 与任何显式 `tls_fingerprint` 互斥；impersonate 可选 `none/chrome/firefox/safari`。
- proxy 不能与强制 `http2`、`http3`、`h2c` 组合；proxy 与 `auto/http1` 可用。
- HTTP/3 不接受显式 TLS fingerprint 或非 `none` impersonate，使用标准 QUIC TLS。
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

`ClientOptions.tls_fingerprint` 的 Python 默认是 `None`；当 HTTP 版本不是 HTTP/3 且 impersonate 为 `none` 时，SDK 的有效默认是 `android_11_okhttp`。

## 完整 DTO 字段矩阵

所有时间字段单位均为毫秒。配置 JSON 总大小上限为 4 MiB。表中的“0=默认”表示不调用对应 req 设置；HTTP/3 的例外单独列出。

### ClientOptions

| 字段 | Python 类型 | 默认 | 含义、边界与 HTTP/3 规则 |
|---|---|---:|---|
| `tls_fingerprint` | `TLSFingerprint | str | None` | `None` | 非 HTTP/3 且无 impersonate 时有效默认 `android_11_okhttp`；值必须属于 49 项目录。HTTP/3 只能省略。 |
| `impersonate` | `Impersonate | str` | `none` | `none/chrome/firefox/safari`；非 `none` 与显式 fingerprint 互斥，HTTP/3 拒绝。 |
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

with Client(go_token="secret") as client:
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
| 本地 Go 服务无法连接、控制连接超时/断开 | `GoServiceUnavailable` | 不适用 |
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

只有收到完整、合法的 `CLIENT_NOT_FOUND` JSON 时，Transport 才使用原 ClientOptions 重建一次 Go 会话，并把完全相同的控制 envelope 重发一次。第二次 `CLIENT_NOT_FOUND` 直接抛错。控制连接中断、超时或响应不完整时绝不自动重发，因此不会在执行结果未知时偷偷重复 POST。

## 限制与安全边界

- 请求和响应均完整缓冲在内存中；默认每方向 48 MiB，可用 `--max-body-mib` 调整。
- v1 不支持 streaming upload/download、WebSocket、SSE 或 parallel download。
- 控制配置 JSON 上限 4 MiB；目标 URL 最长 16384 bytes，method 最长 64 bytes。
- 每个目标请求最多 256 个 headers；单个名字最多 256 bytes，单个值最多 16384 bytes，总计最多 1 MiB。header 使用 Latin-1 无损映射。
- 任意 callback、middleware、hook、response transformer、自定义 dial/TLS handshake/proxy 函数、自定义 marshal、`io.Reader`/`io.Writer`、进度回调都不能跨进程。桥接内部为 uTLS+mTLS 使用的固定 handshake 不对调用方开放。
- Go 不持久化业务 cookies/headers/auth，不跟随 redirect，不使用 CookieJar，不自动字符集转换。
- `Host`、`User-Agent`、`Content-Length`、`Transfer-Encoding`、连接复用和 HTTP/2 帧仍受 req 与 Go Transport 控制；普通请求 header 的契约以上述“控制协议与 header 契约”为准，不扩展为任意原始 TCP 报文重放。
- 鉴权仅面向本机 loopback bearer；控制 token 不进入目标请求。
- Go 服务不输出启动日志或请求日志。控制面错误直接返回 JSON error envelope，Python 映射为带原始 request 的 HTTPX/`GoProtocolError` 异常，页面层可直接捕获并展示。

## 运维与升级

Go 服务应由进程管理器或运维脚本手动常驻启动；Python 进程只连接它。按 Ctrl+C 会触发最多 10 秒的 graceful shutdown，并关闭已登记会话的空闲连接。孤儿会话默认空闲 24 小时后回收；正在执行的会话不会被空闲清理。

两个同步 Client 构造完成后立即对应两个独立 Go session；两个异步 AsyncClient 则在各自第一次请求后才分别拥有独立 session。关闭一个已创建会话的 client 会幂等删除它自己的 session，不影响另一个 client。服务重启导致 session 丢失时，下一次请求按上述 `CLIENT_NOT_FOUND` 规则重建。

v1 发布后，`/api/v1` 的 required/optional key 集合、字段名、类型、默认值和语义保持稳定；optional key 可按约定省略，其他未知 key 一律拒绝。任何协议扩展必须使用新的 `protocol_version` 与 endpoint，或同步升级 Go 服务和 Python SDK 后再发布，不能让单边先接受新字段。Python 包版本与 protocol 版本独立，当前 server/Python 版本均为 `1.0.0`。

## 测试与离线 E2E

在 `gohttpx` 目录执行：

```powershell
go vet ./...
go test ./...
go test -race ./...
python -B -m unittest discover -s python -p "test_*.py" -v
python -c "from pathlib import Path; [compile(p.read_text(encoding='utf-8'), str(p), 'exec') for p in Path('python').glob('*.py')]"
```

Go 测试使用 `testing/httptest`，Python 使用 `unittest`。Python E2E 会在系统临时目录构建单个临时 EXE，启动本机 Go 服务和本机目标 HTTP 服务，覆盖正文编码、cookies、redirect、Basic/Digest auth、重复 query/header、错误状态、timeout、会话隔离与重建；测试不访问公网，结束后删除该临时 EXE。
