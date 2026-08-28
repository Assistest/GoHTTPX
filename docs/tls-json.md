# TLS JSON 配置与实际报文验证

适用于源码版本 2.1.1。Python SDK 与 Go EXE 必须同版本；旧版不具备此入口。`tls_spec` JSON 自 2.1.0 起可用，ClientHello hex 导入自 2.1.1 起可用。

自定义 TLS 只用于你有权测试的接口请求。禁止用于未授权访问、绕过安全控制或任何违法用途，完整条款见 [README 免责声明](../README.md#免责声明)。

## 使用方式

完整可运行的 Python＋内联 JSON 示例放在 [README 首页](../README.md#custom-tls-json)，包含全部 6 个顶层字段和各扩展参数。复制整段即可使用，不需要下载独立 JSON 文件，也不要求在仓库目录运行。

下面是异步调用写法，接在首页示例的 `TLS_SPEC`、`HEADERS` 定义后使用：

```python
import asyncio
from gohttpx import AsyncClient, ClientOptions

async def main():
    async with AsyncClient(client_options=ClientOptions(tls_spec=TLS_SPEC), headers=HEADERS) as client:
        response = await client.get("https://tls.peet.ws/api/all")
        print(response.status_code)

asyncio.run(main())
```

以上是用法示例。固定回归将目标替换成本机 TLS 服务，公网接口不是 CI 的通过条件。

每个 Client 在构造时对配置建立不可变快照，后续修改原 dict 不会改变已有 Client；重新配置需要新建 Client。多个 Client 仍共用所属 Python 的一个 Go 服务，但各自的指纹、连接池和 Cookie 隔离。Go/session 重建时使用原来的配置快照。

## 顶层字段

| 字段 | 类型及规则 |
|---|---|
| `cipher_suites` | 必填，1–128 个字符串，使用 uTLS/IANA 名称、`GREASE` 或 `0x1301` 形式；按列表顺序发送，禁止重复编号 |
| `compression_methods` | 必填，只允许 `["NULL"]` |
| `extensions` | 必填，1–64 个扩展对象；默认按列表顺序发送，非 GREASE 扩展不能重复，GREASE 最多两个 |
| `min_vers` / `max_vers` | 可省略或设 0；非零时须与 `supported_versions` 推导的最小/最大版本一致，771=TLS 1.2，772=TLS 1.3 |
| `shuffle_extensions` | 可省略，默认 false；true 使用 uTLS 的扩展洗牌逻辑，保留 GREASE 等受保护位置 |

仅支持 TLS 1.2/1.3。`supported_versions`、`signature_algorithms` 扩展必须存在；TLS 1.3 要求有效的 TLS 1.3 套件及真实 KeyShare。配置最多 64 KiB、8 层嵌套。重复 JSON key、未知字段、null、错误类型和不兼容配置明确拒绝。Python 接受对象或 JSON 字符串，控制协议传递 JSON 对象，不是二次编码的字符串。

字段名沿用 uTLS JSON 格式，不能使用此前设计草案里的 `type`、`alpn`、`groups` 等简写。加密套件/组/签名算法的十六进制编号必须写成字符串，例如 `"0x0904"`，不能在 JSON 中写裸 `0x0904`。

## 从 ClientHello hex 导入

`gohttpx.tls_spec_from_client_hello()` 以及 `Client(tls_spec=...)` 可直接吃：

- Wireshark 包字节文本（带偏移列，如 `0000   16 03 01 ...`）
- 连续十六进制字符串
- TLS record 或 handshake 原始字节
- 上述内容的文件路径

转换结果是当前接口能表达的配置，不是原包逐字节重放。random、session ID、KeyShare 公钥、GREASE 具体编号和 SNI 主机名都会丢弃，由新连接生成。`encrypted_client_hello` 只声明 GREASE ECH，不能还原抓包中的 AEAD/payload。未知扩展会报错，不会填成 GenericExtension。

## 支持的扩展

每个对象都有必填的 `name`；下表“无”表示不接受其他字段。

| `name` | 额外字段 |
|---|---|
| `GREASE` | 无；ID 和占位内容按连接生成 |
| `server_name` | 无；取目标 URL 的主机，IP 目标按 uTLS 行为不发送 SNI |
| `status_request` | 无 |
| `signed_certificate_timestamp` | 无 |
| `extended_master_secret` | 无 |
| `session_ticket` | 无；只声明扩展，不允许导入票据 |
| `renegotiation_info` | 无；使用 uTLS 的初始握手声明 |
| `encrypted_client_hello` | 无；生成 BoringSSL 风格 GREASE ECH，不是实际的 ECH 加密配置 |
| `supported_groups` | `named_group_list`：组名数组，如 `GREASE`、`x25519`、`secp256r1`、`secp384r1`、`X25519MLKEM768` 或十六进制编号 |
| `ec_point_formats` | `ec_point_format_list`：只允许 `["uncompressed"]` |
| `signature_algorithms` | `supported_signature_algorithms`：算法名、`GREASE` 或十六进制编号数组 |
| `supported_versions` | `versions`：`GREASE`、`TLS 1.3`、`TLS 1.2` 的非空数组 |
| `key_share` | `client_shares`：1–4 个 `{ "group": "x25519" }` 等对象；组必须存在于 supported_groups |
| `application_layer_protocol_negotiation` | `protocol_name_list`：`h2` / `http/1.1` 数组 |
| `psk_key_exchange_modes` | `ke_modes`：只允许 `["psk_dhe_ke"]` |
| `compress_certificate` | `algorithms`：`brotli` / `zlib` 数组 |
| `application_settings` | `supported_protocols`：ALPN 中已有的协议；旧码点 17513 |
| `application_settings_new` | `supported_protocols`：ALPN 中已有的协议；新码点 17613，不与旧版同时使用 |

其他扩展目前返回错误，不会转换成无内容的 GenericExtension。参数数组非空、最多 64 项、名称最多 128 字符，重复名称/编号被拒绝。

KeyShare 支持 x25519、secp256r1、secp384r1、secp521r1、X25519MLKEM768。真实组不接受 `key_exchange`，必须由 uTLS 生成新的密钥材料。GREASE 组可省略 `key_exchange`，或使用官方样例的 `[0]`。在接受十六进制编号的位置，`0x1a1a` 等 GREASE 编号与 `GREASE` 一样按占位符处理，不能用不同编号绕过重复检查。不接受抓包中的静态公钥、随机数、session ID、PSK、票据或自定义回调。

声明某个算法编号只表示 ClientHello 会包含该编号，不代表 Go/uTLS 实现了对应算法。比如 Edge 模板中的 `0x0904/0x0905/0x0906` 已验证出现在 signature_algorithms 中，但不能据此承诺与只接受这些签名算法的服务器完成握手。

## 协议与状态边界

- `tls_spec` 与显式 `tls_fingerprint`、非 none 的 `impersonate` 互斥。
- 保留 `http_version="auto"`，由 JSON 的 ALPN 参与协商。强制 http1 时 ALPN 只能包含 http/1.1；强制 http2、http3、h2c 明确拒绝。
- HTTP/2 SETTINGS、窗口、优先级、伪头顺序、User-Agent 和 Cookie 不属于 ClientHello，仍使用现有独立选项。
- verify、CA、mTLS 和代理不因自定义指纹而被跳过。握手失败返回错误，不回退普通 Go TLS 或内置浏览器预设。
- 连接复用时不会再次发送 ClientHello；只有新 TLS 连接才重新生成随机数、GREASE、session ID 和密钥。
- 2.1 不开放 TLS 1.3 PSK/会话恢复配置。Go 崩溃后会重建 TLS 连接，恢复的是 JSON 配置和 Python 业务 Cookie，不是旧 TLS 连接或密钥。

## 每次配置变更如何验收

正式用例在 `api_test.go`、`python/test_gohttpx.py`、`python/test_gohttpx_e2e_transport.py`、`python/test_package_install.py`。Edge 配置直接从 README 演示提取，复制运行测试仅替换目标 URL、控制端点和测试 CA；最小差异夹具在 `testdata/tls/custom_tls13.json`。抓包辅助工具 `python/tls_test_support.py` 在本机 TLS 服务端读取 TCP 握手字节，再交给 Python SSL 完成真实握手和 HTTP 请求；解析器不使用 Go/uTLS 的配置解析逻辑。

```powershell
go test -race -run TestCustomTLS -count=1
python -B -m unittest discover -s python -p "test_gohttpx_e2e_transport.py" -v
```

新增或修改模板时必须扩展实际报文断言，核对固定字段和扩展顺序；动态随机数和密钥只校验结构、长度及新连接间的更新，不把它们固定为某次抓包值。禁止只检查 JSON 到达 Go、HTTP 返回 200、某个 JA3/JA4 相同，就声称全部配置正确。

当前模板覆盖：

- 自定义顺序、签名算法、版本、曲线、KeyShare、SNI、ALPN、证书压缩。
- Edge 模板在 TLS 1.2/1.3 下的全部扩展 ID 与固定参数；混合 KeyShare 的组及长度、ALPS 新码点。
- 同一 Client 新连接的动态密钥、两个 Client 并发指纹/Cookie 隔离、扩展洗牌。
- 同步/异步 session 重建、托管 Go 强制终止后的恢复、mTLS、CONNECT 代理和真实 HTTP/2。
- 从新构建 wheel 安装、移除 Go 编译器 PATH 后，同样观察实际 ClientHello。

这些测试证明“指定配置已经实际发到服务器”，不等于“与任意版本浏览器完全一致”或“必然通过目标网站风控”。

首次功能实现见 [2.1.0 验证记录](testing/2026-08-28-custom-tls.md)，当前首页示例、文件排除和安装包信息见 [README 内联示例验证](testing/2026-08-28-readme-tls-demo.md)。
