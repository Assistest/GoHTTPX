# 自定义 TLS JSON 验证记录

日期：2026-08-28。范围：GoHTTPX 2.1.0 本地源码与 Windows amd64 wheel；尚未提交或发布此版本。

本文保留首次功能验证时的文件名和构建哈希。随后演示已内联到 README，最新回归与产物见 [README 示例验证](2026-08-28-readme-tls-demo.md)。

环境：Windows amd64，Go 1.26.2，Python 3.10.11，req v3.59.0，uTLS v1.8.2。

## 最终回归

以下结果来自修复 ClientOptions 位置参数兼容性和 GREASE 别名处理之后的同一轮完整回归，按顺序执行。不是沿用修改前的通过记录。

| 命令 | 实际结果 |
|---|---|
| `go test ./... -count=1` | 通过，包测试耗时 5.669 秒 |
| `go test -race ./... -count=1` | 通过，包测试耗时 4.762 秒，无 race 报告 |
| `go vet ./...` | 通过，退出码 0 |
| `python -m build` | 从当前源码生成 sdist，并由 sdist 构建 Windows amd64 wheel |
| `python -B -m unittest discover -s python -p "test_*.py" -v` | 128 项通过，123.013 秒，未跳过 |
| `git diff --check` | 通过；仅有仓库既有 LF/CRLF 转换提示 |

`go test -list . ./...` 发现 65 个顶层 Go 测试；不将子用例重复计数。相对于原有 61 个 Go、115 个 Python 测试，增加 4 个 Go、13 个 Python 测试，另扩展既有安装测试。版本断言随 2.1.0 更新；原有行为断言未删除、放宽或跳过。

## 如何证明实际配置生效

调用链是公开 Python `Client` / `AsyncClient` → 真实 Go 服务 → 本机 TCP/TLS 目标。

`python/tls_test_support.py` 先读取 TLS record 中的实际 ClientHello 字节，使用独立 Python 二进制解析器分析，再通过 `ssl.MemoryBIO` 完成真实 TLS 握手和 HTTP 请求。测试中的观察结果来自目标收到的字节，不来自 Go 的配置对象；不是仅检查 JSON、HTTP 200 或 JA3 哈希。

### custom_tls13.json

以下固定字段均与目标实际接收值一致。表中 GREASE 按占位符归一化，不要求不同连接使用同一个随机 GREASE 编号。

| 字段 | 断言值 |
|---|---|
| legacy_version / compression | `0x0303` / `[0]` |
| cipher_suites 顺序 | GREASE、`0x1302`、`0x1303`、`0x1301` |
| 扩展顺序 | GREASE、0、13、43、10、51、16、27、GREASE |
| SNI | `localhost`，同时验证完整扩展编码 |
| signature_algorithms | `0x0805`、`0x0403`、`0x0804`，扩展内容 `0006080504030804` |
| supported_versions | GREASE、TLS 1.3 |
| supported_groups | GREASE、secp256r1、x25519 |
| key_share | GREASE 占位数据 `[0]`、32 字节 x25519 公钥 |
| ALPN | `http/1.1`，扩展内容 `000908687474702f312e31` |
| compress_certificate | brotli，扩展内容 `020002` |

同一 Client 的 3 次新连接分别产生不同 random、session ID 和 x25519 公钥。另请求实际 `golang` 预设作为对照，确认套件数组不同。GREASE 的十六进制别名分别写入套件、组及 KeyShare 后，仍通过相同的实际报文断言；不同别名不能绕过重复检查。

### edge_151.json

这是参考项目 Edge 模板的 JSON 声明，不是运行时读取其他项目，也不意味着自动匹配机器上的浏览器版本。

同一 JSON 分别连接最高支持 TLS 1.2、TLS 1.3 的目标，实际协商结果分别为 TLSv1.2、TLSv1.3。两种情况下均检查：

- 16 个套件的完整顺序。
- 18 个扩展的完整顺序：GREASE、16、51、35、10、5、23、65037、11、43、65281、0、27、18、13、45、17613、GREASE。
- 签名算法扩展完整内容：`001609040905090604030804040105030805050108060601`。
- ALPN 为 h2/http1.1；ALPS 使用新码点 17613，内容为 `0003026832`。
- 组列表中的 X25519MLKEM768、x25519、secp256r1、secp384r1，以及 TLS 1.3/1.2 的版本声明。
- PSK 模式、brotli、EC 点格式、renegotiation_info、status_request 的固定字节；session_ticket、extended_master_secret、SCT 的空内容。
- GREASE ECH 存在且包含生成数据；KeyShare 中混合组编号 `0x11ec`、公钥长度 1216 字节，x25519 公钥长度 32 字节，扩展总长 1263 字节。

## 隔离、恢复和安装验证

| 场景 | 实际断言 |
|---|---|
| 两个 Client 并发 | 两套不同套件/签名算法/扩展顺序，20 个并发请求分别匹配所属配置，Cookie A/B 不串；20 份 x25519 公钥互不相同 |
| Go 并发握手 | 12 个实际并发 TLS 请求；每次新建扩展对象，race detector 无共享状态竞争 |
| 扩展洗牌 | 6 次新握手出现不同顺序，扩展集合和签名参数不变，GREASE 保留边界位置 |
| AsyncClient 会话恢复 | 修改原 dict、删除 Go session 后重新请求；实际报文仍使用创建时的快照，业务 Cookie 保留 |
| Go 进程崩溃 | 强制结束托管 Go 并等待退出；下次请求启动新 PID，start_count 为 2，恢复原 TLS 配置与 Cookie |
| 证书和代理 | 经带认证 CONNECT 代理完成实际 mTLS，并核对 ClientHello；未信任 CA 时明确报 UPSTREAM_TLS_ERROR |
| HTTP/2 | ALPN 声明 h2，保留 auto，实际返回 HTTP/2，目标收到自定义套件与 ALPN |
| 安装后的包 | 独立 venv，移除 Go 编译器 PATH，确认 import 来自安装目录；内置 EXE 发出的套件、扩展顺序、签名参数与自定义值一致 |
| 子进程回收 | 安装测试以进程句柄确认 Python 退出后 Go 结束；既有父进程异常退出、启动窗口、两进程隔离等故障注入测试全部继续通过 |

同步会话重建另有 fake-control 用例核对完整创建 payload 不变。原有“不确定已发送请求不自动重放”、多 Python 进程隔离和恢复限流测试均保持原断言并通过。

## 严格校验与边界修复

Go 拒绝缺失/未知/大小写错误的字段、null、重复 JSON key、重复标识符、未知扩展、静态真实 KeyShare、组不匹配、错误类型、大小超限、版本冲突和协议冲突。Python 在建立控制连接前拒绝非 JSON 对象、重复 key、非法 JSON 类型和预设冲突；扩展语义由 Go 做最终校验。

自查发现的两个问题均先补测试复现失败，再修复并重新完成全量回归：

1. 新增 dataclass 字段若放在第二位会改变旧版位置参数含义；现在 `tls_spec` 位于 `ClientOptions` 最后，旧位置参数保持兼容。
2. 不同十六进制 GREASE 别名可能绕过重复检查；现在先统一为占位符，再校验重复，KeyShare 同样适用。

## 固定测试位置

- Go：根目录 `api_test.go`，新增名称以 `TestCustomTLS` 开头的 4 个测试。
- Python SDK：`python/test_gohttpx.py`。
- 实际握手：`python/test_gohttpx_e2e_transport.py`，辅助目标为 `python/tls_test_support.py`。
- 安装：`python/test_package_install.py`、`python/installed_test_worker.py`。
- 配置样例：`examples/tls/custom_tls13.json`、`examples/tls/edge_151.json`。

修改模板后必须调整对应的实际报文断言，并执行仓库完整回归；不能只更新 JSON 文件或对照哈希。规则已写入 `AGENTS.md` 和 `PROJECT_CONTEXT.md`。

## 本地构建产物及限制

- wheel：`dist/gohttpx-2.1.0-py3-none-win_amd64.whl`，5,158,202 字节。
- wheel SHA-256：`cd8f641dab5f9e45ee52d9c482c01249aface11f5224d11a9c4e79cf80531a88`。
- 已检查 wheel 平台标签、版本 metadata 及内置 `_gohttpx_bin/gohttpx-server.exe`；未上传 GitHub/PyPI。
- 本次网络行为测试仅访问 loopback，依赖安装访问软件源；没有把百度或任意网站访问结果当作指纹一致性证据。
- 仅验证 Windows amd64 托管。自定义 TLS 支持 TCP TLS 1.2/1.3 与 auto/兼容的 http1；强制 http2/http3/h2c 明确拒绝。
- 不开放 TLS 1.3 PSK/会话恢复注入、静态密钥和任意扩展原始字节。不支持的配置报错，不退回默认指纹。
- 配置能声明算法编号，不等于 uTLS 实现该算法；例如 Edge 模板的 `0x0904/0x0905/0x0906` 已验证发送，但未验证与仅支持这些算法的服务端握手。
- 验证证明的是配置实际影响 ClientHello；HTTP/2 参数、HTTP headers 和浏览器行为仍是独立维度，不承诺完整浏览器一致性或目标网站风控结果。
