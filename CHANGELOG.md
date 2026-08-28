# 更新记录

## 2.1.0（2026-08-28）

- Python `Client`、`AsyncClient`、`ClientOptions` 新增 `tls_spec`，接受 JSON 对象/字符串；Go 严格校验并使用自定义 uTLS ClientHello，不回退内置指纹。
- 沿用 uTLS JSON 字段，支持顺序控制、签名算法、曲线/KeyShare、ALPN/ALPS、GREASE 和常用扩展；不支持的字段明确报错。
- 每连接独立 spec 和动态密钥，保留 mTLS、代理和自动 HTTP/2；Python 保存配置快照，session 重建/Go 崩溃后恢复不变。
- 增加独立网络字节解析的 TLS 抓包用例、Edge 模板 TLS 1.2/1.3 验证、并发/Cookie 隔离和安装包实际握手验证。
- GitHub 首页内联全部 TLS 顶层字段与扩展参数示例，显式配置 User-Agent，并说明 ALPS 互斥替换；测试直接执行 README，独立演示 JSON 不纳入提交或构建包。
- SDK/EXE 同步为 2.1.0，控制协议仍为 v1；版本必须一致。现有版本断言仅随版本号更新，原有行为断言不放宽。
- GitHub 首页增加使用免责声明：仅授权接口测试，禁止违法用途。

## 2.0.0

- 默认 `Client()` / `AsyncClient()` 自动托管 Go；每个 Python 进程一份 Go，多 client 独立 session/Cookie。
- Windows 创建时原子绑定 Job，动态 loopback 端口，私有启动握手；Python 结束时回收所属 Go。
- 单协调器恢复、独立健康检查、退避/冷却；旧实例结果不会更新新实例。
- 增加 `GoRequestOutcomeUnknown`，已提交后结果不确定不自动重放；安全重试与 session 重建共用一次额外尝试预算。
- 新增 configure_runtime/start/astart/shutdown/ashutdown/runtime_status；client.close 不结束共享 Go。
- Windows amd64 wheel 内置同版本 EXE，运行时无需 Go 工具链或下载；保留显式 go_endpoint 外部模式。
- 破坏性变化：仅传 go_token 不再隐式连接 9876；需要外部服务时必须显式传 endpoint。单文件复制接入不再完整。
- 真实生命周期故障测试、完整 Go/Python 回归与独立安装测试见验证记录。
- GitHub Actions 自动构建、测试并发布到 PyPI/GitHub；发布前核验独立与内置 EXE 的源码提交、平台和版本，附带 SHA-256 清单。

历史 1.x 的 Python SDK 与 Go 服务端分开发布，保留如下记录。

## 1.0.2

- 发布版本同步更新。

## 1.0.1

- 发布版本同步更新。

## 1.0.0

- 首次公开发布：本机 loopback GoHTTPX bridge。
- 支持 HTTPX 同步/异步调用、req/v3、uTLS 指纹、HTTP/1/2/3/H2C、mTLS 与代理配置。
- 控制服务不再以固定写超时中断协议允许的长目标请求；目标超时仍由 v1 `timeout_ms` 和 Python 控制连接超时共同约束。
