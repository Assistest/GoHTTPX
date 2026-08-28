# 更新记录

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
