# GoHTTPX 运维说明

## 默认托管模式（2.0）

安装 Windows amd64 wheel 后直接使用 `Client()` / `AsyncClient()`。每个 Python worker 有自己的 Go、动态 loopback 端口、Job 和内部凭证；不要预先手动起一个 Go，也不要配置固定端口或共享密钥。

同步应用可在启动钩子调用 `gohttpx.start()`，异步应用调用 `await gohttpx.astart()`。它们是可选预热，不是每次请求的必需步骤。停止接收业务后先关闭各 client，再在退出钩子调用 `shutdown()` / `ashutdown()`。未调用时正常退出仍有 atexit；强杀时有 Windows Job 回收。

**每次请求只关闭 client，不关闭运行时。** 健康 Go 会保留，避免大量短 session 反复启停 EXE。

## 状态与故障

查看 `gohttpx.runtime_status()`：

| 状态 | 含义与处理 |
|---|---|
| STOPPED | 尚未使用，正常 |
| STARTING / RESTARTING | 等待启动、握手、能力检查 |
| RUNNING | 当前实例可用 |
| BACKOFF | 退避/冷却；查看 last_failure 和 retry_in_seconds |
| FAILED | 二进制、版本、Job 或管理器故障；修复后显式关闭、重新配置 |
| STOPPING / CLOSED | 应用正在/已经关闭，不应自动复活 |

状态不包含 token。可把命名 logger `gohttpx.runtime` 接入现有日志和告警；不要为排查问题输出 Cookie、密钥、证书、请求正文或整个运行时对象。

默认启动期限 10 秒，关闭宽限 5 秒。进程死亡检查约每 0.1 秒一次；独立 HTTP 健康检查每 5 秒一次，单次期限 1 秒，连续 3 次失败才替换进程。重启存在退避；滚动 60 秒内达到 5 次失败则冷却 30 秒。这些是配置值，不是服务恢复 SLA。

`GoRequestOutcomeUnknown` 表示请求可能已在目标执行，不要把它加入通用“连接失败后重发”逻辑。应按订单号等业务标识查结果。服务恢复只保证后续请求有机会继续，不保证中断业务成功。

已接收 Cookie 保留在原 Python client；未接收的 Set-Cookie、Go 连接池和 Python 退出后的内存状态不能恢复。网站若绑定 IP/连接，业务可能需要重新登录。

## 平台和部署边界

- 默认托管支持 Windows 10+/Server 2016+，本次实际测试系统版本见验证记录。Linux/macOS 默认明确拒绝，不伪装成有相同回收保障。
- Windows Job 绑定失败即停止启动，不回退为普通 Popen。受限宿主的嵌套 Job 策略需部署方确认。
- Python 卡死但进程不退出不会触发 Job 回收；应用 watchdog 由部署系统负责。
- 多个 worker 分别拥有一个 Go，资源用量随 worker 数量增加。
- 安装包不在业务运行时联网下载或编译。源码构建需要 Go 工具链；部署应使用预构建 wheel。
- 部署使用 `python -m pip install --upgrade --only-binary=gohttpx "gohttpx==2.1.1"`；也可安装 GitHub Release 中的同版本 Windows wheel。

开发可在第一次使用前指定 `configure_runtime(binary_path=绝对路径)`，该 EXE 必须与 SDK 同版本。修改配置前先关闭旧 client 和运行时。

## 显式外部服务模式

只有显式 `go_endpoint` 才进入外部模式；Python 不拥有外部进程的退出与重启权限。

```powershell
go build -trimpath -ldflags="-s -w" -o gohttpx-server.exe .
$env:GOHTTPX_TOKEN = "replace-with-a-long-random-secret"
.\gohttpx-server.exe --host 127.0.0.1 --port 9876
```

```python
from gohttpx import Client

with Client(go_endpoint="http://127.0.0.1:9876") as client:
    response = client.get("https://example.com/")
```

外部模式 `go_token=None` 读取 `GOHTTPX_TOKEN`；显式 token 覆盖环境变量。`--insecure-no-auth` 仅用于开发；非 loopback 需要显式 `--allow-non-loopback`，此服务不是公网认证代理。

外部服务 CLI 保留 `--max-body-mib`（默认 48）、`--idle-ttl`（默认 24h）、`--version`。`--managed` 是 SDK 私有入口，不可与 host/port/token 等外部配置同时使用。

```powershell
.\gohttpx-server.exe --version
Invoke-RestMethod http://127.0.0.1:9876/api/v1/health
Invoke-RestMethod http://127.0.0.1:9876/api/v1/capabilities -Headers @{Authorization="Bearer $env:GOHTTPX_TOKEN"}
```

仅外部模式的 health 免鉴权；托管模式所有控制路由都校验内部 token 和实例 ID。外部服务 Ctrl+C 最多等待 10 秒优雅退出，自动拉起由外部进程管理器负责。

## 构建与升级

```powershell
python -B tools/release.py validate
python -m build --sdist --wheel
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
python -B -m unittest discover -s python -p "test_*.py" -v
python -B tools/release.py binary
python -B tools/release.py notes
```

正式发布必须先提交已审查的源码，并保持工作树干净。`--sdist --wheel` 让正式 wheel 直接从 checkout 构建，内置 Go 的 VCS 信息可核验；默认 `python -m build` 仍用于从 sdist 重建的开发回归。

wheel 构建时从同一份源码生成 Windows amd64 EXE，不采用开发目录中遗留的二进制。`tools/release.py notes` 核验独立 EXE 和 wheel 内置 EXE 的 clean revision、平台和版本，生成发布说明、SHA-256 与文件大小清单。

推送与源码版本一致的 `v*` 标签触发 `.github/workflows/publish-release.yml`。Windows 验证全部通过后，由已有 PyPI Trusted Publisher 自动上传 wheel/sdist，再自动创建包含 wheel、sdist、独立 EXE 和校验清单的 GitHub Release。无需在本机保存 PyPI token 或手动上传。正式成功以 Actions 结果和两个站点的实际产物为准。

完整验证记录见 [托管运行时测试](docs/testing/2026-08-27-managed-runtime.md)。`.tmp` 中保留的安装测试虚拟环境是忽略的测试产物；需要清理时可手动删除。
