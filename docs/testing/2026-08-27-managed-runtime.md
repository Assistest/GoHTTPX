# GoHTTPX 2.0 托管运行时验证记录

日期：2026-08-27。本地实现与验证完成，未提交、推送或发布。

## 环境与结果

- Windows 内核版本 10.0.26200，amd64；Python 3.10.11，HTTPX 0.28.1。
- Go 1.26.2 windows/amd64。
- Go 全量测试通过：61 个顶层测试，最后一次 2.958 秒。
- Go race 测试通过，8.221 秒；go vet 通过。
- Python 全量测试：112 项全部通过，最终重跑 123.337 秒，包含 27 项托管测试。
- Windows wheel 构建及 twine 检查通过；独立虚拟环境安装测试通过。
- 14 个 Python 文件通过 AST、标识符和控制字符检查；wheel 内实现模块与最终源码逐字节一致。
- 测试结束后仓库路径下未发现仍运行的 server.exe；退出测试另外使用原生进程句柄逐个确认 Go 已结束。

网络行为测试只访问 loopback；构建和安装依赖可能访问软件源。不含生产业务请求。

## 已执行节点

| 节点 | 观察结果 |
|---|---|
| 自动启动与动态端口 | 不传 endpoint/token 成功请求，由 Go 自己绑定端口 0 |
| 大量短 session | 连续 12 个 client 共用一个 Go，每个新 client 的 Cookie 为空 |
| 并发首启 | 12 线程执行 24 个独立 client 请求，仅启动一次 Go，Cookie 各自正确 |
| 同步/异步混用 | 两类 client 共用 Go，A/B Cookie 不串用 |
| Cookie 规则 | 更新、Path 限制、Max-Age 删除通过；原有 HTTPX 完整 E2E 通过 |
| 多 Python 进程 | 两个进程拥有不同端口/实例，分别返回 A/B Cookie；强杀 A 后 B 继续携带 B Cookie 请求 |
| 父进程退出 | 正常退出、未捕获异常、os._exit、外部强杀后，独立观察进程确认 Go 结束 |
| 启动窗口退出 | 子进程刚创建但尚未 bootstrap、ready 已校验但尚未发布时强杀 Python，均无遗留 Go |
| Job 失败 | 注入原生属性设置失败，明确报配置错误，不降级为普通 Popen |
| 私有管道 | Go 严格校验 bootstrap；shutdown、EOF、损坏关停消息均结束服务 |
| 握手检查 | PID、host、port 类型/范围、实例、版本、重复/未知字段、超长/不完整 ready 均拒绝 |
| 部署错误 | 缺失二进制和版本不匹配明确失败；带中文和空格的 EXE 路径启动成功 |
| Go 崩溃恢复 | 原 client Cookie 保留，后续 24 个并发请求共用一次恢复 |
| 在途 POST | 目标执行后杀 Go，同步/异步均抛 GoRequestOutcomeUnknown，副作用计数保持一次 |
| 丢失或错误响应 | 读失败、身份不符、非法 JSON/envelope 不重发已提交请求 |
| 安全重试 | 发送前 ConnectError 最多增加一次尝试，目标只执行一次 |
| Session 丢失 | 删除 Go session 后重建，不重启健康 Go，目标只执行一次 |
| 错实例隔离 | 错凭证返回 401；将 A 的 endpoint 指向另一份真实 Go，不执行目标请求，不接受其结果 |
| 健康检查 | 连续三次独立检查失败才替换存活进程；目标 500/超时不重启 Go |
| 连续失败 | 退避、冷却生效；冷却中关闭不再启动 Go |
| 启动中关闭 | 未发布的候选进程被回收，等待者结束，运行时进入 CLOSED |
| 异步取消 | 取消单个启动等待者不影响其他 client；全部 session 创建等待者取消后仍回收 session；取消 close 等待者不取消清理 |
| 资源回收 | 连续六次重启逐次检查旧 Job、进程句柄、管道关闭和读取线程结束；GC 后空闲采样未出现持续句柄增长 |
| 应用生命周期 | start/astart 共用实例；shutdown/ashutdown 幂等结束 |
| 独立安装 | 在独立虚拟环境、移除 Go PATH、隔离源码导入后，包内 EXE 完成同步/异步请求及父进程退出回收 |

主要证据文件：python/test_managed_runtime.py、managed_test.go、python/test_package_install.py，以及现有 Python/Go E2E。

## 验证边界

交付 wheel：dist/gohttpx-2.0.0-py3-none-win_amd64.whl，5,148,844 字节。
SHA-256：d275102336b36d2ae1820868882645a1a98c5e94a6fc2d44f60facca748d2fb3。

- 仅验证上述 Windows 构建，未单独验证 Server 2016 或所有嵌套 Job 策略。Linux/macOS 托管尚未实现。
- 启动窗口测试覆盖可复现暂停点；创建时原子关联依赖 Windows API 契约，不声称逐条 CPU 指令注入故障。
- 错实例测试使用真实 Go 的 endpoint 改向和错误凭证，未穷举操作系统端口复用。
- 未做全天压测，不将测试时间当成生产 SLA。Python 卡死但进程尚存不触发退出回收；强杀不保证业务请求完成。
