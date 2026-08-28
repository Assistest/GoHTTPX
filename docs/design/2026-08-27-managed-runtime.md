# GoHTTPX 自动托管 Go 进程设计

日期：2026-08-27。

状态：2.0 本地实现已完成，尚未发布。本文保留设计阶段记录；实际接口、默认值与测试证据以 README 和验证记录为准。

落地范围：当前仓库、Python 3.10+、Windows 10+/Windows Server 2016+，首个发布包为 Windows amd64。Linux/macOS 的进程回收必须另行实现、验证，未支持的平台不能把普通 Popen 冒充具有同等保障的 managed 模式。

## 1. 决策摘要

| 问题 | 决策 |
|---|---|
| 谁启动 Go | Python SDK 自动启动编译好的二进制，不在请求过程中运行 go build |
| 启动多少个 | 一个使用 GoHTTPX 的 Python 进程对应一个 Go 进程；多个 Python client 共享进程，各有独立 session |
| 怎么分配端口 | Go 直接监听 127.0.0.1:0，持有 listener 后把实际端口通过私有管道返回 |
| 用户是否配置密钥 | managed 模式不需要；SDK 内部为每次启动生成随机凭证，不能删除实例鉴权 |
| Python 被强杀怎么办 | 创建 Go 时原子关联 Windows Job，设置 KILL_ON_JOB_CLOSE，Job 句柄只由所属 Python 持有 |
| Go 崩溃怎么办 | 单一协调器自动重启，重新握手，发布新实例，按需重建 client session |
| 当前请求是否重发 | 只有能够确认未执行的请求自动继续；结果不确定时抛出专门异常，不能盲目重发 |
| 是否影响 Cookie | 已经被 Python 接收的 Cookie 保留；Go 重启不清空 Python Cookie Jar |
| 现有手动模式 | 显式 go_endpoint 保留为 external 模式；SDK 不启动、不结束、不重启外部进程 |

退出绑定与鉴权解决不同问题。前者防止遗留进程；后者拒绝错误实例上的请求。随机端口不是身份认证。

## 2. 改造前审查记录

本轮已核对当前源码：

- main.go 使用固定默认端口 9876，拒绝端口 0，通过 ListenAndServe 启动，只监听 os.Interrupt 触发优雅关闭。
- python/gohttpx.py 的同步 client 在构造时连接服务并创建 session；异步 client 在首次请求时创建 session。
- 两个 transport 都把控制连接的 TransportError 统一包装为 GoServiceUnavailable，因此仅凭现有异常类型不能判断目标请求是否已经执行。
- 当前只在收到完整 CLIENT_NOT_FOUND 错误后重建 session 并重发一次，不会重启 Go 进程。
- 业务 Cookie、headers、auth 由 Python HTTPX client 管理，Go Cookie Jar 被显式关闭。
- v1 请求和响应 envelope 严格拒绝未知字段，不能直接往业务 JSON 中塞入运行时字段。
- 当前 pip 包只包含 Python 模块，Go EXE 单独发布；要做到安装后直接调用，还需补二进制分发。

本次设计保留发包、TLS、代理、HTTPX、Cookie 和 v1 数据协议的职责。新增的是进程生命周期及其恢复，不重写网络传输栈。

## 3. 进程与 client 所有权

```text
Python 进程 A                         Python 进程 B
  ManagedRuntime A                     ManagedRuntime B
    client A1 -> Go session A1            client B1 -> Go session B1
    client A2 -> Go session A2            client B2 -> Go session B2
             |                                    |
     Go A / 动态端口 A                    Go B / 动态端口 B
     Job A / 凭证 A                       Job B / 凭证 B
```

- 同一 Python 进程内，同步和异步 client 共用一个运行时管理器；不是各启动一份 Go。
- 运行时记录 owner_pid。任何操作先确认当前 PID；不得把父进程的连接、锁、session 或关闭权限当成子进程资源。
- Windows multiprocessing spawn 得到独立运行时；reload 的旧 worker 和新 worker 可以短暂共存，分别使用自己的 Go。
- 每个实际使用 GoHTTPX 的 worker 启动自己的 Go。此决定优先保证回收边界清楚；代价是多 worker 会有多个 Go 进程和连接池。
- 不在 import 时启动 Go。同步 Client 沿用构造时初始化；异步 AsyncClient 沿用首次请求时初始化。
- 关闭 client 只删除它的 session。关闭最后一个 client 不立即结束健康 Go，避免连续业务流程频繁启停；运行时持续到 Python 退出或显式 shutdown。
- 没有存活 client 时，Go 意外退出可以暂缓重启；下一次获得 client 再启动。有存活 client 时自动恢复。
- 不扫描或接管本机其他 GoHTTPX 进程，不使用全局端口登记文件、共享 PID 文件或继承的环境变量传递运行时身份。
- 第一阶段不支持 fork 后复用已有 client。后续 Unix 实现必须在 fork 子进程清理继承的管道写端、重置锁和运行时；CLOEXEC 不能代替 fork 处理。

## 4. 自动启动与私有启动协议

### 4.1 启动顺序

1. 运行时协调器取得本次启动资格。其他调用者等待同一次启动结果，不各自启动。
2. 解析并验证 Go 二进制的绝对路径、平台和 SDK 对应版本，不从 PATH 随意找同名程序。
3. 生成本次启动的 instance_id 和 32 字节密码学随机 token；每次重启重新生成。
4. 创建本次实例专属的 Job 和匿名管道；只给 Go 继承指定的管道端点，不继承 Job 句柄。
5. 使用 CreateProcessW 的扩展属性，在创建 Go 的同时通过 PROC_THREAD_ATTRIBUTE_JOB_LIST 加入 Job。隐藏窗口；不经过 shell。
6. Python 通过 stdin 私有管道发送 bootstrap 消息。Go 在读取、验证该消息后才开始监听。
7. Go 执行 net.Listen("tcp4", "127.0.0.1:0")，通过 listener.Addr() 取得实际端口，并使用同一个 listener 调用 http.Server.Serve。
8. Go 通过 stdout 返回 ready 消息。Python 校验消息、子进程句柄状态、版本和实例标识，再执行携带内部凭证的 capabilities 检查。
9. 所有检查成功后，将完整的不可变实例快照一次性发布为 RUNNING，再允许业务请求使用。

端口分配采用 Go 官方 Listen 的端口 0 语义。禁止“Python 找空闲端口 -> 关闭探测 socket -> Go 再绑定”，否则存在端口被抢占的时间窗口。[Go net.Listen](https://pkg.go.dev/net#Listen)

### 4.2 管道消息

使用 UTF-8、单行 JSON。单条 bootstrap/ready/shutdown 消息上限拟定为 4 KiB，遇到未知字段、重复字段、版本不匹配或超时直接失败。

bootstrap 包含：runtime_protocol_version、instance_id、token、owner_pid、sdk_version。

ready 包含：runtime_protocol_version、instance_id、server_version、protocol_version、pid、host、port。不得回显 token。

生命周期管道与 HTTP 发包协议相互独立：stdin 只接收 bootstrap 和 shutdown；stdout 只输出受控机器消息；目标请求和响应仍走现有本地 HTTP API。

- managed 模式忽略 GOHTTPX_TOKEN，且不允许从外部传入端口和 token；避免继承了其他项目的配置。
- token 不放命令行、不落文件、不写日志，只经过私有管道和本机控制请求。
- 启动握手有截止时间，Go 不能无限等 bootstrap；Python 超时必须关闭 Job 并等待本次子进程退出。
- 父子双方及时关闭自己不使用的管道副本，避免 EOF 被多余句柄阻挡。
- stdin EOF 是辅助退出条件；它不替代 Windows Job 的系统级保障。
- stdout/stderr 必须持续读取，不能因为管道缓冲区写满卡死 Go。stderr 只保留有界、去敏的启动诊断，不能吞掉所有错误，也不能保存无限输出。
- 所有读取器和监视器数量必须固定，不随请求数量增长；关闭时可取消并等待其结束，不让非 daemon 线程阻止 Python 退出。

## 5. 防止 A 请求串到 B

内部凭证保留，但对普通调用方完全隐藏。

每个 managed HTTP 控制请求同时携带内部 bearer token 和实例标识。Go 在创建 session、删除 session、处理目标请求之前校验；失败则拒绝，绝不能进入发包逻辑。

每个受保护的控制响应也携带实例标识。SDK 在解析业务结果、更新 session、交给 HTTPX 更新 Cookie 之前核对它。

- 实例身份来自自己子进程的私有启动管道，不来自一次匿名 health 响应。
- 客户端只使用不可变的 (instance_id, endpoint, token) 快照，不能分别更新三个字段。
- 每个 client 的 Go session 记录 (instance_id, session_id, session_generation)。旧实例的 session_id 不发送给新实例。
- 重启后销毁或退役旧控制连接池，新请求使用新实例快照。迟到的旧错误不能再次重启健康的新实例；迟到的旧 session 创建结果不能覆盖新 session。
- 旧 session 的删除也必须绑定原实例。原实例已经退出时直接做本地清理，不为了删除它重新启动 Go。
- 错误实例返回的 401/实例不匹配不能触发“自动信任新端口”；重新检查自己持有的进程和启动握手。
- 内部控制 headers 不进入目标 request 的 headers、trace 或 dump。

即使旧端口后来被另一个 GoHTTPX 占用，错误凭证也不能使那个实例替 A 发包。TCP 层可能发生一次连到被复用端口的连接，但不得执行业务请求或把 B 的结果当 A 的结果。

该设计防止意外串用和其他实例误调用；不宣称能抵御具有读取当前进程内存能力的同用户恶意程序或管理员。若未来要求完全取消 HTTP 鉴权，应另行迁移到受权限保护的 IPC，而不是裸用随机 TCP 端口。

v1 JSON envelope 保持不变，实例元数据放在 managed 启动协议和外层控制 headers 中；双方一起发布、一起测试，不能对旧服务假装兼容。

## 6. Python 退出与 Go 回收

### 6.1 正常退出

1. 应用停止接收新业务，关闭或等待现有 client 的请求。
2. 运行时进入 STOPPING，禁止新启动和自动重启。
3. 通过 stdin 发送 shutdown，Go 停止接新请求，并限时执行 http.Server.Shutdown、registry.Close。
4. 等待本实例的进程句柄变为退出状态；超时则关闭本实例的 Job，强制回收。
5. 回收管道、线程、控制连接和句柄，进入 CLOSED；重复关闭应得到同一个完成结果。

提供显式 shutdown/ashutdown 供应用生命周期调用，同时以 atexit 做正常解释器退出时的兜底。不能只依赖 __del__，也不能在 atexit 中新建线程。SDK 不擅自覆盖宿主应用的 signal handler。

### 6.2 崩溃或强制结束

Job 配置 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE。句柄只由所属 Python 进程持有、不命名共享、不传给 Go 或其他 worker。Python 退出后其句柄被系统回收；最后一个 Job 句柄关闭时，系统终止所属 Go。[Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)

必须在创建进程时关联 Job；“Popen 之后再 AssignProcessToJobObject”存在启动窗口，即使先挂起子进程，也可能留下尚未加入 Job 的挂起进程。使用官方支持的创建属性消除该窗口。[PROC_THREAD_ATTRIBUTE_JOB_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)

- Job 配置、句柄继承或嵌套 Job 约束不满足时，managed 启动必须失败。不得偷偷退回无绑定模式。
- 每次重启使用新的 Job；关闭旧 Job 不影响新实例，更不能把 Python 自己放入仅用于回收 Go 的 Job。
- 不根据 EXE 名称、端口、裸 PID 做批量清理，所有终止操作针对自己持有的进程句柄/Job。
- 保证的是所属 Python 进程结束后由系统回收 Go，不保证严格同时退出，也不保证强杀时请求完成。
- Python 卡死但进程未退出不触发句柄回收。检测 Python 应用卡死属于宿主 watchdog/部署进程管理职责；不伪装成已经覆盖。

atexit 不覆盖致命错误、某些强制结束和 os._exit，不能作为防幽灵进程的唯一措施。[Python atexit](https://docs.python.org/3/library/atexit.html)

## 7. Go 崩溃恢复

### 7.1 状态与并发

```text
STOPPED -> STARTING -> RUNNING
RUNNING -> RESTARTING -> RUNNING
STARTING / RESTARTING 连续失败 -> BACKOFF -> RESTARTING
不可恢复的配置错误 -> FAILED
任意非 CLOSED 状态 -> STOPPING -> CLOSED
```

- 单一运行时协调器拥有启动、重启、停止权限；工作请求只能报告故障并等待结果。
- 监视器等待自己子进程的退出，不必等到下一条业务请求才发现崩溃。有存活 client 时自动启动替代实例。
- N 个并发请求发现同一实例异常时，只允许一次重启；它们等待同一份结果，分别遵守自己的截止时间。
- 运行时同步机制不能绑定到某个调用者的 asyncio event loop。同步调用可以等待，异步调用必须通过异步适配等待，不能在事件循环中执行阻塞的进程创建/握手。
- 取消一个 async 请求不能取消其他 client 共用的启动或恢复；关闭运行时则必须能取消重启。
- 启动、健康检查、网络 I/O、等待进程退出均在生命周期锁之外执行；结果发布时核对实例代次与 STOPPING 状态。
- 替代进程启动前，确认旧进程已退出。旧进程无法回收则报故障，不能留下双活实例继续尝试。

### 7.2 故障分类

| 现象 | 行为 |
|---|---|
| 本实例进程句柄确认已退出 | 有存活 client 且未关闭时自动重启 |
| 目标站返回 404/500，代理失败，目标请求超时 | 按现有目标错误返回，不重启健康 Go |
| 一次控制连接断开 | 核对实例是否仍活着并做独立健康检查，不直接认定 Go 崩溃 |
| Go 进程存活但连续独立健康检查失败 | 标记疑似无响应，限时停止，确认退出后重启；在途请求按结果不确定处理 |
| 二进制缺失、版本不匹配、Job 无法绑定 | 明确配置错误，不用无限快速重试掩盖 |
| 处于 STOPPING/CLOSED | 不重启，包括监视线程收到预期退出通知时 |

健康检查不能与业务请求共用可能耗尽的控制连接池，不以单个慢业务请求判断 Go 卡死。暂停调试或系统严重负载也可能触发健康策略，默认阈值必须配置并测试，不能承诺零误判。

### 7.3 拟定默认值

下表是设计起点，不是现有能力或性能测试结论。

| 配置 | 初始建议 |
|---|---|
| 单次启动/握手上限 | 10 秒 |
| 正常关闭宽限 | 5 秒，超时回收本实例 |
| 健康检查 | 存活 client 存在时每 5 秒检查，单次 1 秒，连续 3 次失败再确认 |
| 重启退避 | 0.25、0.5、1、2、5 秒，加入少量随机抖动 |
| 崩溃限流 | 滚动 60 秒内 5 次失败后进入 30 秒冷却 |
| 冷却结束 | 仍有 client 且未关闭时只允许一次恢复尝试，失败则再次冷却 |

稳定运行超过观察窗口才重置失败计数，不能在每次短暂 ready 后立刻清零，否则会无限快速崩溃重启。

请求等待恢复有界，且受调用方取消影响。单次 transport 调用开始时固定预算，重试不重置预算；不能把所有等待者永久堆积在恢复队列。HTTPX 的分阶段 timeout 与整个业务流程的总时限不是同一概念，不能暗中宣称一个 timeout 覆盖完整登录/重定向/下单链。

## 8. 恢复服务不等于重发当前业务

### 8.1 默认策略

| 请求状态 | 是否自动继续 |
|---|---|
| 还在等待 Go ready，尚未提交目标请求 | 恢复后在原预算内正常发送 |
| 严格确认控制连接尚未发送请求数据 | 允许恢复后再尝试一次 |
| 当前实例完整返回 CLIENT_NOT_FOUND，且确认 handler 在发包前拒绝 | 重建 session 后最多再尝试一次 |
| 控制写入中断、读超时、响应丢失、Go 在发包中途退出 | 默认不重发；目标可能已经执行 |
| 完整目标响应已经收到并通过实例与协议校验 | 返回该响应；Go 随后退出不影响已完成结果 |

“未收到响应”“Go 已经死亡”“异常名叫 ConnectError”都不能证明请求没有执行。必须保留底层错误和执行阶段，不能沿用目前把全部控制 TransportError 混成一个 ConnectError 的判断方式。

首次实现不新增按 HTTP 方法猜测的自动业务重试：即使 GET 也可能被某些网站用于写操作。需要安全重放的业务由调用方明确实现幂等、结果查询和重试；不能仅因为请求里出现 Idempotency-Key 就认定目标会去重。

RFC 9110 也要求非幂等请求不能在无法判断是否执行的情况下自动重试。[RFC 9110 9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2)

### 8.2 错误接口

拟新增 GoRequestOutcomeUnknown，继承 httpx.TransportError，不继承 ConnectError，避免业务通用“连接失败重试”误把它当成未发送。

异常带原目标 request、instance_id、可用的 request_id、outcome="unknown"；不得伪造目标返回值。拿不到 Go 生成的 request_id 时允许为空。

GoServiceUnavailable 用于未能就绪/明确未提交目标请求等情况，带原因与可用恢复状态。配置错误与结果不确定错误必须可以区分。

由于异常分类更精确会影响调用方，发布说明必须明确迁移，不以保持错误类名字为由保留错误的安全含义。

Go 自动恢复后后续请求继续工作，不代表失败的这条业务会自动成功。例如下单响应丢失时，应先查询订单状态再决定是否重试；本项目不负责替调用方猜业务结果。

SDK 不会吞掉业务异常或重跑整个 Python 函数。调用方需要在请求边界处理异常；如果异常未捕获导致 Python 自己退出，应按退出流程回收 Go，而不是由库阻止宿主退出。

现有 Go RetryOptions/RequestOptions 重试保持默认关闭，不因运行时恢复而提高。运行时重发、session 重建、Go 内部重试不得递归相乘；SDK 单次 transport 调用最多增加一次确认未执行后的提交尝试，Go 内部已由调用方启用的重试另行显式展示。

## 9. Session、Cookie 和旧实例结果

- 新 Go 实例没有旧 session，也没有旧 TCP/TLS 连接；不能“恢复”已经消失的连接池。
- Python client 保留原始有效配置，在发现 instance_id 改变时重新校验 capabilities 并按需创建新 session。
- 每个 client 在同一实例内只重建一次，多个 client 不共用业务 session；不能让一个账号的 TLS/代理设置覆盖另一个。
- 会话创建、关闭和重建均带实例快照。旧实例的完成回调不能覆盖新实例状态；旧实例消失后的 close 不启动替代实例只为发送 DELETE。
- 已经由 HTTPX 接收的 Cookie、headers、auth 不清空。Python 进程退出后，这些内存状态不会自动恢复。
- Go 崩溃前目标新发出的 Set-Cookie 如果尚未被 Python 成功接收，不能凭空补回；目标还可能按连接或 IP 绑定状态，必要时由业务重新准备会话。
- 不把“Go session 已重建”等同于“网站登录状态一定仍有效”。

## 10. Python 接口与兼容模式

以下是拟定接口，不是当前可直接运行的 API。

### 10.1 默认使用

```python
from gohttpx import Client

with Client(follow_redirects=True) as client:
    response = client.get("https://example.com/")
```

示例只说明调用形式，不假定 example.com 会建立业务登录会话。正常使用不需要 go_endpoint、go_token 或端口设置。AsyncClient 保持相同的自动托管语义。

拟将 go_endpoint 默认值改为 None：

- go_endpoint=None、go_token=None：managed 模式。
- 显式 go_endpoint：external 模式，保留现有鉴权行为和环境变量规则；只管理自己的 session。
- 只传 go_token 而不传 endpoint：明确报配置迁移错误，不猜测用户是想连旧 9876 还是创建托管服务。
- managed 模式禁止接受外部 token 和固定 endpoint；不得默默读取 GOHTTPX_TOKEN。

### 10.2 应用生命周期

拟提供 configure_runtime(binary_path=...) 作为可选部署入口，必须在启动前调用；同一进程不能让不同 client 偷偷更换 Go 二进制或运行时配置。

拟提供 start()/astart() 供应用在启动钩子预热；没有调用时仍自动启动。拟提供 shutdown()/ashutdown() 供应用在停止钩子执行有界关闭，并停止后台恢复。

首次使用同步 Client 时可能阻塞等待 Go 启动；已有异步应用应使用 AsyncClient/astart，不在事件循环中调用阻塞的同步构造。

shutdown 完成后已有运行时为 CLOSED，不能被迟到请求复活；后续重新启用需要显式、受控的重新初始化，不由 close 回调偷偷完成。

更改默认连接语义属于破坏性行为，建议作为下一个主版本发布。external 模式作为现有明确用途保留，不增加新的跨进程共享管理框架。

## 11. 二进制分发和可观测性

### 分发

- 发布包含与 Python SDK 版本匹配 Go EXE 的 Windows 平台 wheel；Python 安装时获得二进制，用户不需安装 Go 工具链。
- 保留现有 gohttpx.py 公开入口，仅增加运行时实现和二进制资源包，不为了这次改动重排整个 transport 实现。
- 运行时使用包内固定绝对路径，版本校验失败则拒绝启动。用户显式 binary_path 可用于部署和开发，但必须同样校验。
- 不在生产首次请求时下载 EXE、联网升级或编译。源码安装/不支持的平台缺少匹配二进制时给出明确安装错误。
- 如果仍支持复制单个 gohttpx.py 接入，文档必须说明新增运行时与二进制依赖，不能继续宣称一个文件就包括全部托管能力。
- 发布流程先生成并校验匹配二进制，再打 wheel 并做安装后端到端测试；不能先发布一个缺少 EXE 的包再等后续 job 补文件。

### 可观测性

提供运行时状态快照：state、owner_pid、child_pid、instance_id、restart_count、last_exit_code、last_failure、next_retry_at。token 不对外暴露。

仅输出经过筛选的生命周期事件，如启动失败、意外退出、进入冷却、恢复成功。采用命名 logger，不调用 basicConfig，不打印业务 Cookie、请求头、URL query、正文、证书或 token。宿主应把 BACKOFF/FAILED 接入健康状态或告警。

这会扩展目前“不输出启动日志”的约定：Go stdout 只发管道机器消息；SDK 的故障事件可被应用接入，不默认打印成功请求或敏感数据。

## 12. 预计改动范围

| 文件/区域 | 改动 |
|---|---|
| main.go | managed 启动参数、端口 0 listener、bootstrap/ready、stdin shutdown/EOF、有界退出 |
| api.go | managed 实例鉴权与响应标识；保持现有业务 envelope 和发包职责 |
| python/gohttpx.py | managed/external 选择、实例快照、session 代次、精确错误分类、同步/异步接入 |
| 新增 Python 运行时模块 | 单进程协调器、退避、状态、管道通信、显式生命周期 |
| 新增 Windows 平台模块 | ctypes 调用 Job/CreateProcess/句柄等待；集中处理错误与资源回收 |
| 二进制资源包、pyproject.toml、发布工作流 | 平台 wheel、版本与资源检查、安装后验证 |
| Go/Python 测试 | 创建窗口、进程死亡、多进程隔离、恢复、取消、超时和重放边界 |
| README、RUNBOOK、PROJECT_CONTEXT、CHANGELOG | 新默认行为、支持平台、迁移方式、错误语义与故障排查 |

只为实际的生命周期与平台边界拆模块，不引入通用进程池、跨机器调度、Redis、额外守护服务或数据库。

## 13. 故障注入验收

下列测试是实现后的发布门槛，执行结果见验证记录，不能把本表视为全部已执行的证据。真实子进程测试必须由第三个测试进程观察，不能让已经被杀的 Python 自己报告清理成功。只终止测试自己创建并持有句柄的进程。

| 场景 | 必须观察到的结果 |
|---|---|
| 不传 endpoint/token 的首个 client | Go 自动启动，绑定 loopback 动态端口，目标请求成功 |
| 同步/异步同时首次请求 | 仅一个 Go 实例，多个独立 session |
| 多套 Python/多个 spawn worker 同时运行 | 各自独立实例、凭证、Job、监听地址，目标观测数据互不串用 |
| Python 正常退出、未捕获异常、os._exit、外部强制结束 | 所属 Go 退出、监听消失；其他 Python 的 Go 继续服务 |
| 在创建前、创建中、bootstrap 中、ready 后分别强杀 Python | 不留下正在运行或挂起的孤儿 Go |
| 尝试让其他 worker/Go 继承 Job 句柄 | 继承被阻止；父进程退出仍触发回收 |
| Job 配置/进程属性创建失败 | 明确失败，不降级启动普通 Go |
| 外部服务模式 | 不启动、不停止、不重启不属于本进程的 Go |
| Go 空闲时被结束且有存活 client | 自动恢复；新请求成功 |
| 许多请求同时遇到同一次退出 | 同一轮只重启一次，不产生进程风暴 |
| 有目标副作用后、返回结果前杀 Go | 目标副作用计数保持一次；原请求抛结果不确定；后续新请求可成功 |
| 明确未提交目标请求时 Go 不可用 | 原预算内恢复后提交一次，无额外目标副作用 |
| CLIENT_NOT_FOUND 与进程重启同时出现 | 总额外提交预算不超过一次，不形成嵌套重试 |
| 旧请求/旧 session 创建结果延迟返回 | 不覆盖新实例或新 session，不触发第二次无必要重启 |
| 旧端口被另一测试实例复用 | 错凭证被拒绝，另一实例不执行目标请求，不接受错误实例结果 |
| 目标站超时、代理 405/502、目标 500 | Go 保持运行，只返回相应目标错误 |
| Go 进程存活但服务无响应 | 阈值后回收旧实例，确认退出再恢复；不静默重发在途请求 |
| Go 连续启动即退出 | 退避与冷却生效，错误可观察，不无限高速创建进程 |
| 恢复期间取消一个 async 请求 | 其他等待者仍可完成；取消者不收到迟到业务结果 |
| 恢复期间关闭应用 | 不再启动替代 Go，无残留线程、句柄和进程 |
| Go 重启后继续使用同一 Python client | 已接收 Cookie 与配置保留；新 session 与新连接正确创建 |
| 二进制缺失、版本不匹配、安装目录含空格/中文 | 清楚报错或正确启动；不联网下载，不用 shell 拼命令 |
| wheel 在干净环境安装 | 不装 Go 工具链也能自动启动；资源版本匹配 |
| 生命周期信息与目标 trace/dump | 无内部 token、其他实例状态和敏感启动材料泄漏 |

另外运行当前完整 Go/Python 测试、Go race detector 和 vet，保留现有 Cookie、TLS、代理、HTTP/2、HTTP/3 与取消语义覆盖。性能和回收时间必须实测记录，不能把表中的建议参数当作已经兑现的 SLA。

## 14. 实施次序

1. 先实现真实 Windows 创建时 Job 绑定与死亡测试，确认不会因正常/异常退出遗留子进程。
2. 接入动态 listener、私有握手、内部凭证、严格版本校验，并完成多 Python 进程隔离测试。
3. 实现运行时恢复、单次协调、session 代次、错误语义与并发取消；通过副作用请求故障注入测试。
4. 接入平台 wheel、生命周期诊断与使用文档，最后跑完整回归和干净安装验证。

只有四步都完成并通过验收，才能宣称自动托管、崩溃恢复和退出回收已经可用于线上。仅实现 Popen/atexit 或只验证正常退出，都不算完成。
