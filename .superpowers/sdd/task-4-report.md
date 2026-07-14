# Task 4 报告：代理与资源边界 E2E

## 范围

- 仅修改 `python/e2e_support.py` 与 `python/test_gohttpx_e2e_transport.py`；本报告为任务要求的交付物。
- 未修改生产实现、SDK 或 `api.go`。

## RED / GREEN

- RED：先加入 CONNECT 代理鉴权与显式 CONNECT header E2E。执行
  `python -X utf8 -B -m unittest test_gohttpx_e2e_transport.TransportE2ETests.test_connect_proxy_forwards_auth_and_explicit_headers -v`
  时因缺少 `ConnectProxyFixture` 失败：`ImportError: cannot import name 'ConnectProxyFixture'`。
- GREEN：实现仅测试使用的 loopback CONNECT/SOCKS5 fixtures 后，上述测试通过；随后新增的无效 CONNECT 鉴权映射和 SOCKS5 并发 1 MiB 正文转发测试均通过。
- 根目录 discovery：`python -X utf8 -B -m unittest discover -s python -p "test_gohttpx_e2e_transport.py" -v`，9 tests passed（27.515s）。

## 安全与边界

- 两种代理均只监听 `127.0.0.1`，仅接受数值 loopback IP 或解析后全部为 loopback 的 `localhost`；解析失败或任何其他目标均拒绝，未发生外连。
- 两种代理均记录转发尝试；关闭仅停止并关闭 fixture 自己创建的监听器和线程。
- CONNECT 无效 Basic 鉴权返回 407，E2E 验证其映射为 `httpx.ConnectError` / `UPSTREAM_CONNECT_ERROR`。

## API 更正

任务简报中的 `ClientOptions(proxy_connect_headers=...)` 与当前公开 SDK 不符。现有正确路径为：

```python
ClientOptions(transport=TransportOptions(proxy_connect_headers={"X-Connect": ["one"]}))
```

已按该契约测试，未新增或修改 `ClientOptions` 字段。

## P2 修复：localhost 解析后的拨号边界

- 根因：原先 loopback 校验只返回布尔值，`localhost` 校验通过后仍把原始主机名传给 `socket.create_connection`，存在解析结果变化时越过已验证地址的风险。
- 修复：校验函数改为返回已验证的数值 loopback IP；CONNECT 和 SOCKS5 均只向该 IP 拨号。`localhost` 仅在全部解析结果都是 loopback 时允许，并优先选择 IPv4 数值地址。
- 回归：原始 CONNECT `example.com` 与 SOCKS5 `8.8.8.8` 都被拒绝，`dialed_hosts` 保持为空；CONNECT `localhost` 的已记录拨号地址为 `127.0.0.1`。
- 验证：transport discovery 与末尾 3 项复核均通过；完整 discovery 共 10 项。
