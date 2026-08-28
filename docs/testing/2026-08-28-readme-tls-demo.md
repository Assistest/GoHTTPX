# README 内联 TLS 示例验证

日期：2026-08-28。版本：GoHTTPX 2.1.0，本地未发布。环境：Windows amd64、Go 1.26.2、Python 3.10.11。

## 改动范围

- 首页内联完整 Python＋JSON 示例，列出 `cipher_suites`、`compression_methods`、`extensions`、`min_vers`、`max_vers`、`shuffle_extensions` 六个顶层字段。
- 扩展参数完整展开；新版 ALPS 为主示例，旧版 ALPS 单独说明替换，不构造互斥项同时存在的无效配置。
- 显式设置 User-Agent，说明它和 TLS、HTTP/2 配置独立；不承诺复现完整浏览器行为。
- 旧 `examples/tls/*.json` 保留在本机并被 Git 忽略，构建清单排除整个 examples 目录。用户不需要下载独立演示 JSON。
- 原最小差异配置移入正式测试夹具 `testdata/tls/custom_tls13.json`，已逐项比较 JSON 内容与迁移前一致；没有改动原有报文预期。
- 未修改生产 TLS 实现或 SDK 行为；更新文档、测试数据位置、测试辅助模块及打包清单。

## 实际报文验证

`python/tls_test_support.py` 直接解析 README 的 `tls-demo` 代码块和 `TLS_SPEC_JSON`，不维护第二份 Edge 演示配置。

新增 `test_readme_tls_demo_is_complete_and_runs_without_external_json` 直接执行首页代码，只替换测试目标 URL、控制端点和测试 CA；其余代码及传入配置不变。断言六个顶层字段完整、实际 User-Agent 与示例相同，以及服务端收到的套件、扩展顺序和签名算法内容。README 尚未内联配置时，该测试已复现失败；更新后通过。

既有 Edge TLS 1.2/1.3 用例改为读取 README 配置，原有套件、扩展内容、KeyShare 长度及 ALPS 断言保持不变并通过。

新增旧版 ALPS 替换测试，确认服务端收到 17513、未收到 17613，内容为 `0003026832`；同时设置新旧 ALPS 时，Go 明确返回 `INVALID_REQUEST`。

新增源码包检查，确认 sdist 内 README 与工作区一致、包含正式测试夹具、没有 examples 目录。网络行为回归只访问 loopback，不依赖公网检测站可用性。

## 最后一轮完整回归

| 命令 | 结果 |
|---|---|
| `go test ./... -count=1` | 通过，2.985 秒 |
| `go test -race ./... -count=1` | 通过，6.462 秒，无 race 报告 |
| `go vet ./...` | 通过，退出码 0 |
| `python -X utf8 -m build` | 成功构建 sdist，并从 sdist 构建 Windows amd64 wheel |
| `python -B -X utf8 -m unittest discover -s python -p "test_*.py" -v` | 131 项全部通过，116.299 秒，无跳过 |

Python 相对于上一轮 128 项新增 3 项，既有用例未删除或放宽。Go 仍为 65 个顶层测试。当前 wheel 的隔离 venv 安装、实际握手和退出回收验证继续通过。

## 当前构建产物

- `dist/gohttpx-2.1.0-py3-none-win_amd64.whl`
- 大小：5,160,065 字节。
- SHA-256：`1082dc4f0ab6159dcf37b581fcd01db79abea6fb244dfeff9081eea394a8417e`。
- sdist 中唯一 JSON 文件是内部夹具 `testdata/tls/custom_tls13.json`；没有旧演示 JSON。

本记录在构建和测试完成后生成。没有执行 Git 提交、推送或 PyPI 发布；既有 [首次功能验证记录](2026-08-28-custom-tls.md) 保留当时的文件名与产物哈希，本记录对应本轮调整。
