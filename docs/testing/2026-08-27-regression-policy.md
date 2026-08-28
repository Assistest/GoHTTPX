# 测试目录与回归约定复核

日期：2026-08-27。本轮只调整项目约定、说明文档和 CI 构建顺序，没有修改业务代码、正式用例或既有断言。未提交、推送或发布，远程 CI 未触发。

## 固定位置与本轮改动

- Go 正式测试与被测包同目录，根目录有 `api_test.go`、`main_test.go`、`managed_test.go`。
- Python 正式测试为 `python/test_*.py`，当前共 6 个文件，由默认 unittest discovery 执行。
- `docs/testing/` 保存验证报告；`.tmp/` 的一次性诊断不计入正式回归。
- 新增根目录 `AGENTS.md` 作为开发入口，`PROJECT_CONTEXT.md` 第 14 节明确目录、回归命令和预期变更规则。
- README 和 CI 明确先从当前源码构建 wheel，再运行 Python 全量及安装测试，避免复用旧包。
- 既有预期默认不变；只有需求明确改变对应行为或有证据证明用例有误，才允许调整并说明依据。禁止为通过测试而删除、跳过或放宽断言。

## 本轮实际执行

从仓库根目录顺序执行，所有命令退出码均为 0：

| 命令 | 结果 |
|---|---|
| `go test ./... -count=1` | 通过，包测试耗时 2.909 秒；另外收集确认有 61 个顶层测试 |
| `go test -race ./... -count=1` | 通过，包测试耗时 7.030 秒 |
| `go vet ./...` | 通过 |
| `python -B -X utf8 -m build` | 当前源码的 sdist 和 Windows amd64 wheel 构建成功 |
| `python -B -X utf8 -m unittest discover -s python -p "test_*.py" -v` | 112 项通过，121.330 秒，无失败、错误或跳过，包含独立安装测试 |
| `git diff --check` | 通过；仅提示 Git 的 LF/CRLF 转换策略 |

补充核验：wheel 中的 `gohttpx.py`、`_gohttpx_runtime.py`、`_gohttpx_windows.py` 与当前源码逐字节一致；测试结束后未发现仓库路径下仍运行的 `*server.exe`。Git 状态未出现临时脚本、pyc、数据库或密钥文件新增/修改。

本轮重新构建的 `dist/gohttpx-2.0.0-py3-none-win_amd64.whl` 为 5,149,161 字节，SHA-256 为 `41158b654aa5d7d791a2749c168df6aa9bcb095a969ff9c69ffa2c738f1d4381`。此前托管验证报告中的大小与哈希属于当时的构建，不是本轮重建产物。

## 验证边界

上一轮百度与本机固定响应的内存曲线采样属于临时诊断，没有被转成正式自动回归，也未新增“内存必须降回启动值”的断言。本轮执行的是已有功能、隔离、故障恢复、退出回收和安装回归，不代表完成全天内存压测。
