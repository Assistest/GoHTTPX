# Task 2 发布工作流与用户文档报告

## 起点

- 初始 HEAD：`617233bdd5cb937dce71a815069882392c132e7d`

## 已实施

- 新增标签发布工作流：先校验 `vX.Y.Z` 与 `pyproject.toml` 版本一致，运行 Python 测试、构建并执行 Twine 校验，然后通过 PyPI Trusted Publishing 上传。
- PyPI 上传成功后，构建 Windows amd64、Linux amd64、macOS amd64 与 macOS arm64 服务端二进制；每个资产附带 SHA-256 文件，最后用 `gh release create` 创建 GitHub Release。
- README 新增 PyPI 安装、独立 Go 服务端下载、SHA-256 校验及 `GoServiceUnavailable` 示例；CHANGELOG 记录发布边界。
- 忽略 `dist/` 与 `*.egg-info/`；新增 wheel 元数据 unittest。

## 验证

- `python -m build`：成功生成 sdist 和 wheel。
- `python -m twine check dist/*`：两个分发文件均通过。
- `python -B -m unittest discover -s python -p "test_*.py" -v`：通过。
- 工作流静态断言：确认标签校验、Trusted Publishing、四平台资产、linker flag、SHA-256 以及 PyPI 成功后的 Release 依赖均存在。
- `git diff --check`：通过。

## 范围交叉

工作流保留 `-X main.serverVersion=...`。当前 `serverVersion` 仍是 const，Go linker 只能覆盖字符串变量；根据指示，没有在 Task 2 修改 `api.go` 或 `api_test.go`。Task 3 将其改为变量并加入对应回归测试后，该 linker flag 才会真正注入版本。
