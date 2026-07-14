# GoHTTPX PyPI 包设计

## 目标

将现有 `python/gohttpx.py` 发布为 PyPI 包 `gohttpx`。安装包只提供 Python 客户端；Go 服务端继续由使用者按仓库 README 手工下载、启动和常驻运行。

## 包边界

- 根目录使用 `pyproject.toml` 与 setuptools 构建 wheel、sdist。
- Python 发行包只包含 `gohttpx` 模块和必要元数据，不携带、下载或启动 Go 二进制文件。
- 公开导入保持为 `from gohttpx import Client, AsyncClient, RequestOptions`。
- 支持 Python `>=3.10`，依赖 `httpx>=0.28,<0.29`。

## 服务不可用提示

当客户端无法连接配置的 Go bridge 时，抛出继承自 `httpx.ConnectError` 的专用异常。异常消息包含 GitHub 仓库地址，帮助只安装了 pip 包的用户找到服务端安装与启动说明。原始连接异常作为异常链保留。

只转换 bridge 连接失败；目标站点的 HTTP 状态、超时、TLS 错误和响应内容保持 HTTPX 原有语义。

## 发布与验证

- GitHub Actions 在推送 `v*` 标签时构建 sdist/wheel、在干净环境安装 wheel 并运行 Python 测试，然后以 GitHub Secret 中的 PyPI token 发布。
- 本地测试覆盖：从 wheel 安装后可导入、原有客户端 API 可用、bridge 不可达时异常包含项目地址。
- 发布版本由 Git 标签与 `pyproject.toml` 版本一致性校验保证；首个版本使用当前协议版本 `1.0.0`。

## 非目标

- 不自动管理 Go 服务生命周期。
- 不把平台二进制文件打进 wheel。
- 不改变 Go API、会话或调用方 headers/cookies 的归属。
