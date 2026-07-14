# GoHTTPX PyPI 包 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将现有 Python 客户端发布为可通过 `pip install gohttpx` 安装的 PyPI 包，并在本地 Go bridge 不可达时给出仓库引导。

**Architecture:** 根目录的 `pyproject.toml` 将单文件模块 `python/gohttpx.py` 构建为 `gohttpx` 分发包。客户端仅在控制面连接异常时将 HTTPX 连接错误包装为带 GitHub 地址的 `GoServiceUnavailable`，其他 HTTPX 语义不变。GitHub Actions 复用测试环境，并只在 `v*` 标签上发布已验证的 wheel/sdist。

**Tech Stack:** Python 3.10+、setuptools、build、twine、HTTPX 0.28.x、GitHub Actions、PyPI Trusted Publishing。

## Global Constraints

- Python 公开 API 保持 `from gohttpx import Client, AsyncClient, RequestOptions`。
- 支持 Python `>=3.10`，运行依赖固定为 `httpx>=0.28,<0.29`。
- wheel 不包含、下载或启动 Go 二进制；Go 服务仍由用户手工常驻运行。
- 仅 bridge 控制面不可连接时提供引导；目标站点错误保留 HTTPX 既有语义。
- 文档、注释与用户可见错误使用中文；代码标识符使用英文。

---

### Task 1: 构建可安装 Python 发行包并提供 bridge 引导

**Files:**
- Create: `pyproject.toml`
- Modify: `python/gohttpx.py:166-168, 441-457, 1135-1150`
- Modify: `python/test_gohttpx.py:843-853`
- Create: `python/test_package_install.py`

**Interfaces:**
- Consumes: 当前 `GoServiceUnavailable` 与 `_GoTransport._call()` 的控制面请求。
- Produces: `GoServiceUnavailable(message, *, request=None)`，继承 `httpx.ConnectError`；构建后 `import gohttpx` 导出当前公开 API。

- [ ] **Step 1: 写出 bridge 不可达的失败测试**

```python
def test_unavailable_service_has_github_guidance():
    transport = gohttpx._GoTransport.__new__(gohttpx._GoTransport)
    transport._endpoint = "http://127.0.0.1:1"
    transport._control = httpx.Client(transport=httpx.MockTransport(lambda request: (_ for _ in ()).throw(httpx.ConnectError("down", request=request))))
    with pytest.raises(gohttpx.GoServiceUnavailable, match="github.com/Assistest/GoHTTPX"):
        transport._call("GET", "/api/v1/capabilities", None, None)
```

运行：`python -B -m unittest python/test_gohttpx.py -v`

预期：测试失败，因为当前异常消息没有 GitHub 地址，且异常不是 `httpx.ConnectError` 子类。

- [ ] **Step 2: 用最小改动实现异常语义**

```python
class GoServiceUnavailable(httpx.ConnectError):
    def __init__(self, message: str = "无法连接本地 Go 服务，请安装并启动服务：https://github.com/Assistest/GoHTTPX", *, request: httpx.Request | None = None) -> None:
        super().__init__(message, request=request)
```

保留 `_call()`、`_delete_session()` 与异步对应路径的 `raise ... from exc`，仅改为使用默认消息并将可用的 `request` 传入异常。

- [ ] **Step 3: 写入发行元数据并校验构建产物**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "gohttpx"
version = "1.0.0"
requires-python = ">=3.10"
dependencies = ["httpx>=0.28,<0.29"]
```

用 setuptools 的 `py-modules = ["gohttpx"]` 与 `package-dir = {"" = "python"}` 直接复用现有单文件模块；补齐 README、MIT license classifier、项目 URL 和最小项目说明。先查询 PyPI 名称 `gohttpx` 是否可用；若已存在，停止发布并由用户决定新名称，不擅自替换分发名。

- [ ] **Step 4: 在隔离环境验证 wheel**

```python
def test_installed_package_exports_client(tmp_path):
    # 使用 subprocess 在临时 venv 中安装 dist/gohttpx-1.0.0-py3-none-any.whl，
    # 并断言 `from gohttpx import Client, AsyncClient, RequestOptions` 成功。
```

运行：`python -m build`，再运行 `python -B -m unittest python/test_package_install.py -v`。

预期：生成 `dist/gohttpx-1.0.0-py3-none-any.whl`，隔离解释器导入成功。

- [ ] **Step 5: 运行 Python 全量测试并提交**

运行：`python -B -m unittest discover -s python -p "test_*.py" -v`

预期：全部通过。

```text
git add pyproject.toml python/gohttpx.py python/test_gohttpx.py python/test_package_install.py
git commit -m "feat: 支持 PyPI 安装与服务引导"
```

### Task 2: 添加安全发布工作流与用户文档

**Files:**
- Create: `.github/workflows/publish-pypi.yml`
- Modify: `README.md: Python 使用说明`
- Modify: `CHANGELOG.md: 1.0.0`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: Task 1 构建出的 wheel/sdist 及现有 Python 测试。
- Produces: 推送 `v*` 标签后的 PyPI 发布流程；README 中的安装、服务启动和异常引导说明。

- [ ] **Step 1: 写出发布元数据检查**

在 `python/test_package_install.py` 增加读取 wheel `METADATA` 的测试，断言 `Name: gohttpx`、`Requires-Python: >=3.10` 和 HTTPX 版本范围存在。

运行：`python -B -m unittest python/test_package_install.py -v`

预期：在元数据或依赖缺失前失败。

- [ ] **Step 2: 实现标签发布工作流**

```yaml
on:
  push:
    tags: ["v*"]

permissions:
  id-token: write
  contents: read
```

工作流在 Ubuntu 上安装 Python 3.10、安装 `build` 与测试依赖、运行 Python 全量测试、执行 `python -m build` 和 `twine check dist/*`，最后使用 `pypa/gh-action-pypi-publish` 的 Trusted Publishing 上传。发布前校验标签去掉 `v` 后与 `pyproject.toml` 的版本相同。

- [ ] **Step 3: 更新 README 与变更记录**

README 的 Python 小节改为先执行：

```powershell
pip install gohttpx
```

随后明确 Go 服务端不是 pip 包的一部分，给出仓库链接与启动命令，并展示捕获 `GoServiceUnavailable` 的示例。CHANGELOG 写明 PyPI 分发与服务不可达引导。

- [ ] **Step 4: 运行发布前校验并提交**

运行：

```text
python -m build
python -m twine check dist/*
python -B -m unittest discover -s python -p "test_*.py" -v
```

预期：构建产物元数据合法、测试全通过。

```text
git add .github/workflows/publish-pypi.yml README.md CHANGELOG.md .gitignore python/test_package_install.py
git commit -m "ci: 支持标签发布 PyPI"
```

## 自查

- 规格中的 Python 版本、HTTPX 约束、公开 API、Go 二进制边界、bridge 错误边界和标签发布均有对应任务。
- 未使用占位项；异常名、包名与版本在任务间一致。
- PyPI 名称占用作为发布前的显式停点，避免静默改名破坏用户导入约定。
